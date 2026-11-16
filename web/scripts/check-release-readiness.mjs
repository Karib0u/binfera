// Full production UI and native Hive acceptance checks. Requires prepared engine and demo assets.
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdtemp, rm, mkdir } from "node:fs/promises";
import { tmpdir, cpus, totalmem } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { preview } from "vite";

const web = fileURLToPath(new URL("../", import.meta.url));
const output = resolve(process.argv[2] ?? `evidence/${new Date().toISOString().slice(0, 10)}/release-readiness.json`);
const temp = await mkdtemp(join(tmpdir(), "binfera-release-"));
const evidence = { date: new Date().toISOString(), machine: { cpu: cpus()[0].model, cores: cpus().length, memory: totalmem() } };
evidence.sourceHead = execFileSync("git", ["rev-parse", "HEAD"], { cwd: web, encoding: "utf8" }).trim();
const wasm = await readFile(join(web, "src/wasm/binfera.wasm"));
evidence.wasm = { bytes: wasm.length, sha256: createHash("sha256").update(wasm).digest("hex") };
const bytes = await readFile(join(web, "public/demos/hive.bin"));
const key = Buffer.from("binfera-demo-sample");
for (let i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
evidence.sample = { id: "hive", sha256: createHash("sha256").update(bytes).digest("hex"), bytes: bytes.length };
const sample = join(temp, "sample.bin");
await writeFile(sample, bytes, { mode: 0o600 });
let server, browser;
try {
  console.log("Measuring native Hive (jobs=8), with no competing local build.");
  evidence.native = await new Promise((resolveRun, reject) => {
    const start = performance.now();
    const child = spawn(join(web, "../target/release/binfera"), [sample, "--decompile-all", "--jobs", "8", "--timing"], { stdio: ["ignore", "pipe", "pipe"] });
    let pending = "", errors = "", functions = new Set(), failures = new Set();
    const result = {};
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Native benchmark exceeded 10 minutes")); }, 600_000);
    child.stderr.on("data", chunk => { errors = (errors + chunk).slice(-4000); });
    child.stdout.on("data", chunk => {
      pending += chunk;
      for (;;) {
        const end = pending.indexOf("\n");
        if (end < 0) break;
        const line = pending.slice(0, end); pending = pending.slice(end + 1);
        if (!line.trim()) continue;
        const event = JSON.parse(line), at = Math.round(performance.now() - start);
        if (event.type === "start") { result.inventoryMs = at; result.inventory = event.functions.length; result.named = Object.keys(event.names ?? {}).length; }
        if (event.type === "settled") result.settledMs = at;
        if (event.type === "done") result.doneMs = at;
        if (event.type === "function") {
          functions.add(event.address);
          if (event.error) failures.add(event.address); else failures.delete(event.address);
          if (!result.p90Ms && functions.size >= result.inventory * 0.9) result.p90Ms = at;
          if (event.address === 0x4e5aa0 && event.text) result.largeFunction = event;
        }
      }
    });
    child.on("error", reject);
    child.on("close", async code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(errors || `Native exit ${code}`));
      if (result.largeFunction) await writeFile(join(temp, "hive-function.json"), JSON.stringify(result.largeFunction));
      delete result.largeFunction;
      resolveRun({ ...result, functions: functions.size, failed: failures.size });
    });
  });
  console.log(JSON.stringify(evidence.native));
  server = await preview({ root: web, preview: { host: "127.0.0.1", port: 4179, strictPort: true }, logLevel: "error" });
  browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await context.addInitScript(() => {
    window.audit = { workers: [], reportReadyMs: null };
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(...args) {
        super(...args);
        const run = { createdMs: performance.now() };
        window.audit.workers.push(run);
        this.addEventListener("message", ({ data }) => {
          if (data.type === "fail") run.error = data.message;
          if (data.type === "done") run.doneMs = performance.now();
          if (data.type === "line") {
            try {
              const event = JSON.parse(data.line);
              if (event.type === "start") { run.inventoryMs = performance.now(); run.named = Object.keys(event.names ?? {}).length; }
              if (event.type === "settled") run.settledMs = performance.now();
            } catch {}
          }
        });
        const post = this.postMessage.bind(this);
        this.postMessage = (request, ...rest) => { run.kind = request.kind; post(request, ...rest); };
      }
    };
    new MutationObserver(() => {
      const report = [...document.querySelectorAll("button")].find(el => el.textContent.trim().startsWith("Report"));
      if (report && !report.disabled && window.audit.reportReadyMs === null) window.audit.reportReadyMs = performance.now();
    }).observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: ["disabled"] });
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const snapshot = () => page.evaluate(() => ({ ...window.audit, readyMs: Math.round(performance.now()), status: document.querySelector(".sb-status")?.textContent, cores: navigator.hardwareConcurrency }));
  const ready = () => page.waitForFunction(() => document.querySelector(".sb-status")?.textContent.includes("capabilities in"), undefined, { timeout: 300_000 });
  page.setDefaultTimeout(300_000);
  console.log("Measuring full production UI from an empty browser profile.");
  await page.goto("http://127.0.0.1:4179/#demo=hive");
  await ready();
  evidence.browserCold = await snapshot();
  assert.equal(evidence.browserCold.workers.filter(w => w.error).length, 0);
  console.log(JSON.stringify(evidence.browserCold));
  await page.reload();
  await ready();
  evidence.browserCached = await snapshot();
  assert.equal(evidence.browserCached.workers.length, 0, "Cached reload must launch no analysis workers");
  assert.deepEqual(errors, []);
  console.log(JSON.stringify(evidence.browserCached));
  // Verify that the ready workspace exposes named functions and usable navigation.
  await page.getByRole("button", { name: "Code", exact: true }).click();
  await page.getByRole("textbox", { name: "Filter functions", exact: true }).fill("syscall.init");
  await page.locator("button[data-ctx-fn]").first().waitFor();
  await page.locator("button[data-ctx-fn]").first().click();
  assert.ok(await page.locator(".fn-title,.cp-crumb,.fn-head").count() || await page.locator(".c-code,.insn").count());
  evidence.acceptance = { hive15Seconds: evidence.browserCold.reportReadyMs < 15_000,
    cached3Seconds: evidence.browserCached.readyMs < 3000, cacheStartsNoWorkers: true, namedFunctionNavigation: true };
  // Keep a real large-function record only in the temporary directory for the existing harness.
  const large = spawn(process.execPath, [join(web, "scripts/check-virtualization.mjs"), join(temp, "hive-function.json")], { cwd: web, stdio: ["ignore", "pipe", "pipe"] });
  const closed = new Promise((resolveExit, reject) => { large.on("close", resolveExit); large.on("error", reject); });
  let report = "", diagnostics = "";
  large.stderr.on("data", chunk => { diagnostics += chunk; });
  for await (const chunk of large.stdout) report += chunk;
  const exit = await closed;
  assert.equal(exit, 0, `Real Hive virtualization check: ${diagnostics}`);
  evidence.virtualization = report.trim().split("\n");
  console.log(report);
} finally {
  await browser?.close();
  await new Promise(resolveClose => server ? server.httpServer.close(resolveClose) : resolveClose());
  await rm(temp, { recursive: true, force: true });
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify(evidence, null, 2) + "\n");
  console.log(`Evidence: ${output}`);
}
