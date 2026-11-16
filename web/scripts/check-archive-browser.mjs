// Verify the production-bundled reader and worker URLs in a real browser.
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build, preview } from "vite";
import { chromium } from "playwright";
import SevenZip from "7z-wasm";

const cache = fileURLToPath(new URL("../node_modules/.cache/", import.meta.url));
await mkdir(cache, { recursive: true });
const temp = await mkdtemp(join(cache, "archive-browser-"));
let browser, server;
try {
  const source = fileURLToPath(new URL("../src/archive.ts", import.meta.url));
  await writeFile(join(temp, "index.html"), '<script type="module" src="/main.js"></script>');
  await writeFile(join(temp, "main.js"), `import * as archive from ${JSON.stringify(source)}; window.archive = archive;`);
  await build({ root: temp, configFile: false, worker: { format: "es" }, logLevel: "error" });
  server = await preview({ root: temp, configFile: false, preview: { host: "127.0.0.1", port: 4180, strictPort: true }, logLevel: "error" });
  const sz = await SevenZip({ print: () => {}, printErr: () => {} });
  const payload = new TextEncoder().encode("Harmless browser worker fixture.");
  sz.FS.writeFile("/sample.bin", payload);
  assert.equal(sz.callMain(["a", "-y", "-pinfected", "-mhe=on", "/fixture.7z", "/sample.bin"]), 0);
  const bytes = [...sz.FS.readFile("/fixture.7z")];
  browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("http://127.0.0.1:4180/");
  await page.waitForFunction(() => window.archive);
  const result = await page.evaluate(async bytes => {
    const file = new File([new Uint8Array(bytes)], "fixture.7z");
    const a = await window.archive.openArchive(file, "7z", "infected");
    const text = await (await a.extract(a.entries[0], "infected")).text();
    await a.close();
    const ctl = new AbortController();
    const reading = window.archive.openArchive(file, "7z", "infected", ctl.signal);
    ctl.abort();
    let aborted = false;
    try { await reading; } catch (error) { aborted = error.name === "AbortError"; }
    return { text, aborted };
  }, bytes);
  assert.equal(result.text, new TextDecoder().decode(payload));
  assert.equal(result.aborted, true);
  assert.deepEqual(errors, []);
  console.log("Production browser bundle: encrypted 7z listing, extraction, worker assets and cancellation passed");
} finally {
  await browser?.close();
  await new Promise(resolve => server ? server.httpServer.close(resolve) : resolve());
  await rm(temp, { recursive: true, force: true });
}
