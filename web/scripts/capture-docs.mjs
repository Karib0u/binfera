// Screenshots and short videos for the README and docs/, taken from the running app so they can be
// redone after a UI change instead of drifting out of date.
//
//   npm run capture-docs                 # every image and both videos
//   npm run capture-docs -- code hex     # only these (names below); `--list` prints them
//   npm run capture-docs -- --no-video   # stills only
//
// Needs what `npm run dev` needs (the wasm module, rules.json and public/demos), plus `cwebp` and
// `ffmpeg` on PATH. The agent shots use `vite --mode mock`, which replays a recorded Claude Code
// run (src/dev/agent-replay.json, made by scripts/agent-replay.mjs) instead of a live model.
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import { chromium } from "playwright";
import { BlobWriter, ZipWriter, Uint8ArrayReader } from "@zip.js/zip.js";

const web = fileURLToPath(new URL("..", import.meta.url));
const out = fileURLToPath(new URL("../../docs/images/", import.meta.url));
const VIEWPORT = { width: 1440, height: 814 };

const args = process.argv.slice(2);
const wanted = args.filter((a) => !a.startsWith("--"));
const noVideo = args.includes("--no-video");

for (const tool of ["cwebp", "ffmpeg"]) {
  if (spawnSync(tool, ["-version"]).error) throw new Error(`${tool} is not on PATH`);
}

// ----- helpers ---------------------------------------------------------------------------------

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/** The analysis is done and the panes have drawn: the status bar counts functions and nothing is pending. */
async function ready(page) {
  await page.waitForFunction(() => {
    const t = document.body.innerText;
    return / functions · /.test(t) && !/Decompiling|Analyzing|Loading…/.test(t);
  }, null, { timeout: 180_000 });
  await pause(1500);
}

async function open(page, base, hash) {
  await page.goto(`${base}/${hash}`);
  // A hash set before the app has a file is read once; reloading makes the deep link stick.
  await page.reload();
  await ready(page);
  await page.mouse.move(VIEWPORT.width - 2, VIEWPORT.height - 2);
}

const clickText = (page, selector, text) => page.locator(selector, { hasText: text }).first().click();

async function palette(page, query) {
  await page.keyboard.press(process.platform === "darwin" ? "Meta+k" : "Control+k");
  await page.keyboard.type(query, { delay: 60 });
  await pause(800);
}

/** A password-protected zip of a few demo samples, named as an analyst would name them. */
async function sampleZip() {
  const index = JSON.parse(await readFile(join(web, "public/demos/index.json"), "utf8"));
  const key = new TextEncoder().encode("binfera-demo-sample");
  const names = { wannacry: "wannacry.exe", "3cx": "3cx-ffmpeg.dll", mirai: "mirai.arm", cloudsnooper: "cloudsnooper.elf" };
  const zip = new ZipWriter(new BlobWriter("application/zip"), { password: "infected", zipCrypto: true });
  for (const [id, name] of Object.entries(names)) {
    if (!index.some((d) => d.id === id)) continue;
    const bytes = new Uint8Array(await readFile(join(web, `public/demos/${id}.bin`)));
    for (let i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
    await zip.add(name, new Uint8ArrayReader(bytes));
  }
  return Buffer.from(await (await zip.close()).arrayBuffer());
}

/** Shows where the pointer is in recordings, which do not capture the system cursor. */
const CURSOR = `addEventListener("DOMContentLoaded", () => {
  const c = document.createElement("div");
  c.style.cssText = "position:fixed;z-index:2147483647;width:18px;height:18px;margin:-9px 0 0 -9px;border-radius:50%;background:rgba(234,88,12,.35);border:2px solid rgba(234,88,12,.9);pointer-events:none;transition:transform .12s;left:-40px;top:-40px";
  document.body.appendChild(c);
  addEventListener("mousemove", (e) => { c.style.left = e.clientX + "px"; c.style.top = e.clientY + "px"; }, true);
  addEventListener("mousedown", () => { c.style.transform = "scale(.7)"; }, true);
  addEventListener("mouseup", () => { c.style.transform = ""; }, true);
});`;

/** Moves the pointer there visibly, then clicks. */
async function glide(page, locator, { click = true, wait = 600 } = {}) {
  const el = locator.first();
  await el.scrollIntoViewIfNeeded();
  const box = await el.boundingBox();
  if (!box) throw new Error("nothing to click");
  await page.mouse.move(box.x + Math.min(box.width / 2, 60), box.y + box.height / 2, { steps: 25 });
  await pause(250);
  if (click) await page.mouse.click(box.x + Math.min(box.width / 2, 60), box.y + box.height / 2);
  await pause(wait);
}

// ----- what to capture -------------------------------------------------------------------------

const WANNACRY = "#demo=wannacry";

/** Stills, light theme unless `dark`. `mock` runs in the agent design mode. */
const shots = [
  { name: "code", about: "Decompiled C beside the control-flow graph", go: (p, b) => open(p, b, `${WANNACRY}&fn=0x401ce8&view=c+graph`) },
  { name: "code-dark", dark: true, about: "The same, dark theme", go: (p, b) => open(p, b, `${WANNACRY}&fn=0x401ce8&view=c+graph`) },
  { name: "overview", about: "First look, file map and capabilities", go: (p, b) => open(p, b, WANNACRY) },
  {
    name: "capabilities", about: "One capability: its ATT&CK and MBC ids and the functions behind it",
    go: async (p, b) => {
      await open(p, b, WANNACRY);
      const row = p.locator("button.caprow-head", { hasText: "encrypt data using AES" }).first();
      await row.click();
      // The tactic heading above, the functions below.
      await row.evaluate((el) => el.scrollIntoView({ block: "center" }));
      await pause(600);
    },
  },
  { name: "callgraph", about: "Callers and callees of the main routine, with capability counts", go: (p, b) => open(p, b, `${WANNACRY}&fn=0x401fe7&view=calls`) },
  { name: "hex", about: "The code that extracts the XIA resource beside the embedded ZIP in hex", go: (p, b) => open(p, b, `${WANNACRY}&fn=0x401dab&view=c+hex&at=0x4100f0`) },
  { name: "strings", about: "Referenced strings and the functions that use them", go: (p, b) => open(p, b, `${WANNACRY}&view=strings`) },
  { name: "imports", about: "Imports and exports", go: (p, b) => open(p, b, `${WANNACRY}&view=imports`) },
  { name: "file", about: "PE summary: identity, security flags, build and hashes", go: (p, b) => open(p, b, `${WANNACRY}&view=file`) },
  {
    name: "search", about: "One search across functions, strings, code and imports",
    go: async (p, b) => { await open(p, b, `${WANNACRY}&fn=0x401fe7&view=c+graph`); await palette(p, "Service"); },
  },
  {
    name: "compare", about: "Two builds compared, down to the changed lines",
    go: async (p, b) => {
      await p.goto(`${b}/`);
      await p.locator("#lp-tab-compare").click();
      await p.locator("button.lp-start", { hasText: "Open this comparison" }).click();
      await p.waitForFunction(() => /B adds .* and changes/.test(document.body.innerText), null, { timeout: 180_000 });
      await pause(1000);
      // A changed function shows both sides; the first change is a new one, all on one side.
      await p.getByText("No longer calls IsDebuggerPresent", { exact: false }).first().click();
      await pause(1500);
      await p.mouse.move(VIEWPORT.width - 2, VIEWPORT.height - 2);
    },
  },
  {
    name: "archive", about: "A password-protected zip: unlocked with a known password, one member picked",
    go: async (p, b) => {
      await p.goto(`${b}/`);
      await p.locator('input[type="file"]').first().setInputFiles({ name: "samples.zip", mimeType: "application/zip", buffer: await sampleZip() });
      await p.waitForFunction(() => document.body.innerText.includes("wannacry.exe"), null, { timeout: 60_000 });
      await pause(1200);
      await p.mouse.move(VIEWPORT.width - 2, VIEWPORT.height - 2);
    },
  },
  {
    name: "ai", mock: true, about: "Claude Code's triage of WannaCry, replayed in the Agent panel",
    go: async (p, b) => {
      await open(p, b, `${WANNACRY}&fn=0x401fe7&view=c+graph`);
      await agentTriage(p);
      // Start of the answer: the verdict, under the tool calls that back it.
      await p.evaluate(() => {
        const h = [...document.querySelectorAll(".ag-items h1, .ag-items h2, .ag-items h3")].find((e) => e.textContent?.startsWith("Verdict"));
        if (!h) return;
        h.scrollIntoView({ block: "start" });
        let box = h.parentElement;
        while (box && box.scrollHeight <= box.clientHeight) box = box.parentElement;
        box?.scrollBy(0, -330);
      });
      await pause(600);
    },
  },
  {
    name: "report", mock: true, about: "The report the agent saved, with clickable function addresses",
    go: async (p, b) => {
      await open(p, b, `${WANNACRY}&fn=0x401fe7&view=c+graph`);
      await p.getByRole("button", { name: "Agent", exact: true }).click();
      await clickText(p, "button, [role=tab]", "Artifacts");
      await pause(800);
      await p.locator(".ag-art button, .ag-art li, button", { hasText: "WannaCry (WanaCrypt0r 2.0)" }).first().click();
      await pause(1000);
      await p.mouse.move(VIEWPORT.width - 2, VIEWPORT.height - 2);
    },
  },
];

async function agentTriage(p, { visible = false } = {}) {
  const agent = p.getByRole("button", { name: "Agent", exact: true });
  if (visible) await glide(p, agent); else await agent.click();
  const triage = p.locator("button.ag-suggest", { hasText: "Triage this binary" });
  if (visible) await glide(p, triage, { wait: 0 }); else await triage.click();
  // The run's cost appears under the composer when it ends.
  await p.waitForFunction(() => /·\s*\$\d+\.\d\d/.test(document.body.innerText), null, { timeout: 120_000 });
  await pause(800);
}

/** Recordings: a first look at a sample, and an agent run replayed. */
const videos = [
  {
    name: "tour", gif: true, about: "From a sample to its decompiled code",
    go: async (p, b) => {
      await p.goto(`${b}/`);
      await pause(1500);
      await glide(p, p.locator("button.lp-tile[title='WannaCry']"));
      await glide(p, p.locator("button.lp-start"), { wait: 0 });
      await ready(p);
      await pause(1800);
      // Overview → a capability → the function that matched it.
      const row = p.locator("button.caprow-head", { hasText: "create service" }).first();
      await row.scrollIntoViewIfNeeded();
      await pause(900);
      await glide(p, row, { wait: 1200 });
      await glide(p, p.locator(".caprow a, .caprow button", { hasText: "FUN_00401ce8" }), { wait: 2500 });
      // Search everything at once.
      await p.mouse.move(VIEWPORT.width / 2, 28, { steps: 20 });
      await palette(p, "wnry");
      await pause(1600);
      await p.keyboard.press("Escape");
      // Narrow the function list, then open the main routine.
      await glide(p, p.getByPlaceholder("Filter functions"), { wait: 200 });
      await p.keyboard.type("1fe7", { delay: 120 });
      await pause(700);
      await glide(p, p.locator("span.fn", { hasText: "FUN_00401fe7" }), { wait: 3000 });
    },
  },
  {
    name: "agent", mock: true, about: "Triage this binary, answered by Claude Code through Binfera's tools",
    go: async (p, b) => {
      await open(p, b, `${WANNACRY}&fn=0x401fe7&view=c+graph`);
      p.startHere();
      await pause(800);
      await agentTriage(p, { visible: true });
      await pause(2500);
    },
  },
];

if (args.includes("--list")) {
  for (const s of [...shots, ...videos]) console.log(`${s.name.padEnd(14)} ${s.about}`);
  process.exit(0);
}
const pick = (list) => list.filter((s) => !wanted.length || wanted.includes(s.name));

// ----- run -------------------------------------------------------------------------------------

const servers = {};
async function serve(mode) {
  if (!servers[mode]) {
    const server = await createServer({ root: web, mode, logLevel: "error", server: { port: 0, host: "127.0.0.1" } });
    await server.listen();
    servers[mode] = server;
  }
  const { port } = servers[mode].httpServer.address();
  return `http://127.0.0.1:${port}`;
}

const temp = await mkdtemp(join(tmpdir(), "binfera-capture-"));
const browser = await chromium.launch();
try {
  for (const shot of pick(shots)) {
    const base = await serve(shot.mock ? "mock" : "development");
    const context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 2, colorScheme: shot.dark ? "dark" : "light" });
    const page = await context.newPage();
    try {
      await shot.go(page, base);
      const png = join(temp, `${shot.name}.png`);
      await page.screenshot({ path: png });
      const webp = join(out, `${shot.name}.webp`);
      const r = spawnSync("cwebp", ["-quiet", "-q", "82", "-m", "6", png, "-o", webp]);
      if (r.status !== 0) throw new Error(String(r.stderr));
      console.log(`${shot.name}.webp  ${shot.about}`);
    } catch (e) {
      console.error(`${shot.name}: ${e.message}`);
      await page.screenshot({ path: join(temp, `${shot.name}-failed.png`) }).catch(() => {});
      process.exitCode = 1;
    } finally {
      await context.close();
    }
  }

  for (const video of noVideo ? [] : pick(videos)) {
    const base = await serve(video.mock ? "mock" : "development");
    const dir = join(temp, video.name);
    const context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 1, colorScheme: "light", recordVideo: { dir, size: VIEWPORT } });
    await context.addInitScript(CURSOR);
    const page = await context.newPage();
    // Recordings start when the page does; a video can skip its own loading with `page.startHere()`.
    const opened = Date.now();
    let skip = 0.6;
    page.startHere = () => { skip = (Date.now() - opened) / 1000; };
    let ok = true;
    try {
      await video.go(page, base);
    } catch (e) {
      ok = false;
      console.error(`${video.name}: ${e.message}`);
      process.exitCode = 1;
    }
    await context.close();
    if (!ok) continue;
    const [webm] = (await readdir(dir)).filter((f) => f.endsWith(".webm"));
    await encode(join(dir, webm), video.name, skip, video.gif);
    console.log(`${video.name}.mp4${video.gif ? ` / ${video.name}.gif` : ""}  ${video.about}`);
  }
} finally {
  await browser.close();
  await Promise.all(Object.values(servers).map((s) => s.close()));
  if (!args.includes("--keep")) await rm(temp, { recursive: true, force: true });
  else console.log(`kept ${temp}`);
}

/** MP4 for the docs site; GIF for the README, since GitHub does not play videos from the repository. */
async function encode(webm, name, skip, gif) {
  const ff = (...a) => {
    const r = spawnSync("ffmpeg", ["-v", "error", "-y", ...a]);
    if (r.status !== 0) throw new Error(String(r.stderr));
  };
  const from = skip.toFixed(2);
  ff("-ss", from, "-i", webm, "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "28", "-preset", "slow", "-movflags", "+faststart", "-an", join(out, `${name}.mp4`));
  if (!gif) return;
  const palette = join(tmpdir(), `${name}-palette.png`);
  const scale = "fps=10,scale=960:-1:flags=lanczos";
  // From the MP4, whose smoother frames differ less from one another: about a third of the size.
  const mp4 = join(out, `${name}.mp4`);
  ff("-i", mp4, "-vf", `${scale},palettegen=max_colors=128:stats_mode=diff`, palette);
  ff("-i", mp4, "-i", palette, "-lavfi", `${scale}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle`, join(out, `${name}.gif`));
  await rm(palette, { force: true });
}
