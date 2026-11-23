// Hex byte selection (drag, Shift+click, Shift+arrows), copy formats, and the undo / redo / star toasts.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { chromium } from "playwright";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const temp = await mkdtemp(join(tmpdir(), "binfera-hex-"));
const browser = await chromium.launch();
try {
  await build({ entryPoints: [fileURLToPath(new URL("hex/harness.tsx", import.meta.url))], bundle: true,
    outfile: join(temp, "app.js"), jsx: "automatic", logLevel: "error",
    define: { "process.env.NODE_ENV": '"production"', "import.meta.url": '"http://localhost/app.js"', "import.meta.env.SSR": "false",
      __BINFERA_BUILD__: '{"version":"test","commit":null}' },
    plugins: [{ name: "engine-free", setup(b) {
      b.onResolve({ filter: /\/engine\/assets$/ }, () => ({ path: "engine-assets", namespace: "test" }));
      b.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export const NATIVE = false;" }));
    } }],
  });
  const context = await browser.newContext({ viewport: { width: 1300, height: 800 } });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "http://localhost" });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.route("http://localhost/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/app.js" || path === "/app.css") return route.fulfill({ path: join(temp, path.slice(1)) });
    if (path === "/") return route.fulfill({ contentType: "text/html", body: '<!doctype html><link rel="stylesheet" href="app.css"><div id="root"></div><script src="app.js"></script>' });
    return route.fulfill({ status: 404 });
  });
  await page.goto("http://localhost/");
  await page.evaluate(() => window.mountHex());
  const hex = page.getByRole("region", { name: "Hex pane" });
  await hex.waitFor();
  const byte = (o) => hex.locator(`.hb[data-o="${o}"]`);
  const selected = () => hex.locator(".hb.sel").count();
  const toast = page.locator(".toast");

  // Drag across four bytes of one row.
  await byte(2).dragTo(byte(5));
  assert.equal(await selected(), 4, "dragging selects the bytes between");
  await hex.getByText("4 bytes selected").waitFor();
  // Shift+click extends from where the drag began.
  await byte(9).click({ modifiers: ["Shift"] });
  assert.equal(await selected(), 8, "Shift+click extends the selection");
  // Shift+arrows move the end.
  await hex.locator(".hex-scroll").focus();
  await page.keyboard.press("Shift+ArrowLeft");
  assert.equal(await selected(), 7);

  const raw = await page.evaluate(() => [...window.bytes.slice(2, 9)]);
  await hex.getByRole("button", { name: "Copy hex" }).click();
  await toast.filter({ hasText: "Copied 7 bytes as hex" }).waitFor();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), raw.map((b) => b.toString(16).padStart(2, "0")).join(" "));
  await hex.getByRole("button", { name: "C array" }).click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "{ " + raw.map((b) => "0x" + b.toString(16).padStart(2, "0")).join(", ") + " }");
  // Right-click on the selection offers the same copies.
  await byte(4).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Copy selection as text" }).click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), raw.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join(""));
  // A plain click clears the selection; Escape does too.
  await byte(20).click();
  assert.equal(await selected(), 0);
  await byte(2).dragTo(byte(4));
  await hex.locator(".hex-scroll").focus();
  await page.keyboard.press("Escape");
  assert.equal(await selected(), 0);

  // Undo, redo and star announce themselves.
  await page.locator(".cockpit").first().click({ position: { x: 5, y: 5 } }).catch(() => {});
  await page.keyboard.press("s");
  await toast.filter({ hasText: "Starred work" }).waitFor();
  await page.keyboard.press("Control+z");
  await toast.filter({ hasText: "Undid starring work" }).waitFor();
  await page.keyboard.press("Control+Shift+z");
  await toast.filter({ hasText: "Redid starring work" }).waitFor();
  await page.keyboard.press("Control+z");
  await page.keyboard.press("Control+z");
  await toast.filter({ hasText: "Nothing to undo" }).waitFor();
  assert.deepEqual(errors, []);
  console.log("Hex selection by drag, Shift+click and Shift+arrows; copy as hex / C array / text; undo, redo and star toasts: passed");
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
