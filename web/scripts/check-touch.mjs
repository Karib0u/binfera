// Touch parity on a phone: the tapped-word action bar, the Star button in the header, and the call tree in Refs.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { chromium, devices } from "playwright";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const temp = await mkdtemp(join(tmpdir(), "binfera-touch-"));
const browser = await chromium.launch();
try {
  await build({ entryPoints: [fileURLToPath(new URL("touch/harness.tsx", import.meta.url))], bundle: true,
    outfile: join(temp, "app.js"), jsx: "automatic", logLevel: "error",
    define: { "process.env.NODE_ENV": '"production"', "import.meta.url": '"http://localhost/app.js"', "import.meta.env.SSR": "false",
      __BINFERA_BUILD__: '{"version":"test","commit":null}' },
    plugins: [{ name: "engine-free", setup(b) {
      b.onResolve({ filter: /\/engine\/assets$/ }, () => ({ path: "engine-assets", namespace: "test" }));
      b.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export const NATIVE = false;" }));
    } }],
  });
  const context = await browser.newContext({ ...devices["iPhone 13"], viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.route("http://localhost/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/app.js" || path === "/app.css") return route.fulfill({ path: join(temp, path.slice(1)) });
    if (path === "/") return route.fulfill({ contentType: "text/html", body: '<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="app.css"><div id="root"></div><script src="app.js"></script>' });
    return route.fulfill({ status: 404 });
  });
  await page.goto("http://localhost/");
  const mount = async () => { await page.evaluate(() => window.mountTouch()); await page.waitForSelector(".m-seg"); };
  const bar = page.getByRole("toolbar", { name: /Actions for/ });
  await mount();

  // Star in one tap, from the header.
  const star = page.locator(".m-bar .m-star");
  assert.equal(await star.getAttribute("aria-pressed"), "false");
  await star.tap();
  assert.equal(await star.getAttribute("aria-pressed"), "true");
  await star.tap();

  // Tapping a word opens its action bar; Rename edits the variable, not the function.
  const word = () => page.locator('.m-body [data-id="iVar1"]').first();
  await word().tap();
  await bar.waitFor();
  assert.deepEqual(await bar.getByRole("button").allInnerTexts(), ["Rename", "Xrefs", "Comment", "Copy", "Hex", "×"]);
  await bar.getByRole("button", { name: "Rename" }).tap();
  const field = page.getByRole("textbox", { name: "Rename iVar1" });
  await field.fill("result");
  await field.press("Enter");
  await page.locator('.m-body [data-id="iVar1"]', { hasText: "result" }).first().waitFor();
  assert.equal(await page.locator(".m-title h1").textContent(), "alpha");

  // Xrefs opens the references search; Comment opens the comment sheet; Hex opens the bytes.
  await word().tap();
  await bar.getByRole("button", { name: "Xrefs" }).tap();
  const palette = page.getByRole("dialog", { name: "Search" });
  await palette.waitFor();
  assert.match(await palette.locator("input").inputValue(), /^x:/);
  await page.keyboard.press("Escape");
  await word().tap();
  await bar.getByRole("button", { name: "Comment" }).tap();
  await page.locator("form.comment-editor, .sheet-comment").waitFor();
  await page.keyboard.press("Escape");
  await page.locator("form.comment-editor, .sheet-comment").waitFor({ state: "detached" });
  await word().tap();
  await bar.getByRole("button", { name: "Hex" }).tap();
  await page.getByLabel("File bytes").waitFor();
  assert.equal(await bar.count(), 0, "the bar leaves with the page");
  await mount();

  // Refs: calls as a tree. A tap on the arrow expands a callee into its own calls; a tap on a name opens it.
  await page.getByRole("tab", { name: /^Refs/ }).tap();
  const tree = page.getByRole("tree", { name: "Calls" });
  await tree.waitFor();
  assert.deepEqual(await tree.locator(".ct-fn code").allInnerTexts(), ["beta"]);
  await tree.getByRole("button", { name: "Expand beta" }).tap();
  assert.deepEqual(await tree.locator(".ct-fn code").allInnerTexts(), ["beta", "gamma"], "beta expands into gamma");
  await page.getByRole("tab", { name: /^Called by/ }).tap();
  assert.equal(await page.locator(".ct-empty").textContent(), "Nothing in this file calls this function.");
  await page.getByRole("tab", { name: /^Calls/ }).tap();
  await tree.getByRole("button", { name: "Expand beta" }).tap();
  await page.locator(".ct-fn", { hasText: "gamma" }).tap();
  await page.waitForFunction(() => document.querySelector(".m-title h1")?.textContent === "gamma");
  assert.equal(await page.locator('.m-seg [role=tab][aria-selected=true]').textContent(), "C", "an opened function shows its C");
  assert.deepEqual(errors, []);
  console.log("Touch: tapped-word action bar (rename, xrefs, comment, hex), header Star, call tree expand and open: passed");
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
