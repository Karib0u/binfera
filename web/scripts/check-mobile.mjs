// The phone workspace in headless Chromium: a windowed function list on a 3,500-function binary, the search
// palette's input size and touch targets, the comment sheet, and the sheet's header drag.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { chromium, devices } from "playwright";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const temp = await mkdtemp(join(tmpdir(), "binfera-mobile-"));
const browser = await chromium.launch();
try {
  await build({ entryPoints: [fileURLToPath(new URL("mobile/harness.tsx", import.meta.url))], bundle: true,
    outfile: join(temp, "app.js"), jsx: "automatic", logLevel: "error",
    define: { "process.env.NODE_ENV": '"production"', "import.meta.url": '"http://localhost/app.js"', "import.meta.env.SSR": "false",
      __BINFERA_BUILD__: '{"version":"test","commit":null}' },
    plugins: [{ name: "engine-free", setup(b) {
      b.onResolve({ filter: /\/engine\/assets$/ }, () => ({ path: "engine-assets", namespace: "test" }));
      b.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export const NATIVE = false; export const getFamilyPackName = () => null;" }));
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
  await page.evaluate(() => window.mountMobile());
  await page.locator(".tabbar button", { hasText: "Code" }).tap();

  // The list is windowed: thousands of functions, a few dozen rows in the DOM, and scrolling reaches the end.
  const rows = page.locator(".m-fnlist .item");
  await rows.first().waitFor();
  assert.ok(await rows.count() < 60, `${await rows.count()} rows mounted`);
  assert.ok(await page.locator(".m-fnlist").evaluate((el) => el.scrollHeight) >= 3500 * 52, "the scroll height covers every function");
  await page.locator(".m-fnlist").evaluate((el) => { el.scrollTop = el.scrollHeight; });
  await page.getByText("FUN_0040eab0", { exact: false }).last().waitFor();
  assert.ok(await rows.count() < 60);
  await page.getByText("FUN_0040eab0").last().tap();
  await page.waitForSelector(".m-seg");

  // Search: 16px input (iOS zooms the page below that), 44px scope buttons and rows, inside the visible height.
  await page.evaluate(() => { window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true })); });
  const palette = page.getByRole("dialog", { name: "Search" });
  await palette.waitFor();
  assert.equal(await palette.locator("input").evaluate((el) => getComputedStyle(el).fontSize), "16px");
  for (const b of await palette.locator(".palette-scopes button").all()) assert.ok((await b.boundingBox()).height >= 44, "scope buttons are 44px tall");
  assert.ok((await palette.boundingBox()).y + (await palette.boundingBox()).height <= 844, "the palette fits the screen");
  await page.keyboard.press("Escape");

  // Comment: a bottom sheet with a 16px text area.
  await page.evaluate(() => { window.dispatchEvent(new KeyboardEvent("keydown", { key: ";", bubbles: true })); });
  {
    const sheet = page.getByRole("dialog", { name: /Comment at/ });
    await sheet.waitFor();
    await page.waitForTimeout(450); // the sheet rises into place
    assert.equal(await sheet.locator("textarea").evaluate((el) => getComputedStyle(el).fontSize), "16px");
    assert.ok((await sheet.boundingBox()).y + (await sheet.boundingBox()).height >= 843, "the sheet sits at the bottom edge");
    // Dragging the title, not just the 4px handle, dismisses it.
    const title = sheet.locator(".sheet-title");
    const t = await title.boundingBox();
    await page.mouse.move(t.x + 20, t.y + 5);
    await page.mouse.down();
    await page.mouse.move(t.x + 20, t.y + 60, { steps: 4 });
    await page.mouse.move(t.x + 20, t.y + 160, { steps: 4 });
    await page.mouse.up();
    await sheet.waitFor({ state: "detached" });
  }
  assert.deepEqual(errors, []);
  console.log("Mobile: windowed function list, 16px search input and 44px targets, comment sheet, header drag to dismiss: passed");
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
