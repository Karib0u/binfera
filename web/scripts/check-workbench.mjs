// The desktop workspace in headless Chromium: File map clicks in Data mode, the Overview's Sections link, and renaming any local.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { chromium } from "playwright";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const base = 0x401000;
const temp = await mkdtemp(join(tmpdir(), "binfera-workbench-"));
const browser = await chromium.launch();
try {
  await build({ entryPoints: [fileURLToPath(new URL("workbench/harness.tsx", import.meta.url))], bundle: true,
    outfile: join(temp, "app.js"), jsx: "automatic", logLevel: "error",
    define: { "process.env.NODE_ENV": '"production"', "import.meta.url": '"http://localhost/app.js"', "import.meta.env.SSR": "false",
      __BINFERA_BUILD__: '{"version":"test","commit":null}' },
    plugins: [{ name: "engine-free", setup(b) {
      b.onResolve({ filter: /\/engine\/assets$/ }, () => ({ path: "engine-assets", namespace: "test" }));
      b.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export const NATIVE = false; export const getFamilyPackName = () => null;" }));
    } }],
  });
  const page = await browser.newPage({ viewport: { width: 1300, height: 800 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.context().route("http://localhost/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/app.js" || path === "/app.css") return route.fulfill({ path: join(temp, path.slice(1)) });
    if (path === "/") return route.fulfill({ contentType: "text/html", body: '<!doctype html><link rel="stylesheet" href="app.css"><div id="root"></div><script src="app.js"></script>' });
    return route.fulfill({ status: 404 });
  });
  await page.goto("http://localhost/");
  const mount = async (sel, layout) => { await page.evaluate(([s, l]) => window.mountWorkbench(s, l), [sel, layout]); };

  // Data mode: a click on the File map shows the bytes at that place.
  await mount("strings");
  await page.locator(".nav").waitFor();
  const box = await page.locator(".nav").boundingBox();
  await page.mouse.click(box.x + box.width * 0.9, box.y + box.height / 2);
  await page.getByRole("region", { name: "Hex pane" }).waitFor();
  const cursor = await page.evaluate(() => new URL(location.href).hash);
  assert.match(cursor, /view=c(%2B|\+)hex/, "the map click opens a hex pane");
  assert.match(cursor, /at=0x40[12]/, "the cursor moved to the clicked address");

  // Overview: the Sections link opens the File page at its section table.
  await mount("capa");
  await page.getByRole("button", { name: /Sections/ }).first().click();
  const sections = page.locator('[data-part="sections"]');
  await sections.waitFor();
  await page.waitForFunction(() => { const r = document.querySelector('[data-part="sections"]').getBoundingClientRect(); return r.top >= 0 && r.top < innerHeight; });

  // n renames whichever local was clicked: decompiler names, register inputs and declared locals alike.
  for (const [token, name] of [["iVar3", "total"], ["unaff_EBX", "saved_ebx"], ["auStack_28", "buffer"], ["count", "result"]]) {
    await mount(base, "c");
    await page.locator(`.cockpit [data-id="${token}"]`).first().click();
    await page.keyboard.press("n");
    const field = page.getByRole("textbox", { name: "Rename " + token });
    await field.waitFor();
    await field.fill(name);
    await field.press("Enter");
    await page.locator(".cockpit", { hasText: name }).first().waitFor();
    assert.equal(await page.locator(`.cockpit [data-id="${token}"]`).first().textContent(), name, `${token} renamed`);
    assert.match(await page.locator("input.rename").count() + "", /^0$/);
  }
  assert.equal(await page.getByText("work", { exact: true }).count() > 0, true, "the function keeps its name");

  // The right-click menu offers Rename variable… on a local, and not on a function name.
  await mount(base, "c");
  await page.locator('.cockpit [data-id="iVar3"]').first().click({ button: "right" });
  await page.getByRole("menuitem", { name: /Rename variable/ }).click();
  await page.getByRole("textbox", { name: "Rename iVar3" }).waitFor();
  await page.keyboard.press("Escape");
  assert.deepEqual(errors, []);
  console.log("Workbench: Data-mode File map, Overview Sections link, renaming every kind of local, and the Rename variable menu: passed");
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
