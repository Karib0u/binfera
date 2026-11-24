// Multi-stage triage: an embedded executable or archive opens as its own file in one click, and Compare starts from an open file.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { chromium } from "playwright";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const temp = await mkdtemp(join(tmpdir(), "binfera-stages-"));
const browser = await chromium.launch();
try {
  await build({ entryPoints: [fileURLToPath(new URL("stages/harness.tsx", import.meta.url))], bundle: true,
    outfile: join(temp, "app.js"), jsx: "automatic", logLevel: "error",
    define: { "process.env.NODE_ENV": '"production"', "import.meta.url": '"http://localhost/app.js"', "import.meta.env.SSR": "false",
      __BINFERA_BUILD__: '{"version":"test","commit":null}' },
    plugins: [{ name: "engine-free", setup(b) {
      b.onResolve({ filter: /\/engine\/assets$/ }, () => ({ path: "engine-assets", namespace: "test" }));
      b.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export const NATIVE = false; export const getFamilyPackName = () => null;" }));
    } }],
  });
  const page = await browser.newPage({ viewport: { width: 1300, height: 900 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.route("http://localhost/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/app.js" || path === "/app.css") return route.fulfill({ path: join(temp, path.slice(1)) });
    if (path === "/") return route.fulfill({ contentType: "text/html", body: '<!doctype html><link rel="stylesheet" href="app.css"><div id="root"></div><script src="app.js"></script>' });
    return route.fulfill({ status: 404 });
  });
  await page.goto("http://localhost/");
  await page.evaluate(() => window.mountStages());
  const rows = page.locator(".fv-table tbody tr");
  await rows.first().waitFor();

  // Only an executable or archive offers Analyze; a PNG does not.
  assert.equal(await rows.nth(0).getByRole("button", { name: "Analyze" }).count(), 1);
  assert.equal(await rows.nth(1).getByRole("button", { name: "Analyze" }).count(), 0);
  await rows.nth(0).getByRole("button", { name: "Analyze" }).click();
  await page.waitForFunction(() => window.received.length === 1);
  let got = await page.evaluate(() => window.received[0]);
  assert.equal(got.name, "dropper.exe.RCDATA-XIA.bin");
  assert.equal(got.size, 0x400);
  assert.deepEqual(got.head, await page.evaluate(() => [...window.bytes.slice(0x100, 0x104)]), "the bytes are the resource's, not the file's start");

  // The overlay too.
  await page.locator(".fv-kv").getByRole("button", { name: "Analyze" }).click();
  await page.waitForFunction(() => window.received.length === 2);
  got = await page.evaluate(() => window.received[1]);
  assert.equal(got.name, "dropper.exe.overlay.bin");
  assert.equal(got.size, 0x800);

  // Compare… starts a comparison with this file as one side.
  await page.getByRole("button", { name: "Compare…" }).click();
  assert.equal(await page.evaluate(() => window.compareAsked), 1);
  assert.deepEqual(errors, []);
  console.log("Stages: Analyze on embedded resources and overlays, and Compare… from an open file: passed");
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
