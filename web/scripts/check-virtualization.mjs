// Production components in headless Chromium. Optional argument: a function record with asm/cfg.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { chromium } from "playwright";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const temp = await mkdtemp(join(tmpdir(), "binfera-virtualization-"));
const browser = await chromium.launch();
try {
  await build({ entryPoints: [fileURLToPath(new URL("virtualization/harness.tsx", import.meta.url))], bundle: true,
    outfile: join(temp, "app.js"), jsx: "automatic", define: { "process.env.NODE_ENV": '"production"' }, logLevel: "error",
    plugins: [{ name: "engine-free", setup(b) {
      b.onResolve({ filter: /\/engine\/assets$/ }, () => ({ path: "engine-assets", namespace: "test" }));
      b.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export const NATIVE = false;" }));
    } }],
  });
  await writeFile(join(temp, "index.html"), '<!doctype html><link rel="stylesheet" href="app.css"><div id="root"></div><script src="app.js"></script>');
  const page = await browser.newPage({ viewport: { width: 1100, height: 800 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(pathToFileURL(join(temp, "index.html")).href);
  await page.evaluate(() => {
    window.tasks = [];
    new PerformanceObserver((list) => window.tasks.push(...list.getEntries().map((e) => e.duration))).observe({ type: "longtask" });
  });
  const synthetic = { address: 0x400000, name: "large_test", asm: Array.from({ length: 9931 }, (_, i) =>
    [0x400000 + i * 4, "8b44240c", i % 20 === 19 ? `jnz ${(0x400000 + Math.min(9930, i + 10) * 4).toString(16).toUpperCase()}h` : "mov eax, dword ptr [esp+0Ch]"]) };
  synthetic.asm[0][2] = `jnz ${synthetic.asm.at(-1)[0].toString(16).toUpperCase()}h`;
  const mount = async (f, mode) => {
    await page.evaluate(({ f, mode }) => { window.tasks = []; window.mount(f, mode); }, { f, mode });
    await page.waitForSelector(mode === "graph" ? ".gb" : mode === "mobile" ? ".m-seg" : ".insn");
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  };
  const navigate = async (ad) => {
    await page.evaluate((ad) => window.navigate(ad), ad);
    await page.waitForFunction((ad) => document.querySelector(".insn.hl")?.dataset.addr === String(ad), ad);
  };
  const inPane = async (selector) => page.locator(selector).evaluate((el) => {
    const row = el.getBoundingClientRect(), box = el.closest(".cp-pane").getBoundingClientRect();
    return row.top >= box.top && row.bottom <= box.bottom;
  });
  const stats = async () => page.evaluate(() => ({ nodes: document.querySelectorAll("*").length,
    rows: document.querySelectorAll(".insn,.gi").length, longestTask: Math.max(0, ...window.tasks) }));

  await mount({ ...synthetic, asm: synthetic.asm.slice(0, 1500) }, "asm");
  assert.equal(await page.locator(".insn").count(), 1500, "ordinary functions keep all rows");
  await mount(synthetic, "asm");
  assert.ok(await page.locator(".insn").count() < 100);
  await page.locator('.insn a[title="Go to this instruction"]').first().click();
  await page.waitForFunction((ad) => document.querySelector(".insn.hl")?.dataset.addr === String(ad), synthetic.asm.at(-1)[0]);
  assert.ok(await inPane(".insn.hl"), "branch links reveal unmounted targets");
  await page.locator(".asm").focus();
  await page.keyboard.press("ArrowUp");
  await page.waitForFunction((ad) => window.currentCursor === ad, synthetic.asm.at(-2)[0]);
  assert.ok(await inPane(".insn.hl"), "keyboard selection remains visible");
  await navigate(synthetic.address);
  await page.locator(".arrow").filter({ hasText: `from 0x${synthetic.address.toString(16)} to 0x${synthetic.asm.at(-1)[0].toString(16)}` }).locator(".arrow-hit").dispatchEvent("click");
  await page.waitForFunction((ad) => window.currentCursor === ad, synthetic.asm.at(-1)[0]);
  await navigate(synthetic.asm[5000][0]);
  await page.locator('.insn.hl [data-tok="mov"]').click();
  await navigate(synthetic.asm[8000][0]);
  assert.notEqual(await page.locator('.insn.hl [data-tok="mov"]').evaluate((el) => getComputedStyle(el).backgroundColor), "rgba(0, 0, 0, 0)", "word highlighting applies to newly mounted rows");
  assert.equal(await page.evaluate(() => window.scrollY), 0, "navigation scrolls only the pane");
  await page.locator(".cp-pane").evaluate((el) => el.scrollTop = 100000);
  await page.waitForFunction(() => Number(document.querySelector(".insn")?.dataset.addr) < 0x400000 + 5100 * 4);

  await page.locator(".cockpit").evaluate((el) => el.style.height = "350px");
  await navigate(synthetic.asm[6000][0]);
  assert.ok(await inPane(".insn.hl"), "navigation follows pane resizing");

  const linked = { ...synthetic, text: "void test() {\n  first();\n  last();\n}", lines: [[], [synthetic.address], [synthetic.asm.at(-1)[0]], []] };
  await mount(linked, "sync");
  await page.locator('[data-ln="2"]').click();
  await page.waitForFunction((ad) => window.currentCursor === ad, synthetic.asm.at(-1)[0]);
  assert.ok(await inPane(".insn.hl"), "C selection reveals unmounted assembly");
  await page.locator(".insn.hl").click();
  assert.ok(await page.locator('[data-ln="2"].hl').count(), "assembly selection marks C");

  await mount(synthetic, "mobile");
  await page.evaluate((ad) => window.navigate(ad), synthetic.asm.at(-1)[0]);
  await page.getByRole("tab", { name: "Asm", exact: true }).click();
  await page.waitForSelector(".insn.hl");
  assert.ok(await inPane(".insn.hl"), "opening the phone Asm tab reveals the cursor");
  assert.equal(await page.locator(".insn.hl").evaluate((el) => el.getBoundingClientRect().height), 20);

  const f = process.argv[2] ? JSON.parse(await readFile(process.argv[2], "utf8")) : synthetic;
  for (const mode of ["asm", "graph"]) {
    await mount(f, mode);
    const opening = await stats();
    if (mode === "graph" || f.asm.length > 1500) assert.ok(opening.nodes < 5000, `${mode}: ${opening.nodes} DOM nodes`);
    console.log(`${mode}: ${JSON.stringify(opening)}`);
    if (mode === "graph") {
      const total = Number((await page.locator(".graph-tools small").textContent()).split(" ")[0]);
      assert.ok(await page.locator(".gb").count() < total, "offscreen blocks are not mounted");
      await page.evaluate((ad) => window.navigate(ad), f.asm.at(-1)[0]);
      await page.waitForSelector(".gi.hl");
      assert.ok(await page.locator(".gi.hl").evaluate((el) => {
        const row = el.getBoundingClientRect(), box = el.closest(".graph-view").getBoundingClientRect();
        return row.top >= box.top && row.bottom <= box.bottom;
      }), "cursor pans to a previously unmounted block");
      await page.locator(".gi.hl").click();
      assert.ok(await page.locator(".gb.on").count(), "clicking still selects a block");
      const beforePan = await page.locator(".graph-canvas").getAttribute("style");
      const box = await page.locator(".graph-view").boundingBox();
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.move(box.x + box.width / 2 + 80, box.y + box.height / 2 + 80, { steps: 5 });
      await page.mouse.up();
      assert.notEqual(await page.locator(".graph-canvas").getAttribute("style"), beforePan, "dragging still pans");
      const mini = page.locator(".gmini");
      assert.equal((await mini.locator(".gmini-blocks").evaluateAll((paths) => paths.reduce((n, p) => n + (p.getAttribute("d").match(/M/g) ?? []).length, 0))), total, "minimap still draws every block");
      if ((await mini.boundingBox()).width > 5) await mini.click();
      await page.getByRole("button", { name: "Fit", exact: true }).click();
      assert.equal(await page.locator(".gb").count(), total, "Fit mounts the whole graph");
    }
  }
  assert.deepEqual(errors, []);
  console.log("Threshold, offscreen targets, arrows, keyboard, word highlighting, C sync, graph cursor and minimap: passed");
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
