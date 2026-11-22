// Production components in headless Chromium. Optional argument: a function record with asm/cfg.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { chromium } from "playwright";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const temp = await mkdtemp(join(tmpdir(), "binfera-virtualization-"));
const browser = await chromium.launch();
try {
  const worker = await build({ entryPoints: [fileURLToPath(new URL("../src/listing/listing.worker.ts", import.meta.url))],
    bundle: true, format: "esm", write: false });
  await build({ entryPoints: [fileURLToPath(new URL("virtualization/harness.tsx", import.meta.url))], bundle: true,
    outfile: join(temp, "app.js"), jsx: "automatic", logLevel: "error",
    define: { "process.env.NODE_ENV": '"production"', "import.meta.url": '"http://localhost/app.js"', "import.meta.env.SSR": "false",
      __BINFERA_BUILD__: '{"version":"test","commit":null}' },
    plugins: [{ name: "engine-free", setup(b) {
      b.onResolve({ filter: /\/engine\/assets$/ }, () => ({ path: "engine-assets", namespace: "test" }));
      b.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export const NATIVE = false;" }));
    } }],
  });
  const page = await browser.newPage({ viewport: { width: 1100, height: 800 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  // Same-origin resources for the harness and its worker, without a separate server.
  await page.context().route("http://localhost/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/app.js" || path === "/app.css") return route.fulfill({ path: join(temp, path.slice(1)) });
    if (path === "/listing.worker.ts") return route.fulfill({ contentType: "text/javascript", body: worker.outputFiles[0].text });
    if (path === "/") return route.fulfill({ contentType: "text/html", body: '<!doctype html><link rel="stylesheet" href="app.css"><div id="root"></div><script src="app.js"></script>' });
    return route.fulfill({ status: 404 });
  });
  await page.addInitScript(() => {
    window.listingWorkers = 0;
    window.listingBuilds = [];
    window.Worker = class extends Worker {
      constructor(path, options) {
        super(path, options);
        window.listingWorkers++;
      }
      postMessage(data, transfer) {
        window.listingBuilds.push(data.changes.length);
        super.postMessage(data, transfer);
      }
    };
  });
  await page.goto("http://localhost/");
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

  const [direct, indirect, both] = [4100, 8000, 9000].map((i) => synthetic.asm[i][0]);
  const hex = (va) => `0x${va.toString(16)}`;
  const missing = 0x500000;
  const prefix = "Unknown callee prototype: forwarded arguments or return types may be missing. Supply signatures for reliable call reconstruction.";
  const malformed = `${prefix} Uncertain calls (1): ${hex(direct)} -> truncated`;
  const details = [
    `${hex(direct)} -> named_target (arguments)`, `${hex(indirect)} -> indirect call (return)`,
    `${hex(both)} -> 0x401000 (arguments, return)`,
    ...Array.from({ length: 5 }, (_, i) => `${hex(missing + i)} -> other_target (return)`),
  ];
  const diagnostics = {
    ...linked, incomplete: true, unknown_callees: true,
    asm: linked.asm.map((row) => row[0] === direct || row[0] === both ? [row[0], "e800000000", "call 401000h"]
      : row[0] === indirect ? [row[0], "ffd0", "call eax"] : row),
    lines: [[], [synthetic.address, direct], [], []],
    warnings: ["Ordinary warning.", malformed, `${prefix} Uncertain calls (10): ${details.join("; ")}; 2 more calls`],
  };
  const openWarnings = async () => {
    const disclosure = page.locator(".cp-pane details.warn");
    await disclosure.waitFor();
    if (await disclosure.getAttribute("open") === null) await disclosure.locator("summary").click();
    return disclosure;
  };
  const callAt = (va) => page.getByRole("link", { name: hex(va), exact: true });
  const expectCallSelected = async (pane, va) => {
    const selected = pane.locator(".insn.hl");
    await selected.and(pane.locator(`[data-addr="${va}"]`)).waitFor();
    assert.equal(await selected.count(), 1, "only the exact call-site instruction is selected");
    assert.ok(await selected.evaluate((el) => {
      const row = el.getBoundingClientRect(), box = el.closest(".cp-pane").getBoundingClientRect();
      return row.top >= box.top && row.bottom <= box.bottom;
    }), "the call site is visible in Asm");
  };

  await page.evaluate((f) => window.mountWorkspace(f), diagnostics);
  const cPane = page.getByRole("region", { name: "C pane", exact: true });
  const asmPanes = page.getByRole("region", { name: "Asm pane", exact: true });
  const warnings = await openWarnings();
  assert.equal(await asmPanes.count(), 0, "start in C-only layout");
  await warnings.getByText("Ordinary warning.", { exact: true }).waitFor();
  await warnings.getByText(malformed, { exact: true }).waitFor();
  await warnings.getByText("2 more calls", { exact: true }).waitFor();
  await warnings.getByText(hex(missing), { exact: true }).waitFor();
  assert.equal(await warnings.getByRole("link").count(), 3, "only mapped call sites are actionable");
  await warnings.getByText(/named_target.*uncertain arguments$/).waitFor();
  await warnings.getByText(/indirect call.*uncertain return value$/).waitFor();
  await warnings.getByText(/0x401000.*uncertain arguments and return value$/).waitFor();
  await callAt(direct).press("Enter");
  await expectCallSelected(asmPanes, direct);
  assert.match(await asmPanes.getAttribute("class"), /is-active/);
  assert.match(new URL(page.url()).hash, new RegExp(`view=c\\+asm&at=${hex(direct)}$`));
  await openWarnings();
  await callAt(indirect).click();
  await expectCallSelected(asmPanes, indirect);
  await asmPanes.locator(".cp-pane").evaluate((el) => { el.scrollTop = 0; });
  await asmPanes.locator(`[data-addr="${indirect}"]`).waitFor({ state: "detached" });
  await callAt(indirect).click();
  await expectCallSelected(asmPanes, indirect);
  await cPane.getByRole("button", { name: "Disable pane sync" }).click();
  await callAt(both).click();
  await expectCallSelected(asmPanes.and(page.locator(".unlinked")), both);
  await expectCallSelected(asmPanes.and(page.locator(":not(.unlinked)")), indirect);
  assert.match(new URL(page.url()).hash, new RegExp(`&at=${hex(indirect)}$`), "an independent jump preserves the shared cursor");

  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate((f) => window.mountWorkspace(f), diagnostics);
  await openWarnings();
  await callAt(direct).click();
  await expectCallSelected(page.locator(".m-body"), direct);
  assert.equal(await page.getByRole("tab", { name: "Asm", exact: true }).getAttribute("aria-selected"), "true");
  await page.setViewportSize({ width: 1100, height: 800 });
  console.log("Call diagnostics: exact offscreen targets, C-only layout, linked and independent panes, mobile Asm, and warning fallback passed");

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

  await page.evaluate(() => { window.prepareListing(); window.mountListing(); });
  const listing = page.locator(".listing").first();
  const scroll = listing.locator(".l-scroll");
  await listing.getByText("Disassembly is still loading").waitFor();
  const base = 0x400000, end = base + 10_000 * 64 * 4;
  const tail = end - 96;
  const jump = (address) => page.evaluate((va) => window.navigateListing(va), address);
  const selection = listing.locator(".insn.hl");
  await jump(tail);
  await selection.and(listing.locator(`[data-addr="${tail}"]`)).waitFor();
  const previous = await scroll.evaluate((el) => el.scrollTop);
  const selectedY = (await selection.boundingBox()).y;
  await page.evaluate(() => { window.tasks = []; window.receiveListings(); });
  await page.waitForFunction((y) => document.querySelector(".l-scroll").scrollTop > y + 1_000_000, previous);
  assert.equal(await selection.getAttribute("data-addr"), String(tail), "late listings keep the same selected address");
  assert.ok(Math.abs((await selection.boundingBox()).y - selectedY) <= 1, "late listings preserve cursor position within the viewport");
  assert.ok(await listing.locator(".lrow").count() < 60, "the large file keeps only the viewport and overscan mounted");
  assert.deepEqual(await page.evaluate(() => window.listingBuilds), [128, 9872], "send only new disassembly to the shared worker");
  const longestTask = await page.evaluate(() => Math.max(0, ...window.tasks));

  await page.evaluate(() => window.settleListings());
  await listing.getByText("Disassembly is still loading").waitFor({ state: "hidden" });
  await jump(base);
  await listing.getByText("entry_label:").waitFor();
  await scroll.evaluate((el) => { el.scrollTop = 500; });
  await listing.locator(`[data-addr="${base}"]`).waitFor({ state: "detached" });
  assert.equal(await listing.locator(`[data-addr="${base + 63 * 4}"]`).count(), 0);
  await listing.locator(".arrow-hit").first().dispatchEvent("click");
  await selection.and(listing.locator(`[data-addr="${base + 63 * 4}"]`)).waitFor();

  await listing.getByLabel("Section").selectOption(String(end));
  await listing.getByText("test header").waitFor();
  await listing.getByText("magic").waitFor();
  await listing.getByText("test_import").waitFor();
  await listing.getByText('"listing string"').waitFor();
  await listing.getByTitle("Move the cursor there").click();
  await selection.and(listing.locator(`[data-addr="${base}"]`)).waitFor();

  await page.evaluate(() => window.showListingPanes(false));
  await listing.waitFor({ state: "detached" });
  await page.evaluate(() => window.showListingPanes(true));
  await listing.getByText("entry_label:").waitFor();
  assert.equal(await page.evaluate(() => window.listingWorkers), 1, "two panes and reopening reuse the index");
  assert.deepEqual(await page.evaluate(() => window.listingBuilds), [128, 9872], "settling without new instructions keeps the index");
  assert.deepEqual(errors, []);
  console.log(`Listing: 10,000 functions, 640,000 instructions, longest observed main-thread task ${longestTask} ms during the update`);
  console.log("Shared worker, incremental records, cursor anchoring, crossing arrows, data rows and section jumps: passed");
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
