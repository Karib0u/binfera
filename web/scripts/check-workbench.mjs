// The desktop workspace in headless Chromium: File map clicks in Data mode, the Overview's Sections link, renaming any local,
// the header's grouped actions, Data tabs, the search palette's home, scopes and commands, and keyboard access to menus and dialogs.
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
    plugins: [{ name: "workbench-fixtures", setup(b) {
      b.onResolve({ filter: /\/engine\/assets$/ }, () => ({ path: "engine-assets", namespace: "test" }));
      b.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export const NATIVE = false; export const getFamilyPackName = () => null;" }));
      b.onResolve({ filter: /\/(agent|project)\/client$/ }, ({ path }) => {
        const client = path.split("/").at(-2);
        return { path: fileURLToPath(new URL(`../src/dev/${client}.mock.ts`, import.meta.url)) };
      });
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
  const mount = async (sel, layout, caps = 0) => { await page.evaluate(([s, l, c]) => window.mountWorkbench(s, l, c), [sel, layout, caps]); };
  const focused = () => page.evaluate(() => { const el = document.activeElement; return el?.getAttribute("aria-label") || el?.textContent?.trim() || el?.tagName; });

  // Data mode: a click on the File map shows the bytes at that place.
  await mount("strings");
  await page.locator(".nav").waitFor();
  const box = await page.locator(".nav").boundingBox();
  await page.mouse.click(box.x + box.width * 0.9, box.y + box.height / 2);
  await page.getByRole("region", { name: "Hex pane" }).waitFor();
  const cursor = await page.evaluate(() => new URL(location.href).hash);
  assert.match(cursor, /view=c(%2B|\+)hex/, "the map click opens a hex pane");
  assert.match(cursor, /at=0x40[12]/, "the cursor moved to the clicked address");

  // Data mode: underline tabs above the list, no left column; arrows move between them.
  await mount("strings");
  assert.equal(await page.locator("aside.cats").count(), 0, "no Data sidebar");
  const dataTabs = page.getByRole("tablist", { name: "Data" });
  assert.deepEqual((await dataTabs.getByRole("tab").allTextContents()).map((t) => t.replace(/\d+$/, "")), ["File", "Strings", "Imports & exports"]);
  assert.equal(await dataTabs.getByRole("tab", { name: /Strings/ }).getAttribute("aria-selected"), "true");
  const listLeft = (await page.locator(".data-list").boundingBox()).x, mainLeft = (await page.locator("main.pane").boundingBox()).x;
  assert.equal(listLeft, mainLeft, "the list starts at the main column's edge");
  await dataTabs.getByRole("tab", { name: /Strings/ }).focus();
  await page.keyboard.press("ArrowRight");
  await page.waitForFunction(() => document.activeElement?.id === "dtab-imports");
  assert.equal(await dataTabs.getByRole("tab", { name: /Imports/ }).getAttribute("aria-selected"), "true");
  assert.equal(await page.getByRole("tabpanel").getAttribute("aria-labelledby"), "dtab-imports");

  // The File map row: no permanent label or Legend; the hover readout names the colour, the place and its file offset.
  assert.equal(await page.locator(".nav-row").getByText("File map").count(), 0);
  assert.equal(await page.getByText("Legend", { exact: true }).count(), 0);
  const map = await page.locator(".nav").boundingBox();
  await page.mouse.move(map.x + map.width * 0.25, map.y + map.height / 2);
  const tip = page.locator(".nav-tip");
  await tip.waitFor();
  assert.match(await tip.textContent(), /^0x[0-9a-f]+ · \.text · [a-z ]+ · file offset 0x[0-9a-f]+$/);
  assert.equal(await tip.locator(".nav-swatch").count(), 1, "the readout shows the colour it describes");
  await page.mouse.move(0, 0);

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

  // On a narrower desktop the dock overlays the code, while a wider desktop gives it its own space.
  await page.setViewportSize({ width: 1152, height: 800 });
  await page.evaluate(() => localStorage.setItem("binfera-ui:agent-width", "640"));
  await mount(base, "c");
  const dock = page.getByRole("complementary", { name: "Agent" });
  await page.getByRole("button", { name: "Agent", exact: true }).click();
  await dock.waitFor();
  const shell = await page.locator(".shell").boundingBox();
  const panel = await dock.boundingBox();
  assert.equal(panel.x + panel.width, shell.x + shell.width, "overlay meets the right edge");
  assert.equal(panel.y, shell.y, "overlay starts below the header");
  assert.equal(panel.width, 520, "overlay caps the saved width");
  const artifacts = dock.getByRole("tab", { name: "Artifacts" });
  await artifacts.click();
  assert.equal(await artifacts.getAttribute("aria-selected"), "true");

  await page.setViewportSize({ width: 1440, height: 800 });
  await page.waitForFunction(() => document.querySelector(".agent-dock").getBoundingClientRect().width === 640);
  assert.equal(await dock.evaluate((el) => getComputedStyle(el).position), "relative");
  await page.setViewportSize({ width: 1152, height: 800 });
  const divider = dock.getByRole("separator", { name: "Resize the agent panel" });
  await page.waitForFunction(() => document.querySelector(".agent-dock").getBoundingClientRect().width === 520);
  await divider.press("ArrowRight");
  assert.equal(await divider.getAttribute("aria-valuenow"), "504", "resizing starts from the displayed width");
  await dock.getByRole("button", { name: "Hide the agent panel" }).click();
  await dock.waitFor({ state: "hidden" });

  // Function header: one capability reads inline, several collapse into one trigger.
  await mount(base, "c", 1);
  await page.locator(".cp-caps-inline .cap", { hasText: "Encrypt data using RC4" }).waitFor({ timeout: 5000 });
  await mount(base, "c", 3);
  await page.locator(".cp-head .cap-more").waitFor({ timeout: 5000 });
  assert.equal(await page.locator(".cp-caps-inline .cap").count(), 0, "no inline pills crowd the title");
  const capsTrigger = page.locator(".cp-head").getByRole("button", { name: "3 capabilities" });
  assert.equal(await capsTrigger.getAttribute("aria-expanded"), "false");
  await capsTrigger.click();
  assert.equal(await capsTrigger.getAttribute("aria-expanded"), "true");
  assert.equal(await page.getByRole("group", { name: "Capabilities matched in this function" }).locator(".cap").count(), 3);

  // An unlinked pane's breadcrumb: 11.5px or larger, fully opaque, and at least 4.5:1 against what is behind them.
  await mount(base, "c+asm");
  await page.getByRole("button", { name: "Disable pane sync" }).last().click();
  const crumb = page.locator(".pane-breadcrumb").first();
  await crumb.waitFor();
  const look = await crumb.evaluate((el) => {
    const rgb = (c) => c.match(/[\d.]+/g).slice(0, 4).map(Number);
    const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
    let bg = el, back;
    while (bg) { const c = rgb(getComputedStyle(bg).backgroundColor); if (c.length < 4 || c[3] > 0) { back = c; break; } bg = bg.parentElement; }
    const s = getComputedStyle(el), [a, b] = [lum(rgb(s.color)), lum(back ?? [255, 255, 255])];
    let opacity = 1;
    for (let n = el; n; n = n.parentElement) opacity *= Number(getComputedStyle(n).opacity);
    return { size: parseFloat(s.fontSize), opacity, contrast: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) };
  });
  assert.ok(look.size >= 11.5 && look.size <= 12, `breadcrumb is ${look.size}px`);
  assert.equal(look.opacity, 1, "no dimming opacity");
  assert.ok(look.contrast >= 4.5, `breadcrumb contrast ${look.contrast.toFixed(2)}:1`);

  // Header: Compare, New, packs and theme live in one ⋯ menu; arrows move through it and Escape returns focus.
  await mount(base, "c");
  const topbar = page.locator("header.topbar");
  for (const name of ["Compare…", "New"]) assert.equal(await topbar.getByRole("button", { name, exact: true }).count(), 0, `${name} is grouped`);
  assert.equal(await topbar.locator(".theme-toggle").count(), 0, "the theme toggle is grouped");
  for (const name of ["Back", "Forward", "Report", "More actions"]) await topbar.getByRole("button", { name, exact: true }).waitFor();
  await topbar.getByRole("button", { name: /Open file view/ }).waitFor();
  await topbar.getByRole("button", { name: /Search functions/ }).waitFor();
  const moreButton = topbar.getByRole("button", { name: "More actions" });
  await moreButton.click();
  const moreMenu = page.getByRole("menu", { name: "More actions" });
  const moreItems = await moreMenu.getByRole("menuitem").allTextContents();
  assert.deepEqual(moreItems.slice(0, 3), ["Compare with…", "Analyze another file", "Fingerprint packs…"]);
  assert.match(moreItems[3], /^(Light|Dark) mode$/);
  assert.equal(await focused(), "Compare with…", "the first item takes focus");
  await page.keyboard.press("ArrowDown");
  assert.equal(await focused(), "Analyze another file");
  await page.keyboard.press("ArrowUp");
  await page.keyboard.press("ArrowUp");
  assert.equal(await focused(), "Keyboard shortcuts", "ArrowUp wraps to the last item");
  await page.keyboard.press("Home");
  assert.equal(await focused(), "Compare with…");
  await page.keyboard.press("Escape");
  await moreMenu.waitFor({ state: "detached" });
  assert.equal(await focused(), "More actions", "Escape returns focus to the button");

  // Shortcuts dialog: Tab stays inside, Escape works from anywhere, focus returns to the menu button.
  await page.keyboard.press("ArrowDown");
  await moreMenu.waitFor();
  await page.keyboard.press("End");
  await page.keyboard.press("Enter");
  const keysDialog = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await keysDialog.waitFor();
  for (let n = 0; n < 3; n++) {
    await page.keyboard.press(n % 2 ? "Shift+Tab" : "Tab");
    assert.ok(await keysDialog.evaluate((el) => el.contains(document.activeElement)), "Tab stays in the dialog");
  }
  await page.evaluate(() => document.activeElement.blur());
  await page.keyboard.press("Escape");
  await keysDialog.waitFor({ state: "detached" });
  assert.equal(await focused(), "More actions", "focus returns to the trigger");

  // Fingerprint packs: Tab cycles its two buttons, Escape closes it and focus returns to the status bar button.
  const packsButton = page.locator(".sb-packs");
  await packsButton.click();
  const packs = page.getByRole("dialog", { name: "Fingerprint packs" });
  await packs.waitFor();
  assert.equal(await focused(), "Close", "the dialog's first control takes focus");
  await page.keyboard.press("Tab");
  assert.match(await focused(), /pack/i);
  await page.keyboard.press("Tab");
  assert.equal(await focused(), "Close", "Tab wraps to the first control");
  await page.keyboard.press("Shift+Tab");
  assert.match(await focused(), /pack/i, "Shift+Tab wraps to the last control");
  await page.keyboard.press("Escape");
  await packs.waitFor({ state: "detached" });
  assert.equal(await packsButton.evaluate((el) => el === document.activeElement), true, "focus returns to the status bar button");

  // Search palette, empty: Recent, Starred and the main views instead of a blank list. The open function is
  // listed as open, so Recent shows from the first function on.
  await page.keyboard.press("s");
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Search" });
  await palette.waitFor();
  const paletteSections = () => palette.locator(".palette-sec").allTextContents();
  assert.deepEqual(await paletteSections(), ["Recent", "Starred", "Go to"]);
  assert.equal(await palette.getByRole("group", { name: "Recent" }).getByRole("option").locator("i").textContent(), "open");
  assert.deepEqual(await palette.getByRole("group", { name: "Go to" }).getByRole("option").locator("span").allTextContents(), ["Overview", "Strings", "Imports", "File"]);
  await palette.getByRole("option", { name: /Strings/ }).click();
  await page.getByRole("tab", { name: /Strings/, selected: true }).waitFor();
  await page.keyboard.press("Control+k");
  await palette.waitFor();
  assert.deepEqual(await paletteSections(), ["Recent", "Starred", "Go to"]);
  assert.equal(await palette.getByRole("group", { name: "Recent" }).getByRole("option").locator("span").textContent(), "work");
  assert.equal(await palette.getByRole("group", { name: "Recent" }).getByRole("option").locator("i").textContent(), "function");
  await page.keyboard.press("Escape");
  // Recent survives opening the file again.
  await mount("strings");
  await page.waitForFunction(() => Object.keys(localStorage).some((k) => k.startsWith("binfera.recent:")));
  await page.keyboard.press("Control+k");
  await palette.getByRole("group", { name: "Recent" }).getByRole("option", { name: /work/ }).waitFor();

  // Tab and Shift+Tab cycle the scopes and keep focus in the box.
  const input = palette.getByRole("combobox");
  const pressed = () => palette.locator(".palette-scopes [aria-pressed=true]").textContent();
  for (const scope of ["Functions", "Strings", "Code", "Asm", "Imports", "References", "All"]) {
    await page.keyboard.press("Tab");
    assert.equal(await pressed(), scope);
  }
  await page.keyboard.press("Shift+Tab");
  assert.equal(await pressed(), "References");
  assert.equal(await input.inputValue(), "x: ");
  assert.equal(await input.evaluate((el) => el === document.activeElement), true, "focus stays in the search box");

  // > lists commands; typing narrows them and Enter runs one.
  await input.fill(">");
  const commands = await palette.getByRole("option").locator("span").allTextContents();
  for (const c of ["Toggle theme", "Focus mode", "Fingerprint packs…", "Export Markdown report", "Export HTML report", "Compare with…", "Split Asm", "Reset pane layout"]) assert.ok(commands.includes(c), `${c} is a command`);
  await input.fill(">split");
  assert.deepEqual(await palette.getByRole("option").locator("span").allTextContents(), ["Split Asm"]);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => /view=c(%2B|\+)asm/.test(location.hash));
  await page.keyboard.press("Control+k");
  await input.fill(">reset pane");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => /view=c(%2B|\+)listing/.test(location.hash));
  const themeBefore = await page.evaluate(() => document.documentElement.dataset.theme ?? "");
  await page.keyboard.press("Control+k");
  await input.fill(">theme");
  await page.keyboard.press("Enter");
  assert.notEqual(await page.evaluate(() => document.documentElement.dataset.theme ?? ""), themeBefore, "Toggle theme flips it");
  await page.keyboard.press("Control+k");
  await input.fill(">nothing like this");
  await palette.getByText("No matching commands.").waitFor();
  await page.keyboard.press("Escape");

  const report = page.getByRole("button", { name: "Report", exact: true });
  assert.equal(await report.evaluate((el) => {
    const range = document.createRange();
    range.selectNodeContents(el);
    const [first, ...rest] = range.getClientRects();
    return rest.every((rect) => rect.top === first.top);
  }), true, "Report and its arrow stay on one line");
  await report.click();
  const reportMenu = page.getByRole("menu", { name: "Report" });
  await reportMenu.waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute("role")), "menuitem", "the first item takes focus");
  const firstItem = await page.evaluate(() => document.activeElement.textContent);
  await page.keyboard.press("ArrowDown");
  assert.notEqual(await page.evaluate(() => document.activeElement.textContent), firstItem, "ArrowDown moves");
  await page.keyboard.press("ArrowUp");
  await page.keyboard.press("ArrowUp");
  assert.match(await page.evaluate(() => document.activeElement.textContent), /^All analysis data/, "ArrowUp wraps to the last item");
  await page.keyboard.press("Escape");
  await reportMenu.waitFor({ state: "detached" });
  assert.equal(await report.evaluate((el) => el === document.activeElement), true, "Escape returns focus to Report");

  assert.deepEqual(errors, []);
  console.log("Workbench: file navigation, Data tabs, File map readout, local renaming, capability trigger, breadcrumbs, grouped header, palette home, scopes and commands, menu and dialog keys, desktop Agent layouts, and the Report menu passed");
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
