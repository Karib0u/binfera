// Exercise the built site both as an HTML-only document and as the interactive app.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { preview } from "vite";
import { chromium } from "playwright";

let server, browser;
try {
  server = await preview({
    root: fileURLToPath(new URL("../", import.meta.url)),
    preview: { host: "127.0.0.1", port: 0 },
    logLevel: "error",
  });
  const url = `http://127.0.0.1:${server.httpServer.address().port}/`;
  const response = await fetch(url);
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /<h1>/, "The HTTP response must contain the landing page");
  assert.match(html, /<script type="module"[^>]+src="[^"]+\.js"/, "The app must still load");

  browser = await chromium.launch();
  const staticContext = await browser.newContext({ javaScriptEnabled: false });
  const staticPage = await staticContext.newPage();
  await staticPage.goto(url);
  assert.equal(await staticPage.locator("h1").textContent(), "See what a binary does.");
  for (const name of ["Know what it is", "Read every function", "See what changed", "Follow the data", "Function emulation", "Scripts and CI"]) {
    assert.equal(await staticPage.getByRole("heading", { name, exact: true }).count(), 1, name);
  }
  assert.match(await staticPage.locator(".lp-lede").textContent(), /Decompiled C, capabilities, code origin and binary diffs/);
  for (const [name, href] of [
    ["Docs", "https://docs.binfera.io/"],
    ["Quickstart", "https://docs.binfera.io/getting-started/"],
    ["FAQ", "https://docs.binfera.io/faq/"],
  ]) {
    assert.equal(await staticPage.getByRole("link", { name, exact: true }).getAttribute("href"), href);
  }
  await staticContext.close();

  for (const settings of [
    { colorScheme: "light", expected: "dark" },
    { colorScheme: "dark", expected: "light" },
    { colorScheme: "dark", stored: "light", expected: "dark" },
  ]) {
    const context = await browser.newContext({ colorScheme: settings.colorScheme });
    if (settings.stored) await context.addInitScript(theme => localStorage.setItem("binfera.theme", theme), settings.stored);
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(url + "#fn=0x401000", { waitUntil: "networkidle" });
    assert.equal(await page.locator("h1").count(), 1, "Mounting must not duplicate the landing page");
    assert.match(await page.locator(".lp-message").textContent(), /function 0x401000/);
    await page.getByRole("button", { name: `Switch to ${settings.expected} mode`, exact: true }).click();
    assert.equal(await page.locator("html").getAttribute("data-theme"), settings.expected);
    await page.getByRole("tab", { name: "Compare two files", exact: true }).click();
    assert.equal(await page.getByRole("tab", { name: "Compare two files", exact: true }).getAttribute("aria-selected"), "true");
    await page.getByRole("tab", { name: "Analyze a file", exact: true }).click();

    if (settings.colorScheme === "light") {
      await page.locator("#lp-analyze input[type=file]").setInputFiles(fileURLToPath(new URL("../public/demo.exe", import.meta.url)));
      await page.getByRole("button", { name: "Open file view for demo.exe", exact: true }).waitFor();
      await page.waitForFunction(() => document.querySelector(".sb-status")?.textContent?.startsWith("●"), null, { timeout: 60000 });
      await page.getByRole("button", { name: "Code", exact: true }).click();
      await page.locator("[data-ctx-fn]").first().waitFor({ timeout: 15000 });
      await page.getByRole("button", { name: "More actions", exact: true }).click();
      await page.getByRole("menuitem", { name: "Analyze another file", exact: true }).click();
      await page.getByRole("heading", { name: "See what a binary does.", exact: true }).waitFor();
    }
    assert.deepEqual(errors, []);
    await context.close();
  }
  console.log("Built landing page: HTML-only content and links, themes, deep links, tabs, file analysis and return home passed");
} finally {
  await browser?.close();
  await new Promise(resolve => server ? server.httpServer.close(resolve) : resolve());
}
