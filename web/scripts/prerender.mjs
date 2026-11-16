// Render the initial landing page at build time. The browser still mounts the interactive app.
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { createServer } from "vite";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = new URL("../dist/index.html", import.meta.url);
const vite = await createServer({ root, appType: "custom", server: { middlewareMode: true, hmr: false, watch: null } });
try {
  const { default: Prerender } = await vite.ssrLoadModule("/src/prerender.tsx");
  const html = await readFile(output, "utf8");
  const outlet = '<div id="root"></div>';
  if (!html.includes(outlet)) throw new Error("Landing page outlet not found in dist/index.html");
  const landing = renderToString(createElement(Prerender));
  await writeFile(output, html.replace(outlet, () => `<div id="root">${landing}</div>`));
  console.log("Prerendered the landing page into dist/index.html");
} finally {
  await vite.close();
}
