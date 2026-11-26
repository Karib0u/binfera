#!/usr/bin/env node
/**
 * Generate the 1200x630 Open Graph social preview image at web/public/og.png.
 * Run from repo root: node scripts/generate-og.mjs
 */

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");

const requireFromWeb = createRequire(path.join(root, "web", "package.json"));
const { chromium } = requireFromWeb("playwright");

const logoB64 = fs
  .readFileSync(path.join(root, "docs/images/logo-dark.png"))
  .toString("base64");
const codeB64 = fs
  .readFileSync(path.join(root, "docs/images/code.webp"))
  .toString("base64");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body {
    width: 1200px;
    height: 630px;
    overflow: hidden;
    background: #100f0e;
    color: #fafaf9;
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Inter", "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
  }

  .canvas {
    position: relative;
    width: 1200px;
    height: 630px;
    display: flex;
    background:
      radial-gradient(640px 480px at 8% 12%, rgba(249, 115, 22, 0.14), transparent 65%),
      radial-gradient(760px 560px at 88% 85%, rgba(249, 115, 22, 0.16), transparent 62%),
      radial-gradient(500px 400px at 52% 0%, rgba(99, 102, 241, 0.08), transparent 60%),
      linear-gradient(135deg, #121110 0%, #0d0c0b 100%);
  }

  /* Subtle dot grid */
  .grid {
    position: absolute;
    inset: 0;
    background-image: radial-gradient(rgba(255, 255, 255, 0.085) 1px, transparent 1px);
    background-size: 24px 24px;
    mask-image: radial-gradient(ellipse 85% 85% at 45% 50%, black 20%, transparent 90%);
    -webkit-mask-image: radial-gradient(ellipse 85% 85% at 45% 50%, black 20%, transparent 90%);
    pointer-events: none;
  }

  /* Subtle top accent hairline */
  .top-bar {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, #f97316 0%, #fb923c 38%, rgba(249, 115, 22, 0.12) 100%);
    z-index: 10;
  }

  .left {
    position: relative;
    z-index: 2;
    width: 500px;
    flex-shrink: 0;
    padding: 50px 28px 46px 54px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  .brand {
    display: flex;
    align-items: center;
  }

  .brand img {
    height: 52px;
    width: auto;
    display: block;
  }

  .copy {
    display: flex;
    flex-direction: column;
    gap: 20px;
    margin-top: -6px;
  }

  h1 {
    font-size: 56px;
    font-weight: 750;
    line-height: 1.03;
    letter-spacing: -0.038em;
    color: #fafaf9;
  }

  h1 .dot {
    color: #f97316;
  }

  .subtitle {
    font-size: 19px;
    line-height: 1.48;
    color: #a8a29e;
    font-weight: 420;
    max-width: 410px;
  }

  .subtitle strong {
    color: #e7e5e4;
    font-weight: 560;
  }

  .footer {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .pills {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .pill {
    font-family: "SF Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12.5px;
    font-weight: 550;
    color: #e7e5e4;
    background: rgba(255, 255, 255, 0.055);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 999px;
    padding: 6px 12px;
    letter-spacing: -0.01em;
  }

  .pill.accent {
    color: #fdba74;
    background: rgba(249, 115, 22, 0.12);
    border-color: rgba(249, 115, 22, 0.34);
  }

  .meta-row {
    display: flex;
    align-items: center;
    gap: 12px;
    font-family: "SF Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 13.5px;
    color: #78716c;
  }

  .meta-row .domain {
    color: #f97316;
    font-weight: 600;
  }

  .meta-row .sep {
    opacity: 0.45;
  }

  /* Right visual stage */
  .right {
    position: relative;
    z-index: 2;
    flex: 1;
    overflow: hidden;
  }

  .window-glow {
    position: absolute;
    top: 44px;
    left: 16px;
    width: 660px;
    height: 560px;
    background: radial-gradient(circle at 30% 35%, rgba(249, 115, 22, 0.22), transparent 65%);
    filter: blur(28px);
    pointer-events: none;
  }

  .window {
    position: absolute;
    top: 42px;
    left: 14px;
    width: 720px;
    height: 608px;
    border-radius: 14px 0 0 0;
    background: #ffffff;
    border: 1px solid rgba(255, 255, 255, 0.22);
    border-right: none;
    border-bottom: none;
    box-shadow:
      -20px 24px 64px rgba(0, 0, 0, 0.65),
      -4px 6px 20px rgba(0, 0, 0, 0.45),
      0 0 0 1px rgba(249, 115, 22, 0.12);
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .window-chrome {
    height: 34px;
    flex-shrink: 0;
    background: #f5f5f4;
    border-bottom: 1px solid #e7e5e4;
    display: flex;
    align-items: center;
    padding: 0 14px;
    gap: 12px;
  }

  .dots {
    display: flex;
    gap: 6px;
  }

  .dots span {
    width: 10px;
    height: 10px;
    border-radius: 50%;
  }

  .dots .r { background: #ff5f57; }
  .dots .y { background: #febc2e; }
  .dots .g { background: #28c840; }

  .url-bar {
    font-family: "SF Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11.5px;
    color: #57534e;
    background: #ffffff;
    border: 1px solid #e7e5e4;
    border-radius: 6px;
    padding: 3px 12px;
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .url-bar .lock {
    color: #16a34a;
    font-weight: 700;
  }

  .screenshot-wrap {
    position: relative;
    flex: 1;
    overflow: hidden;
    background: #f5f5f4;
  }

  /* Crop into the real workbench: focus on capa pills + decompiled C + Control Flow Graph */
  .screenshot {
    position: absolute;
    top: -64px;
    left: -270px;
    width: 1120px;
    height: auto;
    display: block;
    image-rendering: -webkit-optimize-contrast;
  }

  /* Soft bottom & right vignette so the cropped edge melts cleanly */
  .screenshot-fade {
    position: absolute;
    inset: 0;
    background:
      linear-gradient(to top, rgba(16, 15, 14, 0.22) 0%, transparent 18%),
      linear-gradient(to left, rgba(16, 15, 14, 0.16) 0%, transparent 10%);
    pointer-events: none;
  }
</style>
</head>
<body>
  <div class="canvas">
    <div class="top-bar"></div>
    <div class="grid"></div>

    <div class="left">
      <div class="brand">
        <img src="data:image/png;base64,${logoB64}" alt="Binfera" />
      </div>

      <div class="copy">
        <h1>See what a<br/>binary does<span class="dot">.</span></h1>
        <p class="subtitle">
          <strong>Ghidra's C++ decompiler</strong> &amp; <strong>Mandiant capa</strong> in Rust.
          Browser, desktop, CLI &amp; MCP. Nothing leaves your device.
        </p>
      </div>

      <div class="footer">
        <div class="pills">
          <span class="pill accent">No JVM</span>
          <span class="pill">Rust + WASM</span>
          <span class="pill">PE · ELF · Mach-O</span>
        </div>
        <div class="meta-row">
          <span class="domain">binfera.io</span>
          <span class="sep">·</span>
          <span>Apache-2.0 Open Source</span>
        </div>
      </div>
    </div>

    <div class="right">
      <div class="window-glow"></div>
      <div class="window">
        <div class="window-chrome">
          <div class="dots">
            <span class="r"></span>
            <span class="y"></span>
            <span class="g"></span>
          </div>
          <div class="url-bar">
            <span class="lock">●</span>
            <span>binfera.io / WannaCry (local WASM, 0 bytes uploaded)</span>
          </div>
        </div>
        <div class="screenshot-wrap">
          <img class="screenshot" src="data:image/webp;base64,${codeB64}" alt="Binfera decompiler and control-flow graph" />
          <div class="screenshot-fade"></div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;

const browser = await chromium.launch();
try {
  const page = await browser.newPage({
    viewport: { width: 1200, height: 630 },
    deviceScaleFactor: 1,
  });
  await page.setContent(html, { waitUntil: "networkidle" });
  const outPath = path.join(root, "web/public/og.png");
  await page.screenshot({ path: outPath, type: "png" });
  const sizeKb = (fs.statSync(outPath).size / 1024).toFixed(1);
  console.log(`Generated ${outPath} (1200x630, ${sizeKb} KB)`);
} finally {
  await browser.close();
}
