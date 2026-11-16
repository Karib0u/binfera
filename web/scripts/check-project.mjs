// Notes <-> project database sync (desktop): import of browser notes, write-through, polling, restart.
// Bundles the real src/names.ts against an in-memory stand-in for the Tauri commands, then runs it.
import { build } from "esbuild";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(mkdtempSync(join(tmpdir(), "binfera-project-")), "check.mjs");
await build({
  entryPoints: [join(here, "project/check.ts")], bundle: true, platform: "node", format: "esm", outfile: out, logLevel: "error",
  plugins: [{ name: "fake-client", setup(b) { b.onResolve({ filter: /project\/client$/ }, () => ({ path: join(here, "project/fake-client.ts") })); } }],
});
const result = spawnSync(process.execPath, [out], { stdio: "inherit" }).status ?? 1;
if (result) process.exit(result);
const browserOut = join(dirname(out), "browser.mjs");
await build({
  entryPoints: [join(here, "project/browser.ts")], bundle: true, platform: "node", format: "esm", outfile: browserOut, logLevel: "error",
});
process.exit(spawnSync(process.execPath, [browserOut], { stdio: "inherit" }).status ?? 1);
