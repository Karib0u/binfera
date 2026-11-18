import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const repo = new URL("../", import.meta.url);

function buildVersion(mode: string) {
  if (mode === "desktop") {
    return JSON.parse(readFileSync(new URL("./src-tauri/tauri.conf.json", import.meta.url), "utf8")).version;
  }
  // Use the released Binfera version instead of the private npm package version.
  const cargo = readFileSync(new URL("Cargo.toml", repo), "utf8");
  const workspace = cargo.split(/^\[workspace\.package\]\s*$/m)[1]?.split(/^\[/m)[0];
  const version = workspace?.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  if (!version) throw new Error("Missing workspace package version in Cargo.toml");
  return version;
}

function buildCommit() {
  if (!existsSync(new URL(".git", repo))) return null;
  try {
    return execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
      cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

// `--mode mock` is a browser-only design aid: the desktop's clients replaced by canned data (src/dev).
// `--mode desktop` is the Tauri build: the engine is the native binfera binary, so the
// WebAssembly-backed engine modules are replaced by their `.native` twins (which share their
// exports) and the wasm module never enters the bundle.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: {
    __BINFERA_BUILD__: JSON.stringify({ version: buildVersion(mode), commit: buildCommit() }),
  },
  worker: { format: "es" },
  resolve: {
    alias: mode === "desktop"
      ? [
          { find: /^(.*\/engine)\/(assets|run)$/, replacement: "$1/$2.native" },
          { find: /^(.*\/project)\/client$/, replacement: "$1/client.native" },
          { find: /^(.*\/agent)\/client$/, replacement: "$1/client.native" },
        ]
      : mode === "mock"
        ? [
            { find: /^(.*\/project)\/client$/, replacement: "$1/../dev/project.mock" },
            { find: /^(.*\/agent)\/client$/, replacement: "$1/../dev/agent.mock" },
          ]
        : [],
  },
  // Tauri needs a fixed port and must see the compile errors the dev server prints.
  clearScreen: false,
  server: { port: 5173, strictPort: mode === "desktop" },
}));
