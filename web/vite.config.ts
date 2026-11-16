import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `--mode mock` is a browser-only design aid: the desktop's clients replaced by canned data (src/dev).
// `--mode desktop` is the Tauri build: the engine is the native binfera binary, so the
// WebAssembly-backed engine modules are replaced by their `.native` twins (which share their
// exports) and the wasm module never enters the bundle.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
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
