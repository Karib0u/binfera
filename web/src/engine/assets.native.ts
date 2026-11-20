// Desktop build's stand-in for assets.ts (vite.config.ts swaps it in with `--mode desktop`).
// The native engine ships inside the app, with its signatures and rules, so there is nothing to
// download and nothing to hand to a worker.
export type Arch = "x64" | "x86" | null;
export type WinApi = "32" | "64" | null;
export function winApiFor(_arch: string | null | undefined, _format: string | null | undefined): WinApi { return null; }
export interface Progress { label: string; fraction: number | null }

/** True in the desktop build: the engine is native, multi-process and not memory-limited. */
export const NATIVE = true;

export interface Assets {
  /** Unused natively; present so callers share one shape with the browser build. */
  module: WebAssembly.Module;
  data(kind: "capa" | "decompile"): Record<string, ArrayBuffer>;
  rules: Record<string, string>;
}

const assets: Assets = { module: null as unknown as WebAssembly.Module, data: () => ({}), rules: {} };

export async function loadAssets(_arch: Arch, _onProgress: (p: Progress | null) => void, _signatures = true, _winApi: WinApi = null): Promise<Assets> {
  return assets;
}

export async function loadEngine(_onProgress: (p: Progress | null) => void): Promise<WebAssembly.Module> {
  return assets.module;
}

export async function loadEngineId(): Promise<string | null> { return null; }
