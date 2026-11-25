import { invoke } from "@tauri-apps/api/core";

export interface NativeFamilyPack {
  available: true;
  name: string;
  size: number;
  path: string;
  /** "BXFAM002" or "BXFAM003", from the header; absent when unreadable. */
  format?: string | null;
}

type FamilyPackStatus = NativeFamilyPack | { available: false };

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

export function setCustomFamilyPack(_bytes: ArrayBuffer, _name: string): void {}
export function getFamilyPackName(): string | null { return null; }
export function addFamilyOverlay(_bytes: ArrayBuffer, _name: string): void {}
export function removeFamilyOverlay(_index: number): void {}
export async function loadFamilyPack(): Promise<NativeFamilyPack | null> {
  const status = await invoke<FamilyPackStatus>("family_pack_status");
  return status.available ? status : null;
}

/** The base pack then the overlays, as the native side resolves them. Empty without a base pack. */
export async function loadFamilyPacks(): Promise<NativeFamilyPack[]> {
  const base = await loadFamilyPack();
  if (!base) return [];
  const overlays = await invoke<FamilyPackStatus[]>("family_overlays_status");
  return [base, ...overlays.filter((o): o is NativeFamilyPack => o.available)];
}

export async function pickNativeFamilyPack(): Promise<NativeFamilyPack | null> {
  const status = await invoke<FamilyPackStatus | null>("select_family_pack");
  return status?.available ? status : null;
}

/** Opens the file dialog and layers the chosen pack over the others. False when cancelled. */
export async function pickNativeFamilyOverlay(): Promise<boolean> {
  const status = await invoke<FamilyPackStatus | null>("add_family_overlay");
  return !!status?.available;
}

export async function removeNativeFamilyOverlay(index: number): Promise<void> {
  await invoke("remove_family_overlay", { index });
}
