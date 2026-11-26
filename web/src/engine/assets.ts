// Everything the engine needs from the network, downloaded once per page load with aggregate
// progress: the compiled wasm module, the FLIRT signature databases, the Function ID pack and the Windows prototype pack for
// the sample's architecture, and the capa rules.
import { digest } from "./resultCache";
import wasmUrl from "../wasm/binfera.wasm?url";

export type Arch = "x64" | "x86" | null;
/** Pointer width of the Windows API prototype pack a PE image needs (`winapi32.pack`, `winapi64.pack`). */
export type WinApi = "32" | "64" | null;

/** The Windows pack for a PE image: 32-bit for x86, 64-bit for x64 and AArch64 (which share it). */
export function winApiFor(arch: string | null | undefined, format: string | null | undefined): WinApi {
  if (format !== "pe") return null;
  return arch === "x86" ? "32" : arch === "x64" || arch === "aarch64" ? "64" : null;
}

/** False in the browser build: the engine is WebAssembly in workers (assets.native.ts says true). */
export const NATIVE = false;
/** Download progress. `stage` tells the engine module (first) from the signatures, rules and packs (second). */
export interface Progress { label: string; fraction: number | null; stage?: "engine" | "data" }

const base = import.meta.env.BASE_URL;
const FAMILY_PACK = `${base}sigs/family.bxfam`;
const SIGNATURES = ["1_flare_msvc_rtf_32_64.sig", "2_flare_msvc_atlmfc_32_64.sig", "3_flare_common_libs.sig"];

interface Download { loaded: number; total: number | null }
const downloads = new Map<string, Download>();
const cache = new Map<string, Promise<Uint8Array<ArrayBuffer>>>();
let listener: ((p: Progress) => void) | null = null;
let stage: "engine" | "data" = "engine";

function report() {
  if (!listener) return;
  const what = stage === "engine" ? "Downloading the analysis engine" : "Downloading signatures and rules";
  if (!downloads.size) return listener({ label: stage === "engine" ? "Starting the analysis engine" : "Loading signatures and rules", fraction: null, stage });
  let loaded = 0, total = 0, known = true;
  for (const d of downloads.values()) {
    loaded += d.loaded;
    if (d.total === null) known = false; else total += d.total;
  }
  const mb = (n: number) => (n / 1048576).toFixed(0);
  listener({
    label: known && total ? `${what} · ${mb(loaded)} / ${mb(total)} MB` : `${what} · ${mb(loaded)} MB`,
    fraction: known && total ? Math.min(1, loaded / total) : null,
    stage,
  });
}

/** Fetches `url` once (later callers share the result), reporting bytes as they arrive. */
function download(url: string): Promise<Uint8Array<ArrayBuffer>> {
  let hit = cache.get(url);
  if (!hit) {
    hit = (async () => {
      const res = await fetch(url);
      if (!res.ok || !res.body) throw new Error(`could not download ${url} (${res.status}); run \`npm run prepare-assets\``);
      // With content-encoding the header holds the compressed size, not what the stream yields.
      const length = Number(res.headers.get("content-length"));
      const entry: Download = { loaded: 0, total: res.headers.get("content-encoding") || !length ? null : length };
      downloads.set(url, entry);
      const chunks: Uint8Array[] = [];
      const reader = res.body.getReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        chunks.push(value);
        entry.loaded += value.length;
        report();
      }
      const out = new Uint8Array(entry.loaded);
      let at = 0;
      for (const c of chunks) { out.set(c, at); at += c.length; }
      entry.total = entry.loaded;
      report();
      return out;
    })();
    hit.catch(() => cache.delete(url));
    cache.set(url, hit);
  }
  return hit;
}

let wasmModule: Promise<WebAssembly.Module> | null = null;
const loadModule = () => (wasmModule ??= download(wasmUrl).then((b) => WebAssembly.compile(b)).catch((e) => { wasmModule = null; throw e; }));

export interface Assets {
  module: WebAssembly.Module;
  /** Files for the module's `/sigs`. Fresh copies per call, since workers take ownership. */
  data(kind: "capa" | "decompile"): Record<string, ArrayBuffer>;
  rules: Record<string, string>;
}

/** `familyPack` also fetches the hosted family pack here, so its download is counted with the rest instead of running silently afterwards. */
export async function loadAssets(arch: Arch, onProgress: (p: Progress | null) => void, signatures = true, winApi: WinApi = null, familyPack = false): Promise<Assets> {
  downloads.clear();
  stage = "data";
  listener = onProgress;
  report();
  try {
    const fid = arch ? `fid-${arch}.pack` : null;
    const winapi = winApi ? `winapi${winApi}.pack` : null;
    const [module, sigs, pack, api, rules] = await Promise.all([
      loadModule(),
      Promise.all(signatures ? SIGNATURES.map((n) => download(`${base}sigs/${n}`)) : []),
      fid ? download(`${base}sigs/${fid}z`).then(async (bytes) => new Uint8Array(await new Response(
        new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip")),
      ).arrayBuffer())) : Promise.resolve(null),
      // The Windows prototype pack is stored uncompressed: it is mostly names and type text the
      // CDN compresses in transit, and the engine copies it out of the file system anyway.
      winapi ? download(`${base}sigs/${winapi}`) : Promise.resolve(null),
      download(`${base}rules.json`).then((b) => JSON.parse(new TextDecoder().decode(b)) as Record<string, string>),
      familyPack ? download(FAMILY_PACK).catch(() => null) : null,
    ]);
    const copy = (b: Uint8Array<ArrayBuffer>) => b.slice().buffer;
    return {
      module,
      rules,
      data(kind) {
        const files: Record<string, ArrayBuffer> = {};
        sigs.forEach((bytes, i) => (files[SIGNATURES[i]] = copy(bytes)));
        if (kind === "decompile" && fid && pack) files[fid] = copy(pack);
        if (kind === "decompile" && winapi && api) files[winapi] = copy(api);
        return files;
      },
    };
  } finally {
    listener = null;
    onProgress(null);
  }
}

/** Load just the module so header inspection can choose the signature assets. */
export async function loadEngine(onProgress: (p: Progress | null) => void): Promise<WebAssembly.Module> {
  downloads.clear();
  stage = "engine";
  listener = onProgress;
  report();
  try { return await loadModule(); }
  finally { listener = null; onProgress(null); }
}

// The rules download is shared with loadAssets, and its digest is computed once per page load.
let engineId: Promise<string | null> | null = null;
export function loadEngineId(): Promise<string | null> {
  return engineId ??= download(`${base}rules.json`)
    .then(async bytes => {
      const hash = await digest(bytes.buffer);
      return hash ? `${wasmUrl}:${hash}` : null;
    })
    .catch(() => { engineId = null; return null; });
}

export async function pickNativeFamilyPack(): Promise<null> { return null; }
export async function pickNativeFamilyOverlay(): Promise<boolean> { return false; }
export async function removeNativeFamilyOverlay(_index: number): Promise<void> {}

/** "BXFAM002" or "BXFAM003" when the bytes start like a family pack header, else null. */
export function familyPackFormat(bytes: Uint8Array): string | null {
  if (bytes.byteLength < 40) return null;
  const magic = String.fromCharCode(...bytes.subarray(0, 8));
  return magic === "BXFAM002" || magic === "BXFAM003" ? magic : null;
}

export interface FamilyPackBytes {
  name: string;
  size: number;
  format: string;
  bytes: ArrayBuffer;
}

interface HeldPack { bytes: Uint8Array<ArrayBuffer>; name: string; format: string }

let defaultFamilyPack: Promise<HeldPack | null> | null = null;
let customFamilyPack: HeldPack | null = null;
let overlayFamilyPacks: HeldPack[] = [];

function hold(bytes: ArrayBuffer, name: string): HeldPack {
  const view = new Uint8Array(bytes.slice(0));
  const format = familyPackFormat(view);
  if (!format) throw new Error(`${name} is not a valid BXFAM002 or BXFAM003 family pack`);
  return { bytes: view, name, format };
}

/** Registers a user-supplied `.bxfam` pack in memory for this tab (never uploaded). It replaces the base pack. */
export function setCustomFamilyPack(bytes: ArrayBuffer, name: string): void {
  customFamilyPack = hold(bytes, name);
}

export function getFamilyPackName(): string | null {
  return customFamilyPack?.name ?? null;
}

/** Layers a user-supplied `.bxfam` pack over the base pack for this tab (never uploaded). */
export function addFamilyOverlay(bytes: ArrayBuffer, name: string): void {
  overlayFamilyPacks = [...overlayFamilyPacks, hold(bytes, name)];
}

export function removeFamilyOverlay(index: number): void {
  overlayFamilyPacks = overlayFamilyPacks.filter((_, i) => i !== index);
}

const copy = (p: HeldPack): FamilyPackBytes => ({ name: p.name, size: p.bytes.byteLength, format: p.format, bytes: p.bytes.slice().buffer });

/**
 * The packs to match against, base first: the user-loaded pack or the hosted starter pack
 * (`sigs/family.bxfam`), then the overlays. Empty when there is no base pack, so builds without a
 * pack stay quiet; missing or non-pack responses count as no pack.
 */
export async function loadFamilyPacks(): Promise<FamilyPackBytes[]> {
  // Shares `download`'s cache: the analysis usually fetched it already, with progress, in loadAssets.
  defaultFamilyPack ??= download(FAMILY_PACK)
    .then((buf) => {
      const format = familyPackFormat(buf);
      return format ? { bytes: buf, name: "Starter pack", format } : null;
    })
    .catch(() => null);
  const basePack = customFamilyPack ?? await defaultFamilyPack;
  return basePack ? [basePack, ...overlayFamilyPacks].map(copy) : [];
}

/** The base pack alone, for callers that predate layering. */
export async function loadFamilyPack(): Promise<ArrayBuffer | null> {
  return (await loadFamilyPacks())[0]?.bytes ?? null;
}
