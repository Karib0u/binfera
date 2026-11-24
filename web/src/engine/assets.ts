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
export interface Progress { label: string; fraction: number | null }

const base = import.meta.env.BASE_URL;
const SIGNATURES = ["1_flare_msvc_rtf_32_64.sig", "2_flare_msvc_atlmfc_32_64.sig", "3_flare_common_libs.sig"];

interface Download { loaded: number; total: number | null }
const downloads = new Map<string, Download>();
const cache = new Map<string, Promise<Uint8Array<ArrayBuffer>>>();
let listener: ((p: Progress) => void) | null = null;

function report() {
  if (!listener) return;
  if (!downloads.size) return listener({ label: "Starting analysis engine", fraction: null });
  let loaded = 0, total = 0, known = true;
  for (const d of downloads.values()) {
    loaded += d.loaded;
    if (d.total === null) known = false; else total += d.total;
  }
  const mb = (n: number) => (n / 1048576).toFixed(0);
  listener({
    label: known && total ? `Downloading analysis engine · ${mb(loaded)} / ${mb(total)} MB` : `Downloading analysis engine · ${mb(loaded)} MB`,
    fraction: known && total ? Math.min(1, loaded / total) : null,
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

export async function loadAssets(arch: Arch, onProgress: (p: Progress | null) => void, signatures = true, winApi: WinApi = null): Promise<Assets> {
  downloads.clear();
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

const FAMILY_MAGIC = [0x42, 0x58, 0x46, 0x41, 0x4d, 0x30, 0x30, 0x32]; // "BXFAM002"
function isBxfam002(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 40) return false;
  for (let i = 0; i < FAMILY_MAGIC.length; i++) if (bytes[i] !== FAMILY_MAGIC[i]) return false;
  return true;
}

let defaultFamilyPack: Promise<Uint8Array<ArrayBuffer> | null> | null = null;
let customFamilyPack: { bytes: Uint8Array<ArrayBuffer>; name: string } | null = null;

/** Registers a user-supplied `.bxfam` pack in memory for this tab (never uploaded). */
export function setCustomFamilyPack(bytes: ArrayBuffer, name: string): void {
  const view = new Uint8Array(bytes.slice(0));
  if (!isBxfam002(view)) throw new Error(`${name} is not a valid BXFAM002 family pack`);
  customFamilyPack = { bytes: view, name };
}

export function getFamilyPackName(): string | null {
  return customFamilyPack?.name ?? null;
}

/**
 * Optionally fetches the hosted starter pack (`sigs/family.bxfam`) or returns the user-loaded pack.
 * Missing or non-pack responses return `null` cleanly so builds without a pack stay quiet.
 */
export async function loadFamilyPack(): Promise<ArrayBuffer | null> {
  if (customFamilyPack) return customFamilyPack.bytes.slice().buffer;
  defaultFamilyPack ??= fetch(`${base}sigs/family.bxfam`)
    .then(async (res) => {
      if (!res.ok) return null;
      const buf = new Uint8Array(await res.arrayBuffer());
      return isBxfam002(buf) ? buf : null;
    })
    .catch(() => null);
  const bytes = await defaultFamilyPack;
  return bytes ? bytes.slice().buffer : null;
}
