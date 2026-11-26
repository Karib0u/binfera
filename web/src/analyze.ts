import type { Arch } from "./graph";
import type { Analysis, DecompiledFunction, FamilyReport, Packing } from "./types";
import { addFamilyOverlay, loadAssets, loadEngine, loadEngineId, loadFamilyPacks, NATIVE, pickNativeFamilyOverlay, pickNativeFamilyPack, removeFamilyOverlay, removeNativeFamilyOverlay, setCustomFamilyPack, winApiFor } from "./engine/assets";
import { summarizeCapa } from "./engine/capa";
import { EngineError, runEngine, TOO_LARGE } from "./engine/run";
import { extractStrings } from "./engine/strings";
import { createImage, type ImageMetadata } from "./engine/image";
import { digest, readResults, writeResults, forgetResults } from "./engine/resultCache";
import type { RawCodeOptions } from "./engine/engine.worker";
import { shellcodePayload } from "./engine/shellcode";

type Event =
  | { type: "start"; warnings?: string[]; functions: number[]; names?: Record<string, string>; resolved?: Record<string, string>; arch?: Arch; packed?: Packing | null }
  | { type: "settled" }
  | { type: "done"; warnings?: string[] }
  | ({ type: "function" } & DecompiledFunction);

const message = (e: unknown) => String((e as Error)?.message ?? e);
/** An emulation run, from opening the image to its JSON, as `binfera mcp` bounds it. */
const EMULATION_DEADLINE_MS = 120_000;

/**
 * iPhones and iPads (iPadOS reports itself as a Mac with a touch screen) kill a tab that holds
 * much over a gigabyte, and report a core count that says nothing about it. One capa worker alone
 * needs about that, so on these devices the engine runs one worker at a time.
 */
export const memoryConstrained = () =>
  /iPhone|iPad|iPod/.test(navigator.userAgent) || (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);

/**
 * Decompiler workers: each holds its own engine instance, so leave cores for capa and the page.
 * Every worker recovers the whole file, so its memory does not shrink with more workers: a large
 * file gets fewer of them, or several gigabytes each would add up past what the device has. A file
 * under 2 MB needs a few hundred megabytes per worker, so it can use up to six: a 1.2 MB Rust
 * program (BlackCat) spends over two minutes of engine time decompiling.
 */
function decompileWorkers(size: number) {
  if (memoryConstrained()) return 1;
  const cores = navigator.hardwareConcurrency || 4;
  const bySize = size > 16 << 20 ? 1 : size > 4 << 20 ? 2 : size > 2 << 20 ? 4 : 6;
  return Math.max(1, Math.min(bySize, cores - 2));
}

/**
 * Runs Binfera in WebAssembly workers in the browser or as a native sidecar on desktop.
 * Every result is fed into `onUpdate` as it arrives.
 */
export async function analyze(file: File, onUpdate: (a: Analysis) => void, signal: AbortSignal, raw?: RawCodeOptions, again = false) {
  const a: Analysis = {
    fileName: file.name, size: file.size, strings: [], stringsTotal: 0, image: null, entry: null, arch: null, packed: null, order: [], functions: new Map(), names: new Map(),
    capa: null, capaError: null, family: null, familyError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: null, settled: false, done: false,
  };
  let functions = new Map(a.functions), names = new Map(a.names);
  let functionsChanged = false, namesChanged = false;
  const publish = () => {
    if (functionsChanged) { functions = new Map(a.functions); functionsChanged = false; }
    if (namesChanged) { names = new Map(a.names); namesChanged = false; }
    onUpdate({ ...a, functions, names });
  };
  let pending = false;
  const flush = () => {
    if (pending) return;
    pending = true;
    setTimeout(() => { pending = false; if (!signal.aborted) publish(); }, 80);
  };

  const functionAddresses = new Set<number>();
  const settledShards = new Set<number>();
  const onLine = (line: string, shard?: number) => {
    if (!line.trim()) return;
    const e = JSON.parse(line) as Event;
    if (e.type === "start") {
      a.fileWarnings = [...new Set([...(a.fileWarnings ?? []), ...(e.warnings ?? [])])];
      // A later shard can start after another has already discovered extra callees.
      for (const address of e.functions) functionAddresses.add(address);
      a.order = [...functionAddresses].sort((x, y) => x - y);
      for (const [address, name] of Object.entries(e.names ?? {})) {
        const at = Number(address);
        if (a.names.get(at) !== name) {
          a.names.set(at, name);
          namesChanged = true;
        }
      }
      // Every shard reports the same globals.
      if (e.resolved) a.resolved = new Map(Object.entries(e.resolved).map(([address, name]) => [Number(address), name]));
      a.arch = e.arch ?? null;
      a.packed = e.packed ?? null;
    }
    else if (e.type === "settled" || e.type === "done") {
      if (shard !== undefined) {
        settledShards.add(shard);
        a.settled = settledShards.size === shards;
      }
      if (e.type === "done") a.fileWarnings = [...new Set([...(a.fileWarnings ?? []), ...(e.warnings ?? [])])];
    }
    else if (e.type === "function") {
      // A callee several shards found (one recovery never listed) arrives more than once: keep the first.
      if (a.functions.has(e.address) && !a.functions.get(e.address)?.retry_pending) return;
      a.functions.set(e.address, e);
      functionsChanged = true;
      // A callee the decompiler found that recovery never listed: make it a navigable function.
      if (!functionAddresses.has(e.address)) {
        functionAddresses.add(e.address);
        a.order = [...a.order, e.address].sort((x, y) => x - y);
      }
    }
    flush();
  };

  const input = shellcodePayload(await file.arrayBuffer(), raw?.offset);
  const bytes = input.bytes;
  const view = new Uint8Array(bytes);
  const progress = (p: Analysis["loading"]) => { a.loading = p; flush(); };
  // Forced formats change the result and are deliberately excluded, as on desktop.
  const sha256 = !NATIVE && !raw ? await digest(bytes) : null;
  if (again && sha256) await forgetResults(sha256);
  const engineId = sha256 ? await loadEngineId() : null;
  if (signal.aborted) return;
  const applyImage = (info: ImageMetadata) => {
    if (info.format === "sc32" || info.format === "sc64") {
      a.shellcode = {
        format: info.format, os: raw?.os ?? info.shellcode?.os ?? "windows", offset: raw?.offset,
        guessed: !raw, ambiguous: info.shellcode?.ambiguous ?? true, evidence: info.shellcode?.evidence ?? [],
        osDetected: !raw && !!info.shellcode?.os, encoding: input.encoding, inputSize: input.inputSize,
      };
      a.size = bytes.byteLength;
      raw = { format: a.shellcode.format, os: a.shellcode.os };
    }
    a.image = createImage(view, info);
    a.entry = info.entry;
    a.arch = info.arch;
    a.fileWarnings = info.warnings;
    ({ strings: a.strings, total: a.stringsTotal } = extractStrings(view, a.image));
    flush();
  };
  if (!NATIVE) a.retryFunction = async (address) => {
    const previous = a.functions.get(address);
    if (!previous?.retry_pending) return;
    let output = "";
    try {
      const assets = await loadAssets(a.image?.fidArch ?? null, progress, a.image?.format === "pe", winApiFor(a.image?.arch, a.image?.format));
      if (signal.aborted) return;
      await runEngine({ kind: "decompileOne", module: assets.module, sample: bytes.slice(0), data: assets.data("decompile"), address, resourceRetry: true, raw },
        (line) => { output += line + "\n"; }, signal);
      if (signal.aborted) return;
      const result = JSON.parse(output) as DecompiledFunction;
      a.functions.set(address, { ...previous, ...result, error: undefined, retry_pending: false });
    } catch (e) {
      if (signal.aborted) return;
      a.functions.set(address, { ...previous, error: message(e), retry_pending: true });
    }
    functionsChanged = true;
    flush();
  };
  a.emulate = async (address, request, callSites, runSignal) => {
    // One deadline over the engine's own: opening a large image takes a while before the run starts.
    const run = new AbortController();
    const stop = () => run.abort();
    const timer = setTimeout(stop, EMULATION_DEADLINE_MS);
    signal.addEventListener("abort", stop);
    runSignal.addEventListener("abort", stop);
    try {
      const assets = await loadAssets(null, () => {}, false, winApiFor(a.image?.arch, a.image?.format));
      if (run.signal.aborted) throw new DOMException("aborted", "AbortError");
      let output = "";
      await runEngine({ kind: "emulate", module: assets.module, sample: bytes.slice(0), data: assets.data("decompile"), address, request, callSites, raw },
        (line) => { output += line; }, run.signal);
      return output;
    } catch (e) {
      if (run.signal.aborted && !runSignal.aborted && !signal.aborted) throw new Error("Emulation took longer than two minutes and was stopped");
      throw e;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", stop);
      runSignal.removeEventListener("abort", stop);
    }
  };
  /** Matches against the packs, base first. Browser packs carry their bytes; native ones are paths the desktop side holds. */
  type PackHandle = { name: string; size: number; format?: string | null; bytes?: ArrayBuffer };
  const matchWithPacks = async (
    packs: PackHandle[],
    runSignal: AbortSignal,
    preloaded?: { module: WebAssembly.Module; data: Record<string, ArrayBuffer> },
  ) => {
    if (!packs.length) return;
    const engine = preloaded ?? await (async () => {
      const loaded = await loadAssets(null, progress, a.image?.format === "pe", null);
      return { module: loaded.module, data: loaded.data("capa") };
    })();
    if (runSignal.aborted) return;
    const buffers = packs.flatMap((p) => (p.bytes ? [p.bytes] : []));
    let json = "";
    await runEngine(
      { kind: "family", module: engine.module, sample: bytes.slice(0), data: engine.data, packs: buffers.length ? buffers : undefined, packNames: buffers.length ? packs.map((p) => p.name) : undefined, overlays: packs.length - 1 },
      (line) => { json += line; },
      runSignal,
    );
    if (runSignal.aborted) return;
    a.family = JSON.parse(json) as FamilyReport;
    a.familyPackName = packs[0].name;
    a.familyPacks = packs.map((p, i) => ({ name: p.name, size: p.size, format: p.format ?? undefined, role: i === 0 ? "base" : "overlay" }));
    a.familyError = null;
    flush();
  };
  /** Re-runs matching with the current packs; false when it failed (the error is shown). */
  const rematch = async (): Promise<boolean> => {
    a.familyError = null;
    try {
      await matchWithPacks(await loadFamilyPacks(), signal);
      return true;
    } catch (e) {
      if (signal.aborted) return false;
      a.familyError = message(e);
      flush();
      return false;
    }
  };
  if (NATIVE) {
    a.pickFamilyPack = async () => {
      if (raw || signal.aborted) return;
      const pack = await pickNativeFamilyPack();
      if (pack && !signal.aborted) await rematch();
    };
    a.addFamilyOverlay = async () => {
      if (raw || signal.aborted) return;
      if (!(await pickNativeFamilyOverlay()) || signal.aborted) return;
      // A pack the engine refuses is taken off again, so the next match still works.
      if (!(await rematch())) {
        const error = a.familyError;
        await removeNativeFamilyOverlay((a.familyPacks?.length ?? 1) - 1);
        a.familyError = error;
        flush();
      }
    };
    a.removeFamilyOverlay = async (index: number) => {
      if (raw || signal.aborted) return;
      await removeNativeFamilyOverlay(index);
      await rematch();
    };
  } else {
    a.runFamilyPack = async (packFile: File) => {
      if (raw) return;
      const packBytes = await packFile.arrayBuffer();
      if (signal.aborted) return;
      setCustomFamilyPack(packBytes, packFile.name);
      await rematch();
    };
    a.addFamilyOverlay = async (packFile?: File) => {
      if (raw || !packFile) return;
      const packBytes = await packFile.arrayBuffer();
      if (signal.aborted) return;
      addFamilyOverlay(packBytes, packFile.name);
      const index = (await loadFamilyPacks()).length - 2;
      if (!(await rematch())) {
        const error = a.familyError;
        removeFamilyOverlay(index);
        a.familyError = error;
        flush();
      }
    };
    a.removeFamilyOverlay = async (index: number) => {
      if (raw) return;
      removeFamilyOverlay(index);
      await rematch();
    };
  }
  const cached = sha256 && engineId && !again ? await readResults(sha256, engineId) : null;
  if (cached) {
    try {
      const info = JSON.parse(await cached.image.text()) as ImageMetadata;
      const capa = summarizeCapa(JSON.parse(await cached.capa.text()));
      a.ready = true;
      applyImage(info);
      const lines = (await cached.decomp.text()).split("\n");
      for (let i = 0; i < lines.length; i += 200) {
        if (signal.aborted) return;
        for (const line of lines.slice(i, i + 200)) onLine(line);
        await new Promise<void>(resolve => setTimeout(resolve, 0));
      }
      if (signal.aborted) return;
      a.capa = capa;
      a.settled = true;
      a.done = true;
      publish();
      if (!raw) {
        const packs = await loadFamilyPacks();
        if (packs.length && !signal.aborted) {
          await matchWithPacks(packs, signal).catch((e) => {
            if (!signal.aborted) { a.familyError = message(e); flush(); }
          });
        }
      }
      return;
    } catch {
      // A corrupt entry is disposable. Start from clean state before running the engine.
      if (sha256) await forgetResults(sha256);
      raw = undefined;
      a.functions.clear();
      a.names.clear();
      functionsChanged = namesChanged = true;
      a.settled = false;
      a.ready = false;
      settledShards.clear();
      functionAddresses.clear();
      a.order = [];
      a.image = null;
      a.entry = null;
      a.strings = [];
      a.stringsTotal = 0;
      a.shellcode = undefined;
      a.resolved = undefined;
      a.arch = null;
      a.packed = null;
      a.fileWarnings = undefined;
    }
  }
  const module = await loadEngine(progress);
  if (signal.aborted) return;
  let metadata = "";
  await runEngine({ kind: "inspect", module, sample: bytes.slice(0), data: {}, raw }, line => { metadata += line; }, signal);
  if (signal.aborted) return;
  const info = JSON.parse(metadata) as ImageMetadata;
  applyImage(info);

  const assets = await loadAssets(info.fidArch, progress, info.format === "pe", winApiFor(info.arch, info.format), !raw);
  if (signal.aborted) return;
  a.ready = true;
  flush();

  // A file too large for the engine's memory limit is refused. The capability worker has the lower
  // limit, so its refusal leaves the decompiler running; once a decompiler worker refuses, every
  // worker would fail the same way, so all of them are stopped to give the memory back.
  const stop = new AbortController();
  const stopAll = () => stop.abort();
  signal.addEventListener("abort", stopAll);
  const failed = (e: unknown, set: (m: string) => void, everything: boolean) => {
    if (signal.aborted) return;
    if (e instanceof EngineError && e.code === TOO_LARGE) {
      const refusal = e.message.replace(/^error: /, "");
      if (everything) { a.tooLarge ??= refusal; stop.abort(); } else a.capaTooLarge = refusal;
    } else if (!stop.signal.aborted) set(message(e));
    flush();
  };

  let capaJson: string | null = null;
  const decompLines: string[] = [];
  let decompComplete = false;
  const capa = () => (async () => {
    let json = "";
    await runEngine(
      { kind: "capa", module: assets.module, sample: bytes.slice(0), data: assets.data("capa"), rules: assets.rules, raw },
      (l) => (json += l), stop.signal,
    );
    a.capa = summarizeCapa(JSON.parse(json), raw ? 0 : undefined);
    if (!stop.signal.aborted) capaJson = json;
    flush();
  })().catch((e) => failed(e, (m) => (a.capaError = m), false));

  // Natively one run does the sharding itself (`--jobs`), so it is a single request here.
  const shards = NATIVE || raw ? 1 : decompileWorkers(bytes.byteLength);
  const decompile = () => Promise.all(
    Array.from({ length: shards }, (_, i) =>
      runEngine(
        { kind: "decompile", module: assets.module, sample: bytes.slice(0), data: assets.data("decompile"), shard: [i, shards], raw },
        line => { onLine(line, i); if (sha256 && engineId) decompLines.push(line); }, stop.signal,
      ),
    ),
  ).then(() => { decompComplete = !stop.signal.aborted; }).catch((e) => failed(e, (m) => (a.decompileError = m), true));

  const familyMatch = () => (async () => {
    if (raw) return;
    const packs = await loadFamilyPacks();
    if (!packs.length || stop.signal.aborted) return;
    await matchWithPacks(packs, stop.signal, { module: assets.module, data: assets.data("capa") });
  })().catch((e) => failed(e, (m) => (a.familyError = m), false));

  // Decompiled functions are what the page shows first, so on a constrained device they go
  // first and capa follows once their memory is released; elsewhere all run at once.
  if (memoryConstrained()) { await decompile(); await familyMatch(); await capa(); } else await Promise.all([familyMatch(), capa(), decompile()]);
  signal.removeEventListener("abort", stopAll);
  if (signal.aborted) return;
  if (sha256 && engineId && !raw && capaJson !== null && decompComplete && !stop.signal.aborted) {
    await writeResults(sha256, engineId, {
      image: new Blob([metadata]), capa: new Blob([capaJson]), decomp: new Blob(decompLines.map(line => line + "\n")),
    });
  }
  if (signal.aborted) return;
  a.done = true;
  publish();
}
