// Desktop build's stand-in for run.ts: the same `runEngine`, backed by the native binfera binary
// through the Tauri commands in src-tauri/src/engine.rs instead of a WebAssembly worker.
import { Channel, invoke } from "@tauri-apps/api/core";
import type { EngineRequest } from "./engine.worker";
import { emulateArgs } from "./emulate";

/** binfera's exit status when code recovery refused the file as too large for its memory limit. */
export const TOO_LARGE = 14;

/** A failed run; `code` is binfera's exit status when it exited rather than crashed. */
export class EngineError extends Error {
  constructor(message: string, readonly code?: number) { super(message); }
}

interface Outcome { code: number | null; stderr: string; lines: number }
interface Plan { args: string[]; files?: Record<string, string>; sample: boolean; stdin?: string }

/**
 * The browser build's argument lists, minus its workarounds: no `--jobs 1` (the engine may use
 * every core), no `--max-instructions` (the native engine is not capped by a 4 GB address space)
 * and no sharding across workers (one `--jobs N` run prepares code recovery once and keeps
 * persistent worker processes busy). `{sample}` and `{rules}` become paths on the native side.
 */
function plan(req: EngineRequest): Plan {
  switch (req.kind) {
    case "inspect": return { sample: true, args: ["{sample}", "--image-info", "--guess-shellcode"] };
    case "capa": return { sample: true, args: ["{sample}", "--json", "--rules", "{rules}"] };
    // Overlay packs are named by index: the native side holds the paths, the webview never sees them.
    case "family": return { sample: true, args: ["family", "match", "--pack", "{family_pack}", ...Array.from({ length: req.overlays ?? 0 }, (_, i) => ["--pack", `{family_overlay:${i}}`]).flat(), "{sample}", "--json"] };
    case "fingerprint": return { sample: true, args: ["fingerprint", "{sample}"] };
    case "decompileOne": return { sample: true, args: ["{sample}", "--decompile-function", `0x${req.address.toString(16)}`, "--json", ...(req.resourceRetry ? ["--resource-retry"] : [])] };
    case "decompile": {
      const jobs = Math.max(1, navigator.hardwareConcurrency || 4);
      return { sample: true, args: ["{sample}", "--decompile-all", "--jobs", String(jobs)] };
    }
    // The text files live in the run's working directory, so their `/name` becomes `name`.
    case "emulate": return { sample: true, args: emulateArgs("{sample}", req.address, req.callSites), stdin: req.request };
    case "diff": return { sample: false, files: req.files, args: ["diff", ...req.args.map((a) => (a.startsWith("/") ? a.slice(1) : a))] };
  }
}

let nextRun = 1;

/** Runs one native binfera invocation and calls `onLine` for each stdout line as it is printed. */
export async function runEngine(req: EngineRequest, onLine: (line: string) => void, signal: AbortSignal): Promise<void> {
  const abort = () => new DOMException("aborted", "AbortError");
  if (signal.aborted) throw abort();
  const { args, files, sample, stdin } = plan(req);
  if (req.raw) args.push("--format", req.raw.format, "--os", req.raw.os);
  const id = nextRun++;
  let staged: number | null = null;
  const cancel = () => { void invoke("cancel_engine", { id }); };
  signal.addEventListener("abort", cancel);
  try {
    if (sample) {
      staged = await invoke<number>("stage_sample", new Uint8Array(req.sample));
      if (signal.aborted) throw abort();
    }
    const channel = new Channel<string>();
    // The channel delivers in order, but only the run's own lines matter once it was cancelled.
    // It does not deliver before the command returns, though: a stored run is replayed in an
    // instant, so its last lines can still be on their way when the outcome arrives.
    let received = 0;
    let wake: (() => void) | null = null;
    let expected = Infinity;
    channel.onmessage = (line) => {
      received++;
      if (!signal.aborted) onLine(line);
      if (received >= expected) wake?.();
    };
    let outcome: Outcome;
    try {
      outcome = await invoke<Outcome>("run_engine", { request: { id, sample: staged, args, files: files ?? {}, stdin }, onLine: channel });
    } catch (e) {
      if (signal.aborted) throw abort();
      throw new EngineError(String(e));
    }
    if (signal.aborted) throw abort();
    expected = outcome.lines;
    if (received < expected) {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new EngineError(`the engine's output was cut short (${received} of ${expected} lines arrived)`)), 60_000);
        const done = () => { clearTimeout(timer); signal.removeEventListener("abort", done); resolve(); };
        wake = done;
        signal.addEventListener("abort", done);
      });
      if (signal.aborted) throw abort();
    }
    // `diff` exits 1 to say the files differ, which is an answer rather than a failure.
    if (outcome.code !== 0 && !(req.kind === "diff" && outcome.code === 1)) {
      throw new EngineError(outcome.stderr.trim() || `binfera exited with status ${outcome.code ?? "unknown (killed)"}`, outcome.code ?? undefined);
    }
  } finally {
    signal.removeEventListener("abort", cancel);
    if (staged !== null) void invoke("release_sample", { id: staged });
  }
}
