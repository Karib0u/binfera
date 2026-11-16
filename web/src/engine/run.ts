import type { EngineMessage, EngineRequest } from "./engine.worker";

/** binfera's exit status when code recovery refused the file as too large for its memory limit. */
export const TOO_LARGE = 14;

/** A failed run; `code` is binfera's exit status when it exited rather than crashed. */
export class EngineError extends Error {
  constructor(message: string, readonly code?: number) { super(message); }
}

/**
 * Runs one WebAssembly binfera invocation in its own worker (a fresh module per run, so its memory
 * is returned afterwards) and calls `onLine` for each stdout line as it is printed.
 */
export function runEngine(req: EngineRequest, onLine: (line: string) => void, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./engine.worker.ts", import.meta.url), { type: "module" });
    const finish = (fn: () => void) => { signal.removeEventListener("abort", onAbort); worker.terminate(); fn(); };
    const onAbort = () => finish(() => reject(new DOMException("aborted", "AbortError")));
    if (signal.aborted) return onAbort();
    signal.addEventListener("abort", onAbort);
    worker.onmessage = (ev: MessageEvent<EngineMessage>) => {
      const m = ev.data;
      if (m.type === "line") onLine(m.line);
      else if (m.type === "done") finish(resolve);
      else finish(() => reject(new EngineError(m.message, m.code)));
    };
    worker.onerror = (ev) => finish(() => reject(new Error(ev.message || "worker failed")));
    worker.postMessage(req, [req.sample, ...Object.values(req.data)]);
  });
}
