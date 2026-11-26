import type { Analysis } from "./types";

type Progressed = Pick<Analysis, "ready" | "loading" | "image" | "capa" | "capaError" | "capaTooLarge" | "family" | "familyError">;

/** Shares of the bar: the engine download, then signatures, rules and packs (about 20 MB and 48 MB). */
const START = 0.02, ENGINE = 0.2, READ = 0.22, ASSETS = 0.65;

/**
 * How far one analysis is, 0 to 1. In the browser the downloads take the first 65%: the engine,
 * reading the file, then signatures, rules and packs. The work (decompiling, with capability and
 * code-origin matching beside it) takes the rest, or all of it on desktop, which downloads nothing.
 * Each stage owns a fixed share, so finishing one never sends the bar back to the start.
 */
export function overallProgress(a: Progressed, decompiled: number, native: boolean): number {
  const work = 0.85 * decompiled + (a.capa || a.capaError || a.capaTooLarge ? 0.1 : 0) + (a.family || a.familyError ? 0.05 : 0);
  if (native) return work;
  if (!a.ready) {
    const f = a.loading?.fraction ?? 0;
    if (a.loading?.stage === "data") return READ + (ASSETS - READ) * f;
    if (a.loading) return START + (ENGINE - START) * f;
    return a.image ? READ : START;
  }
  return ASSETS + (1 - ASSETS) * work;
}

/** The download step on its own, 0 to 1: the engine is about 30% of the bytes. Null while unknown. */
export function downloadProgress(a: Progressed): number | null {
  const f = a.loading?.fraction;
  if (a.loading?.stage === "data") return 0.3 + 0.7 * (f ?? 0);
  if (a.loading) return f == null ? null : 0.3 * f;
  return a.image ? 0.3 : null;
}
