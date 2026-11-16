import type { CapaResult } from "../types";

/* eslint-disable @typescript-eslint/no-explicit-any */
const addr = (a: any): number | null => (a && a.type === "absolute" ? a.value : null);

/** Reduces binfera's `--json` document to what the UI shows. */
export function summarizeCapa(doc: any, imageBase?: number): CapaResult {
  // Raw capability recovery uses its compatibility base; the native decompiler uses offset zero.
  const base = addr(doc.meta.analysis.base_address);
  const delta = imageBase === undefined ? 0 : (base ?? 0) - imageBase;
  const rules = Object.values<any>(doc.rules).map((r) => {
    const m = r.meta;
    const scope = m.scopes?.static ?? Object.values<string>(m.scopes ?? {})[0] ?? "file";
    const addresses = (r.matches as any[]).map(([a]) => addr(a)).filter((a): a is number => a !== null).map(a => a - delta);
    return {
      name: m.name, namespace: m.namespace ?? null, scope, lib: !!m.lib,
      attack: (m.attack ?? []).map((a: any) => ({ id: a.id, tactic: a.tactic, technique: a.technique, subtechnique: a.subtechnique })),
      mbc: (m.mbc ?? []).map((b: any) => ({ id: b.id, objective: b.objective, behavior: b.behavior, method: b.method })),
      description: m.description ?? "", count: r.matches.length, addresses,
    };
  });
  const a = doc.meta.analysis;
  return {
    sample: { md5: doc.meta.sample.md5, sha256: doc.meta.sample.sha256 },
    format: a.format, arch: a.arch, os: a.os, baseAddress: base === null ? null : base - delta,
    rules,
  };
}
