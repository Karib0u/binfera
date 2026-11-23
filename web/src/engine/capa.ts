import type { CapaResult } from "../types";

type MatchAddress = { type: string; value?: unknown };
type MatchTree = {
  success: boolean;
  node: { type: string; feature?: { type: string }; statement?: { type: string } };
  locations: MatchAddress[];
  children: MatchTree[];
};

const addr = (a: MatchAddress | null | undefined): number | null =>
  a?.type === "absolute" && typeof a.value === "number" ? a.value : null;

function collectEvidence(match: MatchTree, delta: number, addresses: Set<number>) {
  if (!match.success) return;
  // Rule references carry scope addresses. Their child matches carry the feature locations.
  const { node } = match;
  if ((node.type === "feature" && node.feature?.type !== "match") || node.statement?.type === "range") {
    for (const location of match.locations) {
      const at = addr(location);
      if (at !== null) addresses.add(at - delta);
    }
  }
  for (const child of match.children) collectEvidence(child, delta, addresses);
}

/* eslint-disable @typescript-eslint/no-explicit-any */
/** Reduces binfera's `--json` document to what the UI shows. */
export function summarizeCapa(doc: any, imageBase?: number): CapaResult {
  // Raw capability recovery uses its compatibility base; the native decompiler uses offset zero.
  const base = addr(doc.meta.analysis.base_address);
  const delta = imageBase === undefined ? 0 : (base ?? 0) - imageBase;
  const rules = Object.values<any>(doc.rules).map((r) => {
    const m = r.meta;
    const scope = m.scopes?.static ?? Object.values<string>(m.scopes ?? {})[0] ?? "file";
    const addresses: number[] = [];
    const evidence = new Map<number, number[]>();
    for (const [address, match] of r.matches as [MatchAddress, MatchTree][]) {
      const at = addr(address);
      if (at === null) continue;
      const site = at - delta;
      addresses.push(site);
      if (scope === "file") continue;
      const found = new Set(evidence.get(site));
      collectEvidence(match, delta, found);
      if (found.size) evidence.set(site, [...found]);
    }
    return {
      name: m.name, namespace: m.namespace ?? null, scope, lib: !!m.lib,
      attack: (m.attack ?? []).map((a: any) => ({ id: a.id, tactic: a.tactic, technique: a.technique, subtechnique: a.subtechnique })),
      mbc: (m.mbc ?? []).map((b: any) => ({ id: b.id, objective: b.objective, behavior: b.behavior, method: b.method })),
      description: m.description ?? "", count: r.matches.length, addresses, evidence,
    };
  });
  const a = doc.meta.analysis;
  return {
    sample: { md5: doc.meta.sample.md5, sha256: doc.meta.sample.sha256 },
    format: a.format, arch: a.arch, os: a.os, baseAddress: base === null ? null : base - delta,
    rules,
    library: (a.library_functions ?? []).map((f: any) => addr(f.address)).filter((x: number | null): x is number => x !== null).map((x: number) => x - delta),
  };
}
