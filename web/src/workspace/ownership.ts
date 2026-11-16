import { useMemo } from "react";
import type { Analysis, CapaRule } from "../types";
/** The nearest function start at or before `addr`: only a guess while the listings are still arriving. */
function preceding(order: number[], addr: number) {
  let lo = 0, hi = order.length - 1, r = -1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (order[mid] <= addr) { r = mid; lo = mid + 1; } else hi = mid - 1; }
  return r < 0 ? null : order[r];
}

/** Once decompilation is done: every instruction address, with the functions whose listing contains it. */
export function useContainment(a: Analysis) {
  return useMemo(() => {
    const owners = new Map<number, number[]>();
    if (!a.settled) return null;
    for (const [ad, f] of a.functions) for (const [at] of f.asm ?? []) owners.set(at, [...(owners.get(at) ?? []), ad]);
    return owners;
  }, [a.settled, a.functions]);
}

/** The functions an address belongs to: exact once the listings are in, the preceding start until then. */
export function ownersOf(a: Analysis, containment: Map<number, number[]> | null, addr: number): number[] {
  if (containment) return containment.get(addr) ?? (a.functions.has(addr) ? [addr] : []);
  const o = preceding(a.order, addr);
  return o === null ? [] : [o];
}

/** Maps every function-or-smaller rule match onto the functions containing it. A match no decompiled
 *  function contains (capa's own recovery found code the decompiler did not) stays at file level. */
export function useFunctionRules(a: Analysis, containment: Map<number, number[]> | null) {
  return useMemo(() => {
    const byFn = new Map<number, CapaRule[]>();
    const fileLevel: CapaRule[] = [];
    for (const rule of a.capa?.rules ?? []) {
      if (rule.lib) continue;
      const owners = new Set<number>();
      if (rule.scope !== "file") for (const ad of rule.addresses) for (const o of ownersOf(a, containment, ad)) owners.add(o);
      if (!owners.size) { fileLevel.push(rule); continue; }
      for (const o of owners) byFn.set(o, [...(byFn.get(o) ?? []), rule]);
    }
    return { byFn, fileLevel };
  }, [a.order, a.capa, containment]);
}
