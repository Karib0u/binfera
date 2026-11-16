import { useMemo } from "react";
import type { Analysis } from "../types";
import { unescapeLiteral } from "../highlight";
import { rowFlow, ADDR_IN_ASM, asmAddress } from "../graph";

export function useReferences(a: Analysis) {
  const image = a.image;
  const functionAddresses = useMemo(() => new Set(a.order), [a.order]);
  const byName = useMemo(() => {
    const m = new Map<string, number>();
    for (const ad of a.order) {
      m.set("FUN_" + ad.toString(16).padStart(8, "0"), ad);
      const n = a.functions.get(ad)?.name ?? a.names.get(ad);
      if (n) m.set(n, ad);
    }
    return m;
  }, [a.order, a.functions, a.names]);
  const resolve = (tok: string) => {
    const hit = byName.get(tok);
    if (hit !== undefined) return hit;
    if (!/^0x[0-9a-f]+$/i.test(tok)) return undefined;
    const address = parseInt(tok, 16);
    return functionAddresses.has(address) ? address : undefined;
  };
  // Calls come from the instruction listing: direct calls, and jumps to another function's entry
  // (tail calls). A name in the pseudocode can be a function pointer passed as data, so it is not one.
  const { callees, callers } = useMemo(() => {
    const callees = new Map<number, number[]>(), callers = new Map<number, number[]>();
    if (!a.settled) return { callees, callers };
    for (const [ad, f] of a.functions) {
      if (!f.asm) continue;
      const out = new Set<number>();
      if (f.calls) for (const target of f.calls) {
        if (target !== ad && functionAddresses.has(target)) out.add(target);
      }
      for (const row of f.calls ? [] : f.asm) {
        const { kind, target } = rowFlow(row, a.arch);
        if ((kind === "call" || kind === "jump") && target !== undefined && target !== ad && functionAddresses.has(target)) out.add(target);
      }
      callees.set(ad, [...out].sort((x, y) => x - y));
      for (const c of out) callers.set(c, [...(callers.get(c) ?? []), ad]);
    }
    return { callees, callers };
  }, [a.settled, a.functions, functionAddresses, a.arch]);

  // Recovery references give instruction addresses; printed literals and global labels also
  // expose strings resolved by the decompiler beyond the recovery graph.
  const { strRefs, fnStrings } = useMemo(() => {
    const strRefs = new Map<number, number[]>(), fnStrings = new Map<number, number[]>();
    if (!a.settled) return { strRefs, fnStrings };
    const known = new Set(a.strings.map((x) => x.a));
    const byText = new Map<string, number[]>();
    for (const x of a.strings) byText.set(x.s, [...(byText.get(x.s) ?? []), x.a]);
    for (const [ad, f] of a.functions) {
      if (!f.text) continue;
      const hits = new Set<number>();
      if (f.data_refs) {
        for (const ref of f.data_refs) if (known.has(ref.to)) hits.add(ref.to);
      }
      // The decompiler often prints a string inline (L"...") instead of naming its address.
      for (const lit of (f.text.match(/L?"(?:\\.|[^"\\\n])*"/g) ?? [])) for (const v of byText.get(unescapeLiteral(lit)) ?? []) hits.add(v);
      for (const t of (f.text.match(/\b0x[0-9a-fA-F]{5,16}\b|\b[A-Za-z_]\w*_[0-9a-fA-F]{6,16}\b/g) ?? [])) {
        const v = parseInt(t.startsWith("0x") ? t : t.slice(t.lastIndexOf("_") + 1), 16);
        if (known.has(v)) hits.add(v);
      }
      if (!hits.size) continue;
      fnStrings.set(ad, [...hits].sort((x, y) => x - y));
      for (const h of hits) strRefs.set(h, [...(strRefs.get(h) ?? []), ad]);
    }
    return { strRefs, fnStrings };
  }, [a.settled, a.functions, a.strings]);
  const strByAddr = useMemo(() => new Map(a.strings.map((x) => [x.a, x])), [a.strings]);
  // Callers of each import: the functions whose decompiled text names it.
  const importRefs = useMemo(() => {
    const m = new Map<string, number[]>();
    if (!a.settled || !image?.imports.length) return m;
    const names = new Set(image.imports.map((i) => i.name));
    const bySlot = new Map(image.imports.filter((i) => i.va).map((i) => [i.va, i.name]));
    for (const [ad, f] of a.functions) {
      const hit = new Set<string>();
      for (const ref of f.data_refs ?? []) { const name = bySlot.get(ref.to); if (name) hit.add(name); }
      for (const t of f.text?.match(/[A-Za-z_][\w$@?]*/g) ?? []) {
        if (names.has(t)) hit.add(t);
        else { const bare = t.replace(/^[A-Za-z0-9]+_/, ""); if (bare !== t && names.has(bare)) hit.add(bare); } // the decompiler writes kernel32_SetLastError
      }
      // Calls go through the import's pointer slot: its address shows in the listing and in the data labels.
      for (const [, , text] of f.asm ?? []) for (const m2 of text.matchAll(ADDR_IN_ASM)) { const n = bySlot.get(asmAddress(m2)); if (n) hit.add(n); }
      for (const t of f.text?.match(/_[0-9a-fA-F]{6,16}\b/g) ?? []) { const n = bySlot.get(parseInt(t.slice(1), 16)); if (n) hit.add(n); }
      for (const n of hit) m.set(n, [...(m.get(n) ?? []), ad]);
    }
    return m;
  }, [a.settled, a.functions, image]);
  // Use recovery references first, supplementing them with globals resolved in decompiled C.
  // Listings without structured references retain the operand-text fallback.
  const xrefs = useMemo(() => {
    const m = new Map<number, { fn: number; at: number }[]>();
    if (!a.settled || !image) return m;
    const add = (to: number, fn: number, at: number) => {
      const l = m.get(to);
      if (!l) m.set(to, [{ fn, at }]);
      else if (!l.some((x) => x.fn === fn && x.at === at)) l.push({ fn, at });
    };
    for (const [fn, f] of a.functions) {
      const own = new Set((f.asm ?? []).map((r) => r[0]));
      const seen = new Set<number>();
      if (f.data_refs) {
        for (const ref of f.data_refs) {
          if (own.has(ref.to) || image.vaToOff(ref.to) === null) continue;
          seen.add(ref.to);
          add(ref.to, fn, ref.from);
        }
      }
      for (const [at, , text] of f.data_refs ? [] : f.asm ?? []) {
        for (const mm of text.matchAll(ADDR_IN_ASM)) {
          const v = asmAddress(mm);
          if (own.has(v) || image.vaToOff(v) === null) continue;
          seen.add(v);
          add(v, fn, at);
        }
      }
      for (const t of f.text?.match(/\b0x[0-9a-fA-F]{5,16}\b|\b[A-Za-z_]\w*_[0-9a-fA-F]{6,16}\b/g) ?? []) {
        const v = parseInt(t.startsWith("0x") ? t : t.slice(t.lastIndexOf("_") + 1), 16);
        if (!seen.has(v) && !Number.isNaN(v) && image.vaToOff(v) !== null && !own.has(v)) { seen.add(v); add(v, fn, -1); }
      }
    }
    // Strings the decompiler printed inline carry no address in the text; the string lookup found them.
    for (const [v, fns] of strRefs) for (const fn of fns) add(v, fn, -1);
    return m;
  }, [a.settled, a.functions, image, strRefs]);
  // The decompiled text and listings in lower case, for the search box.
  const codeIndex = useMemo(() => {
    if (!a.settled) return [];
    return [...a.functions].map(([ad, f]) => ({ ad, f, c: (f.text ?? "").toLowerCase() }));
  }, [a.settled, a.functions]);
  return { functionAddresses, resolve, callers, callees, strRefs, fnStrings, strByAddr, importRefs, xrefs, codeIndex };
}
