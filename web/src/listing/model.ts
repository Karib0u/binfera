import { mappedOffset, type ImageMetadata, type StructField, type Structure } from "../engine/image";
import type { AsmRow, StringEntry } from "../types";

export type ListingFunctions = ReadonlyMap<number, { asm?: AsmRow[]; labels?: Record<string, string> }>;
export type ListingImage = Pick<ImageMetadata, "regions" | "sections" | "imports" | "ptrSize"> & { structures?: Structure[] };

export interface PackedFunction {
  /** Alternating instruction addresses and byte lengths. */
  rows: Float64Array;
  labels?: Record<string, string>;
}

export interface BuildRequest {
  image?: ListingImage;
  strings?: StringEntry[];
  changes: [number, PackedFunction | null][];
}

export type Atom =
  | { kind: "sec"; va: number; lines: number; name: string; end: number; perms: string; entropy?: number }
  | { kind: "fn"; va: number; lines: number; fn: number }
  | { kind: "code"; va: number; lines: number; fn: number; row: number }
  | { kind: "str"; va: number; lines: number; text: string; w: boolean; len: number }
  | { kind: "imp"; va: number; lines: number; name: string; dll: string }
  | { kind: "gap"; va: number; lines: number; len: number; off: number }
  | { kind: "struct"; va: number; lines: number; name: string; len: number; off: number }
  | { kind: "field"; va: number; lines: number; field: StructField };

export interface ListingIndex {
  atoms: Atom[];
  starts: Uint32Array<ArrayBuffer>;
  total: number;
  labels: Record<string, string>;
  ranges: { start: number; end: number; maxEnd: number; fn: number }[];
}

export interface ListingModel extends ListingIndex {
  functions: ListingFunctions;
}

export function packRows(asm: AsmRow[], rows: Float64Array) {
  for (let i = 0; i < asm.length; i++) {
    const [at, bytes] = asm[i];
    rows[2 * i] = at;
    rows[2 * i + 1] = Math.max(1, (/\s/.test(bytes) ? bytes.replace(/\s/g, "").length : bytes.length) / 2);
  }
}

/** First index after a prefix of matching elements. */
export function endOfPrefix(length: number, before: (i: number) => boolean): number {
  let lo = 0, hi = length;
  while (lo < hi) {
    const mid = lo + Math.floor((hi - lo) / 2);
    if (before(mid)) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Index the mapped file in address order, grouping runs of instructions from the same function. */
export function buildIndex(image: ListingImage, strings: StringEntry[], functions: ReadonlyMap<number, PackedFunction>): ListingIndex {
  const insns: { at: number; size: number; fn: number; row: number }[] = [];
  const heads = new Map<number, number>();
  const labels: Record<string, string> = {};
  const ranges: ListingIndex["ranges"] = [];
  for (const [fn, { rows, labels: fnLabels }] of functions) {
    if (!rows.length) continue;
    heads.set(rows[0], fn);
    Object.assign(labels, fnLabels);
    let start = Infinity, end = -Infinity;
    for (let i = 0; i < rows.length; i += 2) {
      const at = rows[i];
      start = Math.min(start, at);
      end = Math.max(end, at);
      insns.push({ at, size: rows[i + 1], fn, row: i / 2 });
    }
    ranges.push({ start, end, maxEnd: end, fn });
  }
  insns.sort((x, y) => x.at - y.at);
  ranges.sort((x, y) => x.start - y.start);
  for (let i = 1; i < ranges.length; i++) ranges[i].maxEnd = Math.max(ranges[i - 1].maxEnd, ranges[i].end);
  const strs = [...strings].sort((x, y) => x.a - y.a);
  const imps = image.imports.filter((i) => i.va).sort((x, y) => x.va - y.va);
  const atoms: Atom[] = [];
  const fields = (image.structures ?? []).flatMap((s) => s.va === undefined ? [] : s.fields.map((f, n) => ({ va: s.va! + f.off - s.off, f, head: n === 0 ? s : undefined }))).sort((x, y) => x.va - y.va);
  const spanOf = (s: { va: number; size: number; vsize: number }) => s.va + Math.min(s.size, Math.max(s.vsize, 1));
  const mapped = image.sections.filter((s) => s.size > 0 && mappedOffset(image.regions, s.va) !== null).sort((x, y) => x.va - y.va);
  // Headers outside every section (usually Mach-O) get a section of their own.
  const headerSpans: { name: string; va: number; size: number; vsize: number; perms: string; entropy?: number }[] = [];
  for (const { va, f } of fields) {
    if (mapped.some((s) => va >= s.va && va < spanOf(s))) continue;
    const last = headerSpans[headerSpans.length - 1], stop = va + f.size;
    if (last && va <= last.va + last.size + 0x1000) { last.size = Math.max(last.size, stop - last.va); last.vsize = last.size; }
    else headerSpans.push({ name: "file headers", va, size: f.size, vsize: f.size, perms: "r--" });
  }
  const secs = [...mapped, ...headerSpans].sort((x, y) => x.va - y.va);
  secs.forEach((s, n) => {
    const next = secs[n + 1];
    if (headerSpans.includes(s) && next && s.va + s.size > next.va) { s.size = next.va - s.va; s.vsize = s.size; }
  });
  for (const s of secs) {
    const end = spanOf(s);
    atoms.push({ kind: "sec", va: s.va, lines: 2, name: s.name, end, perms: s.perms, entropy: s.entropy });
    let pos = s.va;
    let i = endOfPrefix(insns.length, (n) => insns[n].at < s.va);
    let j = endOfPrefix(strs.length, (n) => strs[n].a < s.va);
    let k = endOfPrefix(imps.length, (n) => imps[n].va < s.va);
    let m = endOfPrefix(fields.length, (n) => fields[n].va < s.va);
    const gap = (to: number) => {
      if (to > pos) atoms.push({ kind: "gap", va: pos, lines: Math.ceil((to - pos) / 16), len: to - pos, off: mappedOffset(image.regions, pos) ?? 0 });
    };
    while (pos < end) {
      const ni = i < insns.length && insns[i].at < end ? insns[i].at : Infinity;
      const nj = j < strs.length && strs[j].a < end ? strs[j].a : Infinity;
      const nk = k < imps.length && imps[k].va < end ? imps[k].va : Infinity;
      const nf = m < fields.length && fields[m].va < end ? fields[m].va : Infinity;
      const next = Math.min(ni, nj, nk, nf);
      if (next === Infinity) break;
      if (next < pos) { if (nf === next) m++; else if (ni === next) i++; else if (nj === next) j++; else k++; continue; }
      // A header's named fields beat text that merely looks like a string across them.
      if (nj === next && nf !== next && nf < strs[j].a + Math.max(strs[j].s.length, 1)) { j++; continue; }
      gap(next);
      if (nf === next) {
        const { va, f, head } = fields[m++];
        if (head) atoms.push({ kind: "struct", va, lines: 1, name: head.name, len: head.size, off: head.off });
        atoms.push({ kind: "field", va, lines: 1, field: f });
        pos = va + f.size;
      } else if (ni === next) {
        const { at, size, fn, row } = insns[i++];
        const head = heads.get(at);
        if (head !== undefined) atoms.push({ kind: "fn", va: at, lines: 2, fn: head });
        const last = atoms[atoms.length - 1];
        if (last.kind === "code" && last.fn === fn && last.row + last.lines === row) last.lines++;
        else atoms.push({ kind: "code", va: at, lines: 1, fn, row });
        pos = at + size;
      } else if (nj === next) {
        const x = strs[j++];
        const len = Math.min(end - x.a, (x.s.length + 1) * (x.w ? 2 : 1));
        atoms.push({ kind: "str", va: x.a, lines: 1, text: x.s, w: x.w, len });
        pos = x.a + len;
      } else {
        const x = imps[k++];
        atoms.push({ kind: "imp", va: x.va, lines: 1, name: x.name, dll: x.dll });
        pos = x.va + image.ptrSize;
      }
    }
    gap(end);
  }
  const starts = new Uint32Array(atoms.length + 1);
  for (let i = 0; i < atoms.length; i++) starts[i + 1] = starts[i] + atoms[i].lines;
  return { atoms, starts, total: starts[atoms.length], labels, ranges };
}

export function atomAtLine(model: ListingModel, line: number): number {
  return endOfPrefix(model.atoms.length, (i) => model.starts[i] <= line) - 1;
}

export function instructionAt(model: ListingModel, atom: Extract<Atom, { kind: "code" }>, offset: number): AsmRow {
  return model.functions.get(atom.fn)!.asm![atom.row + offset];
}

export function addressAtLine(model: ListingModel, line: number): number | null {
  if (line < 0 || line >= model.total) return null;
  const n = atomAtLine(model, line);
  const at = model.atoms[n], offset = line - model.starts[n];
  if (at.kind === "code") return instructionAt(model, at, offset)[0];
  if (at.kind === "gap") return at.va + offset * 16;
  return at.va;
}

export function lineOf(model: ListingModel, va: number): number | null {
  const n = endOfPrefix(model.atoms.length, (i) => model.atoms[i].va <= va) - 1;
  if (n < 0) return null;
  const at = model.atoms[n], start = model.starts[n];
  if (at.kind === "code") return start + endOfPrefix(at.lines, (i) => instructionAt(model, at, i)[0] <= va) - 1;
  if (at.kind === "gap") return start + Math.min(at.lines - 1, Math.floor((va - at.va) / 16));
  return start + at.lines - 1;
}
