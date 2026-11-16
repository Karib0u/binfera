import { useEffect, useMemo, useRef, useState } from "react";
import Asm from "./Asm";
import { ArrowPaths, functionArrows, gutterWidth, type Arrow } from "./BranchArrows";
import type { StructField } from "./engine/image";
import type { Analysis } from "./types";

const ROW = 20;
const hex = (n: number, pad = 0) => n.toString(16).padStart(pad, "0");

type Row = [number, string, string];
interface Atom {
  kind: "sec" | "fn" | "insn" | "str" | "imp" | "gap" | "struct" | "field";
  va: number;
  lines: number;
  row?: Row; fn?: number; text?: string; w?: boolean; len?: number; off?: number; name?: string; dll?: string;
  sec?: { name: string; end: number; perms: string; entropy?: number };
  field?: StructField;
}

const DIRECTIVE: Record<number, string> = { 1: "db", 2: "dw", 4: "dd", 8: "dq" };

/** Every address of the file in order: section headers, file structures, function heads, instructions, strings, import slots, and the raw bytes between them. */
function build(a: Analysis): { atoms: Atom[]; starts: Uint32Array; total: number } | null {
  const image = a.image;
  if (!image) return null;
  const insns: { row: Row; at: number }[] = [];
  const heads = new Map<number, number>();
  const labels: Record<string, string> = {};
  for (const [fn, f] of a.functions) {
    if (!f.asm?.length) continue;
    heads.set(f.asm[0][0], fn);
    Object.assign(labels, f.labels);
    for (const row of f.asm) insns.push({ row, at: row[0] });
  }
  insns.sort((x, y) => x.at - y.at);
  const strs = [...a.strings].sort((x, y) => x.a - y.a);
  const imps = image.imports.filter((i) => i.va).sort((x, y) => x.va - y.va);
  const atoms: Atom[] = [];
  const lower = <T,>(arr: T[], key: (v: T) => number, v: number) => {
    let lo = 0, hi = arr.length;
    while (lo < hi) { const m = (lo + hi) >> 1; if (key(arr[m]) < v) lo = m + 1; else hi = m; }
    return lo;
  };
  const fields = (image.details?.structures ?? []).flatMap((s) => s.va === undefined ? [] : s.fields.map((f, n) => ({ va: s.va! + f.off - s.off, f, head: n === 0 ? s : undefined }))).sort((x, y) => x.va - y.va);
  const spanOf = (s: { va: number; size: number; vsize: number }) => s.va + Math.min(s.size, Math.max(s.vsize, 1));
  const mapped = image.sections.filter((s) => s.size > 0 && image.vaToOff(s.va) !== null).sort((x, y) => x.va - y.va);
  // Headers outside every section (usually Mach-O) still get a place: a section of their own, up to the next real one.
  const headerSpans: { name: string; va: number; size: number; vsize: number; perms: string; entropy?: number }[] = [];
  for (const { va, f } of fields) {
    if (mapped.some((s) => va >= s.va && va < spanOf(s))) continue;
    const last = headerSpans[headerSpans.length - 1], stop = va + f.size;
    // Fields a table does not name leave small holes; they are still the same headers, shown as bytes.
    if (last && va <= last.va + last.size + 0x1000) { last.size = Math.max(last.size, stop - last.va); last.vsize = last.size; }
    else headerSpans.push({ name: "file headers", va, size: f.size, vsize: f.size, perms: "r--" });
  }
  const secs = [...mapped, ...headerSpans].sort((x, y) => x.va - y.va);
  secs.forEach((s, n) => {
    const next = secs[n + 1];
    if (headerSpans.includes(s as typeof headerSpans[number]) && next && s.va + s.size > next.va) { s.size = next.va - s.va; s.vsize = s.size; }
  });
  for (const s of secs) {
    const end = spanOf(s);
    atoms.push({ kind: "sec", va: s.va, lines: 2, sec: { name: s.name, end, perms: s.perms, entropy: s.entropy } });
    let pos = s.va, i = lower(insns, (x) => x.at, s.va), j = lower(strs, (x) => x.a, s.va), k = lower(imps, (x) => x.va, s.va), m = lower(fields, (x) => x.va, s.va);
    const gap = (to: number) => {
      if (to > pos) atoms.push({ kind: "gap", va: pos, lines: Math.ceil((to - pos) / 16), len: to - pos, off: image.vaToOff(pos) ?? 0 });
    };
    while (pos < end) {
      const ni = i < insns.length && insns[i].at < end ? insns[i].at : Infinity;
      const nj = j < strs.length && strs[j].a < end ? strs[j].a : Infinity;
      const nk = k < imps.length && imps[k].va < end ? imps[k].va : Infinity;
      const nf = m < fields.length && fields[m].va < end ? fields[m].va : Infinity;
      const next = Math.min(ni, nj, nk, nf);
      if (next === Infinity) break;
      if (next < pos) { if (nf === next) m++; else if (ni === next) i++; else if (nj === next) j++; else k++; continue; } // overlaps what was just placed
      // A header's named fields beat text that merely looks like a string across them.
      if (nj === next && nf !== next && nf < strs[j].a + Math.max(strs[j].s.length, 1)) { j++; continue; }
      gap(next);
      if (nf === next) {
        const { va, f, head } = fields[m++];
        if (head) atoms.push({ kind: "struct", va, lines: 1, name: head.name, len: head.size, off: head.off });
        atoms.push({ kind: "field", va, lines: 1, field: f });
        pos = va + f.size;
      } else if (ni === next) {
        const { row, at } = insns[i++];
        const fn = heads.get(at);
        if (fn !== undefined) atoms.push({ kind: "fn", va: at, lines: 2, fn });
        atoms.push({ kind: "insn", va: at, lines: 1, row, name: labels[at] });
        pos = at + Math.max(1, row[1].replace(/\s/g, "").length / 2);
      } else if (nj === next) {
        const x = strs[j++];
        const len = Math.min(end - x.a, x.s.length * (x.w ? 2 : 1) + (x.w ? 2 : 1));
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
  for (let n = 0; n < atoms.length; n++) starts[n + 1] = starts[n] + atoms[n].lines;
  return { atoms, starts, total: starts[atoms.length] };
}

/** The whole file as text, the way IDA's listing shows it: addresses, bytes, instructions, data and strings in one scroll. */
export default function Listing({ a, cursor, marked, tick, onCursor, label, resolve, strAt, textAt, isData, onData, onOpenFn, onString, onImport, fnInfo, xrefCount, onXrefs, exportName, slot, arrows: showArrows }: {
  /** Branch arrows in a gutter; phones leave the room to the text. */
  arrows?: boolean;
  slot: (va: number) => { name: string; dll: string } | undefined;
  xrefCount: (va: number) => number; onXrefs: (va: number) => void; exportName: (ad: number) => string | undefined;
  a: Analysis; cursor: number | null; tick: number; onCursor: (va: number) => void;
  /** Other instructions to mark with the cursor: those of a selected C line. */
  marked?: Set<number>;
  label: (ad: number) => string; resolve: (t: string) => number | undefined; strAt: (ad: number) => string | undefined; textAt: (ad: number) => string | undefined;
  isData: (ad: number) => boolean; onData: (ad: number) => void;
  onOpenFn: (ad: number) => void; onString: (text: string) => void; onImport: (name: string) => void;
  /** A function's header comment: how it is reached and what it does. */
  fnInfo: (ad: number) => string;
}) {
  const model = useMemo(() => (a.settled ? build(a) : null), [a.settled, a.functions, a.image, a.strings]);
  const box = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0), [height, setHeight] = useState(600);
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => setHeight(el.clientHeight);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [model]);

  const atomAt = (va: number) => {
    if (!model) return -1;
    const { atoms } = model;
    let lo = 0, hi = atoms.length - 1, r = -1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (atoms[m].va <= va) { r = m; lo = m + 1; } else hi = m - 1; }
    // Prefer the instruction or data atom over the header lines sharing its address.
    while (r > 0 && (atoms[r].kind === "fn" || atoms[r].kind === "sec") && atoms[r + 1]?.va === va) r++;
    return r;
  };
  const lineOf = (va: number) => {
    const n = atomAt(va);
    if (n < 0 || !model) return null;
    const at = model.atoms[n];
    return model.starts[n] + (at.kind === "gap" ? Math.floor((va - at.va) / 16) : at.kind === "sec" || at.kind === "fn" ? at.lines - 1 : 0);
  };
  // Lanes are per function, so an arrow keeps its place as the list scrolls. Sorted, to find the visible ones quickly.
  const branches = useMemo(() => {
    if (!model || !showArrows) return null;
    const seen = new Set<string>(), list: (Arrow & { y1: number; y2: number; lo: number; hi: number })[] = [];
    let lanes = 0, span = 0;
    for (const f of a.functions.values()) {
      for (const r of f.asm?.length ? functionArrows(f.asm, a.arch) : []) {
        const key = r.from + ":" + r.to, y1 = lineOf(r.from), y2 = lineOf(r.to);
        if (seen.has(key) || y1 === null || y2 === null) continue;
        seen.add(key);
        const lo = Math.min(y1, y2), hi = Math.max(y1, y2);
        list.push({ ...r, y1, y2, lo, hi });
        lanes = Math.max(lanes, r.lane + 1);
        span = Math.max(span, hi - lo);
      }
    }
    return { list: list.sort((x, y) => x.lo - y.lo), lanes, span };
  }, [model, a.arch, showArrows]);
  useEffect(() => {
    const el = box.current;
    if (!el || cursor === null) return;
    const line = lineOf(cursor);
    if (line === null) return;
    const y = line * ROW;
    if (y < el.scrollTop + ROW || y > el.scrollTop + el.clientHeight - 2 * ROW) { el.scrollTop = Math.max(0, y - el.clientHeight / 3); setTop(el.scrollTop); }
  }, [cursor, model, tick]);

  if (!a.settled) return <div className="view"><h1>Listing</h1><p className="fine">The listing is built once decompilation finishes ({a.functions.size} of {a.order.length} functions so far).</p></div>;
  if (!model || !model.total) return <div className="view"><h1>Listing</h1><p className="empty">No sections to list in this file.</p></div>;
  const { atoms, starts, total } = model;

  const rows: React.ReactNode[] = [];
  const first = Math.max(0, Math.floor(top / ROW) - 8), last = Math.min(total, Math.ceil((top + height) / ROW) + 8);
  let n = (() => { let lo = 0, hi = atoms.length - 1; while (lo < hi) { const m = (lo + hi + 1) >> 1; if (starts[m] <= first) lo = m; else hi = m - 1; } return lo; })();
  const active = new Set(marked);
  if (cursor !== null) active.add(cursor);
  const gutter = gutterWidth(branches?.lanes ?? 0);
  const shown: (Arrow & { y1: number; y2: number })[] = [];
  if (branches) {
    const list = branches.list;
    let lo = 0, hi = list.length;
    while (lo < hi) { const m = (lo + hi) >> 1; if (list[m].lo < first - branches.span) lo = m + 1; else hi = m; }
    for (let i = lo; i < list.length && list[i].lo < last; i++) {
      const r = list[i];
      if (r.hi >= first) shown.push({ ...r, y1: (r.y1 - first) * ROW + ROW / 2, y2: (r.y2 - first) * ROW + ROW / 2 });
    }
  }
  for (let line = first; line < last; line++) {
    while (n + 1 < atoms.length && starts[n + 1] <= line) n++;
    const at = atoms[n], k = line - starts[n];
    const y = line * ROW;
    let body: React.ReactNode;
    if (at.kind === "sec") {
      body = k === 0 ? <div className="l-sec">; ───── section <b>{at.sec!.name}</b> · 0x{hex(at.va)} – 0x{hex(at.sec!.end)} · {at.sec!.perms}{at.sec!.entropy !== undefined && ` · entropy ${at.sec!.entropy.toFixed(2)}`}</div> : null;
    } else if (at.kind === "struct") {
      body = (
        <div className="l-struct" onClick={() => onCursor(at.va)}>
          <code className="ia">{hex(at.va, 8)}</code><b>{at.name}</b><small>{at.len} bytes at file offset 0x{hex(at.off!)}</small>
        </div>
      );
    } else if (at.kind === "field") {
      const f = at.field!;
      body = (
        <div className={"l-line l-field" + (cursor !== null && cursor >= at.va && cursor < at.va + f.size ? " hl" : "")} onClick={() => onCursor(at.va)}>
          <code className="ia">{hex(at.va, 8)}</code>
          <span className="l-fname">{f.name}</span>
          <code className="l-fop">{DIRECTIVE[f.size] ?? "db"}</code>
          <code className="l-bytes">{f.value}</code>
          {f.note && <small>; {f.note}</small>}
          {f.target !== undefined && <button className="hexlink" title="Move the cursor there" onClick={(e) => { e.stopPropagation(); onCursor(f.target!); }}>→ 0x{hex(f.target)}</button>}
        </div>
      );
    } else if (at.kind === "fn") {
      body = k === 0 ? null : (
        <div className="l-fn" onClick={() => onOpenFn(at.fn!)} title="Open the decompiled function">
          <code className="ia">{hex(at.va, 8)}</code><b>{label(at.fn!)}</b><span> proc</span>{exportName(at.fn!) && <em className="exp-tag">export</em>}<small>{fnInfo(at.fn!)}</small>
        </div>
      );
    } else if (at.kind === "insn") {
      body = <Asm arch={a.arch} onCode={onCursor} rows={[at.row!]} labels={at.name ? { [at.va]: at.name } : undefined} self={-1} resolve={resolve} onGoto={onOpenFn} strAt={strAt} textAt={textAt} label={label} active={active} onPick={onCursor} capAt={noCaps} isData={isData} onData={onData} slot={slot} onImport={onImport} />;
    } else if (at.kind === "str") {
      body = (
        <div className={"l-line" + (cursor !== null && cursor >= at.va && cursor < at.va + at.len! ? " hl" : "")} onClick={() => onCursor(at.va)}>
          <code className="ia">{hex(at.va, 8)}</code>
          <code className="l-op">{at.w ? "du" : "db"}</code>
          <a className="xref tk-s" href="#str" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onString(at.text!); }}>{JSON.stringify(at.text)}</a>
          <small>; {at.w ? "UTF-16" : "ASCII"} string, {at.len} bytes</small>
          {xrefCount(at.va) > 0 && <button className="hexlink" onClick={(e) => { e.stopPropagation(); onXrefs(at.va); }}>{xrefCount(at.va)} xrefs</button>}
        </div>
      );
    } else if (at.kind === "imp") {
      body = (
        <div className={"l-line" + (cursor === at.va ? " hl" : "")} onClick={() => onCursor(at.va)}>
          <code className="ia">{hex(at.va, 8)}</code>
          <code className="l-op">{a.image!.ptrSize === 8 ? "dq" : "dd"}</code>
          <a className="xref tk-f" href="#imp" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onImport(at.name!); }}>{at.name}</a>
          <small>; import {at.dll}</small>
          {xrefCount(at.va) > 0 && <button className="hexlink" onClick={(e) => { e.stopPropagation(); onXrefs(at.va); }}>{xrefCount(at.va)} xrefs</button>}
        </div>
      );
    } else {
      const base = at.va + k * 16, len = Math.min(16, at.va + at.len! - base), off = at.off! + k * 16;
      const bytes = a.image!.bytes.subarray(off, off + len);
      body = (
        <div className={"l-line" + (cursor !== null && cursor >= base && cursor < base + len ? " hl" : "")} onClick={() => onCursor(base)}>
          <code className="ia">{hex(base, 8)}</code>
          <code className="l-op">db</code>
          <code className="l-bytes">{Array.from(bytes, (b) => hex(b, 2) + "h").join(", ")}</code>
          <small className="l-ascii">; {Array.from(bytes, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("")}</small>
        </div>
      );
    }
    const ctxVa = at.kind === "gap" ? at.va + k * 16 : at.va;
    rows.push(<div className="lrow" key={line} style={{ top: y }} data-ctx-va={ctxVa} data-ctx-kind={at.kind === "fn" ? "fn" : at.kind === "str" ? "string" : undefined} data-ctx-fn={at.kind === "fn" ? at.fn : undefined}>{body}</div>);
  }

  return (
    <div className="listing">
      <div className="l-bar">
        <label>Section
          <select value="" onChange={(e) => { const v = Number(e.target.value); if (v) { onCursor(v); } }}>
            <option value="">jump to…</option>
            {a.image!.sections.filter((s) => s.size > 0).map((s) => <option key={s.name + s.va} value={s.va}>{s.name} · 0x{hex(s.va)}</option>)}
          </select>
        </label>
        <span className="fine" title="Click an address to move the cursor, a function head to open it">{total.toLocaleString("en-US")} lines</span>
      </div>
      <div className="l-scroll" ref={box} onScroll={(e) => setTop(e.currentTarget.scrollTop)}>
        <div style={{ height: total * ROW, position: "relative", "--arrow-gutter": gutter + "px" } as React.CSSProperties}>
          {rows}
          {gutter > 0 && <svg className="arrows" style={{ left: 8, top: first * ROW }} width={gutter} height={(last - first) * ROW} aria-hidden><ArrowPaths arrows={shown} width={gutter} active={active} onPick={(ad) => onCursor(ad)} /></svg>}
        </div>
      </div>
    </div>
  );
}

const noCaps = new Map<number, string[]>();
