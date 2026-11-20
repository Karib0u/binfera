import { useLayoutEffect, useRef, useState } from "react";
import Asm from "./Asm";
import { ArrowPaths, cachedFunctionArrows, gutterWidth, MAX_ARROW_LANES, type Arrow } from "./BranchArrows";
import { addressAtLine, atomAtLine, endOfPrefix, instructionAt, lineOf, type ListingModel } from "./listing/model";
import { useListing } from "./listing/useListing";
import type { Analysis, Arch } from "./types";

const ROW = 20;
const hex = (n: number, pad = 0) => n.toString(16).padStart(pad, "0");

const DIRECTIVE: Record<number, string> = { 1: "db", 2: "dw", 4: "dd", 8: "dq" };

function visibleArrows(model: ListingModel, arch: Arch, first: number, last: number) {
  const start = addressAtLine(model, first), end = addressAtLine(model, last - 1);
  const shown: (Arrow & { y1: number; y2: number })[] = [];
  if (start === null || end === null) return shown;
  const { ranges } = model;
  const seen = new Set<string>();
  for (let i = endOfPrefix(ranges.length, (n) => ranges[n].maxEnd < start); i < ranges.length && ranges[i].start <= end; i++) {
    const range = ranges[i];
    if (range.end < start) continue;
    for (const arrow of cachedFunctionArrows(model.functions.get(range.fn)!.asm!, arch)) {
      const { from, to } = arrow;
      if (Math.min(from, to) > end || Math.max(from, to) < start) continue;
      const key = from + ":" + to;
      if (seen.has(key)) continue;
      const y1 = lineOf(model, from), y2 = lineOf(model, to);
      if (y1 === null || y2 === null || Math.min(y1, y2) >= last || Math.max(y1, y2) < first) continue;
      seen.add(key);
      shown.push({ ...arrow, y1: (y1 - first) * ROW + ROW / 2, y2: (y2 - first) * ROW + ROW / 2 });
    }
  }
  return shown;
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
  const model = useListing(a);
  const box = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0), [height, setHeight] = useState(600);
  const scroll = useRef(0);
  const previous = useRef<{ model: ListingModel; cursor: number | null; tick: number }>(null);
  const ready = model && model !== "failed" && model.total > 0;
  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => setHeight(el.clientHeight);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [ready]);

  useLayoutEffect(() => {
    const el = box.current;
    if (!el || !model || model === "failed") {
      previous.current = null;
      return;
    }
    const before = previous.current;
    previous.current = { model, cursor, tick };
    if (!before || before.cursor !== cursor || before.tick !== tick) {
      const line = cursor === null ? null : lineOf(model, cursor);
      if (line !== null) {
        const y = line * ROW;
        if (y < el.scrollTop + ROW || y > el.scrollTop + el.clientHeight - 2 * ROW) el.scrollTop = Math.max(0, y - el.clientHeight / 3);
      }
    } else if (before.model !== model && scroll.current > 0) {
      // Stay at the same address as instructions replace raw bytes above the viewport.
      const selected = cursor === null ? null : lineOf(before.model, cursor);
      const topLine = Math.floor(scroll.current / ROW);
      const anchor = selected !== null && selected >= topLine && selected * ROW < scroll.current + el.clientHeight ? selected : topLine;
      const va = anchor === selected ? cursor : addressAtLine(before.model, anchor);
      const line = va === null ? null : lineOf(model, va);
      if (line !== null) el.scrollTop = scroll.current + (line - anchor) * ROW;
    }
    scroll.current = el.scrollTop;
    setTop(scroll.current);
  }, [cursor, model, tick]);

  if (model === "failed") return <div className="view"><h1>Listing</h1><p className="empty">Could not build the listing.</p></div>;
  if (!model && (a.image || !a.done)) return <div className="view"><h1>Listing</h1><p className="fine">Preparing the listing…</p></div>;
  if (!model || !model.total) return <div className="view"><h1>Listing</h1><p className="empty">No sections to list in this file.</p></div>;
  const { atoms, starts, total } = model;

  const rows: React.ReactNode[] = [];
  const first = Math.max(0, Math.floor(top / ROW) - 8), last = Math.min(total, Math.ceil((top + height) / ROW) + 8);
  let n = atomAtLine(model, first);
  const active = new Set(marked);
  if (cursor !== null) active.add(cursor);
  const gutter = showArrows && model.ranges.length ? gutterWidth(MAX_ARROW_LANES) : 0;
  const shown = gutter ? visibleArrows(model, a.arch, first, last) : [];
  for (let line = first; line < last; line++) {
    while (n + 1 < atoms.length && starts[n + 1] <= line) n++;
    const at = atoms[n], k = line - starts[n];
    const y = line * ROW;
    let body: React.ReactNode;
    let ctxVa = at.va;
    if (at.kind === "sec") {
      body = k === 0 ? <div className="l-sec">; ───── section <b>{at.name}</b> · 0x{hex(at.va)} – 0x{hex(at.end)} · {at.perms}{at.entropy !== undefined && ` · entropy ${at.entropy.toFixed(2)}`}</div> : null;
    } else if (at.kind === "struct") {
      body = (
        <div className="l-struct" onClick={() => onCursor(at.va)}>
          <code className="ia">{hex(at.va, 8)}</code><b>{at.name}</b><small>{at.len} bytes at file offset 0x{hex(at.off)}</small>
        </div>
      );
    } else if (at.kind === "field") {
      const f = at.field;
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
        <div className="l-fn" onClick={() => onOpenFn(at.fn)} title="Open the decompiled function">
          <code className="ia">{hex(at.va, 8)}</code><b>{label(at.fn)}</b><span> proc</span>{exportName(at.fn) && <em className="exp-tag">export</em>}<small>{fnInfo(at.fn)}</small>
        </div>
      );
    } else if (at.kind === "code") {
      const row = instructionAt(model, at, k);
      ctxVa = row[0];
      body = <Asm arch={a.arch} onCode={onCursor} rows={[row]} labels={model.labels} self={-1} resolve={resolve} onGoto={onOpenFn} strAt={strAt} textAt={textAt} label={label} active={active} onPick={onCursor} capAt={noCaps} isData={isData} onData={onData} slot={slot} onImport={onImport} />;
    } else if (at.kind === "str") {
      body = (
        <div className={"l-line" + (cursor !== null && cursor >= at.va && cursor < at.va + at.len ? " hl" : "")} onClick={() => onCursor(at.va)}>
          <code className="ia">{hex(at.va, 8)}</code>
          <code className="l-op">{at.w ? "du" : "db"}</code>
          <a className="xref tk-s" href="#str" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onString(at.text); }}>{JSON.stringify(at.text)}</a>
          <small>; {at.w ? "UTF-16" : "ASCII"} string, {at.len} bytes</small>
          {xrefCount(at.va) > 0 && <button className="hexlink" onClick={(e) => { e.stopPropagation(); onXrefs(at.va); }}>{xrefCount(at.va)} xrefs</button>}
        </div>
      );
    } else if (at.kind === "imp") {
      body = (
        <div className={"l-line" + (cursor === at.va ? " hl" : "")} onClick={() => onCursor(at.va)}>
          <code className="ia">{hex(at.va, 8)}</code>
          <code className="l-op">{a.image!.ptrSize === 8 ? "dq" : "dd"}</code>
          <a className="xref tk-f" href="#imp" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onImport(at.name); }}>{at.name}</a>
          <small>; import {at.dll}</small>
          {xrefCount(at.va) > 0 && <button className="hexlink" onClick={(e) => { e.stopPropagation(); onXrefs(at.va); }}>{xrefCount(at.va)} xrefs</button>}
        </div>
      );
    } else {
      const base = at.va + k * 16, len = Math.min(16, at.va + at.len - base), off = at.off + k * 16;
      ctxVa = base;
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
    rows.push(<div className="lrow" key={line} style={{ top: y }} data-ctx-va={ctxVa} data-ctx-kind={at.kind === "fn" ? "fn" : at.kind === "str" ? "string" : undefined} data-ctx-fn={at.kind === "fn" ? at.fn : undefined}>{body}</div>);
  }

  return (
    <div className="listing">
      <div className="l-bar">
        <label>Section
          <select value="" onChange={(e) => { if (e.target.value !== "") onCursor(Number(e.target.value)); }}>
            <option value="">jump to…</option>
            {a.image!.sections.filter((s) => s.size > 0).map((s) => <option key={s.name + s.va} value={s.va}>{s.name} · 0x{hex(s.va)}</option>)}
          </select>
        </label>
        <span className="fine" title="Click an address to move the cursor, a function head to open it">{total.toLocaleString("en-US")} lines</span>
        {!a.settled && !a.done && <span className="fine">Disassembly is still loading</span>}
      </div>
      <div className="l-scroll" ref={box} onScroll={(e) => { scroll.current = e.currentTarget.scrollTop; setTop(scroll.current); }}>
        <div style={{ height: total * ROW, position: "relative", "--arrow-gutter": gutter + "px" } as React.CSSProperties}>
          {rows}
          {shown.length > 0 && <svg className="arrows" style={{ left: 8, top: first * ROW }} width={gutter} height={(last - first) * ROW} aria-hidden><ArrowPaths arrows={shown} width={gutter} active={active} onPick={(ad) => onCursor(ad)} /></svg>}
        </div>
      </div>
    </div>
  );
}

const noCaps = new Map<number, string[]>();
