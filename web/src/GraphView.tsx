import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { ADDR_IN_ASM, asmAddress, buildCfg, layoutCfg, operandNote, rowFlow, type Arch, type AsmRow, type EdgeKind } from "./graph";
import { importKey, tokenized, tokKey } from "./highlight";
import { useNotes } from "./names";
import type { FunctionGraph, CapaRule } from "./types";

const LINE_H = 18, HEAD_H = 24, CAP_H = 18, PAD_X = 10, PAD_Y = 6;
const MIN_ZOOM = 0.1, MAX_ZOOM = 2.5;
/** A graph that only fits below this zoom opens at READ_ZOOM on its entry block instead, where the text can be read. */
const LEGIBLE_ZOOM = 0.6, READ_ZOOM = 0.9;
const MINI_W = 150, MINI_H = 190;
const EDGE_VAR: Record<EdgeKind, string> = { true: "var(--c-str)", false: "var(--err)", jump: "var(--c-fn)" };

let charWidth = 0;
/** Width of one monospace character at the graph's font size, measured once. */
function measureChar() {
  if (charWidth) return charWidth;
  const mono = getComputedStyle(document.documentElement).getPropertyValue("--mono") || "monospace";
  const ctx = document.createElement("canvas").getContext("2d");
  if (ctx) { ctx.font = `12px ${mono}`; charWidth = ctx.measureText("0".repeat(20)).width / 20; }
  return (charWidth ||= 7.2);
}

interface Props {
  rows: AsmRow[];
  recovered?: FunctionGraph;
  arch: Arch;
  self: number;
  name: string;
  rules: CapaRule[];
  resolve: (t: string) => number | undefined;
  label: (ad: number) => string;
  strAt: (ad: number) => string | undefined;
  /** Text at a data address that the strings list leaves out. */
  textAt?: (ad: number) => string | undefined;
  onGoto: (ad: number) => void;
  /** The address every view follows: its instruction is marked, and brought into view when it moves. */
  cursor?: number | null; onCursor?: (ad: number) => void;
  /** Other instructions to mark with it: those of a selected C line. */
  marked?: Set<number>;
  /** The import a pointer-slot address holds, so `call [0x40d184]` reads as the API it calls; and file data. */
  slot?: (va: number) => { name: string; dll: string } | undefined; onImport?: (name: string) => void;
  isData?: (ad: number) => boolean; onData?: (ad: number) => void;
  /** A branch target outside this function. */
  onCode?: (va: number) => void;
}

interface View { x: number; y: number; k: number }

/** Control-flow graph of one function, in the manner of IDA's graph view: blocks, coloured edges, pan and zoom. */
export default function GraphView({ rows, recovered, arch, self, name, rules, resolve, label, strAt, textAt, onGoto, cursor, onCursor, marked, slot, onImport, isData, onData, onCode }: Props) {
  const cfg = useMemo(() => buildCfg(rows, arch, recovered), [rows, arch, recovered]);
  // The parent passes fresh closures and arrays on every render; key the layout on content so it is not redone (and the view reset).
  const strRef = useRef(strAt);
  strRef.current = strAt;
  const textRef = useRef(textAt);
  textRef.current = textAt;
  const nameRef = useRef((v: number): string | undefined => undefined);
  nameRef.current = (v) => { const target = resolve("0x" + v.toString(16)); return target !== undefined && target !== self ? label(target) : slot?.(v)?.name; };
  const rulesRef = useRef(rules);
  rulesRef.current = rules;
  const ruleKey = rules.map((r) => r.name).join("|");

  // Blocks that hold a basic-block or instruction scoped capa match.
  const caps = useMemo(() => {
    const m = new Map<number, string[]>();
    for (const r of rulesRef.current) {
      if (r.scope !== "basic block" && r.scope !== "instruction") continue;
      for (const ad of r.addresses) {
        const b = [...cfg.blocks].reverse().find((x) => x.addr <= ad);
        if (b && !(m.get(b.id) ?? []).includes(r.name)) m.set(b.id, [...(m.get(b.id) ?? []), r.name]);
      }
    }
    return m;
  }, [ruleKey, cfg]);

  const layout = useMemo(() => {
    const cw = measureChar();
    return layoutCfg(cfg, (b) => {
      const noteLen = (text: string) => {
        for (const m of text.matchAll(ADDR_IN_ASM)) { const s = operandNote(text, m.index!, asmAddress(m), strRef.current, textRef.current); if (s !== undefined) return Math.min(s.length, 40) + 8; }
        return 0;
      };
      // A name shown in place of an address can be longer than the address.
      const extra = (text: string) => { let n = 0; for (const m of text.matchAll(ADDR_IN_ASM)) n += Math.max(0, (nameRef.current(asmAddress(m))?.length ?? 0) - m[0].length); return n; };
      const chars = Math.max(...b.rows.map((r) => 10 + r[2].length + extra(r[2]) + noteLen(r[2]) + 2), 12);
      const headChars = (b.addr === self ? name.length : 4 + 8) + 2;
      return { w: Math.ceil(Math.max(chars, headChars) * cw) + PAD_X * 2, h: HEAD_H + (caps.get(b.id)?.length ?? 0) * CAP_H + b.rows.length * LINE_H + PAD_Y * 2 };
    });
  }, [cfg, caps, self, name]);

  const box = useRef<HTMLDivElement>(null);
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 });
  const [picked, setPicked] = useState<number | null>(null);
  const [panning, setPanning] = useState(false);

  // Until the user pans or zooms, the graph keeps its opening view as the pane is resized.
  const touched = useRef(false);
  const [size, setSize] = useState({ w: 0, h: 0 });
  // The cursor check below runs right after an opening view is set, before the next render: it needs that view.
  const viewRef = useRef(view);
  viewRef.current = view;
  const place = useCallback((v: View) => { viewRef.current = v; setView(v); }, []);
  const fit = useCallback(() => {
    const el = box.current;
    if (!el || !layout.width || !el.clientWidth || !el.clientHeight) return;
    touched.current = false;
    const k = Math.min(1, el.clientWidth / layout.width, el.clientHeight / layout.height);
    place({ k, x: Math.max(0, (el.clientWidth - layout.width * k) / 2), y: 0 });
  }, [layout]);
  /** Centres a graph point in the pane. */
  const centerOn = useCallback((px: number, py: number, k: number) => {
    const el = box.current;
    if (el) setView({ k, x: el.clientWidth / 2 - px * k, y: el.clientHeight / 2 - py * k });
  }, []);
  const open = useCallback(() => {
    const el = box.current;
    if (!el || !layout.width || !el.clientWidth || !el.clientHeight) return;
    if (Math.min(el.clientWidth / layout.width, el.clientHeight / layout.height) >= LEGIBLE_ZOOM) return fit();
    touched.current = false;
    const entry = layout.nodes.find((p) => cfg.blocks[p.id].addr === self) ?? layout.nodes[0];
    place({ k: READ_ZOOM, x: el.clientWidth / 2 - (entry.x + entry.w / 2) * READ_ZOOM, y: 16 - entry.y * READ_ZOOM });
  }, [fit, layout, cfg, self]);
  useLayoutEffect(() => { open(); setPicked(null); }, [open]);
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(() => { setSize({ w: el.clientWidth, h: el.clientHeight }); if (!touched.current) open(); });
    ro.observe(el);
    return () => ro.disconnect();
  }, [open]);

  // The cursor moved from another view (a capability, the listing, a C line): bring its instruction into view.
  useEffect(() => {
    const el = box.current;
    if (!el || cursor == null) return;
    const node = layout.nodes.find((p) => cfg.blocks[p.id].rows.some((r) => r[0] === cursor));
    if (!node) return;
    const b = cfg.blocks[node.id], row = b.rows.findIndex((r) => r[0] === cursor);
    const y = node.y + node.h - PAD_Y - (b.rows.length - row - 0.5) * LINE_H, x = node.x + node.w / 2;
    const v = viewRef.current, sx = x * v.k + v.x, sy = y * v.k + v.y;
    if (v.k >= LEGIBLE_ZOOM && sx > 0 && sx < el.clientWidth && sy > 0 && sy < el.clientHeight) return;
    touched.current = true;
    centerOn(x, y, Math.max(v.k, READ_ZOOM));
  }, [cursor, layout, cfg, centerOn]);

  const zoomAt = useCallback((factor: number, px: number, py: number) => {
    touched.current = true;
    setView((v) => {
      const k = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, v.k * factor));
      return { k, x: px - ((px - v.x) / v.k) * k, y: py - ((py - v.y) / v.k) * k };
    });
  }, []);
  const zoomCenter = (factor: number) => { const el = box.current; if (el) zoomAt(factor, el.clientWidth / 2, el.clientHeight / 2); };

  // Wheel pans; Ctrl/Cmd+wheel (and trackpad pinch, which arrives as ctrl+wheel) zooms. Needs a non-passive listener.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      if (e.ctrlKey || e.metaKey) zoomAt(Math.exp(-e.deltaY * 0.01), e.clientX - r.left, e.clientY - r.top);
      else { touched.current = true; setView((v) => ({ ...v, x: v.x - e.deltaX, y: v.y - e.deltaY })); }
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  // Drag to pan, two fingers to pinch.
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const moved = useRef(0);
  const onDown = (e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest("a, button, .gmini")) return;
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    moved.current = 0;
    setPanning(true);
  };
  const onMove = (e: React.PointerEvent) => {
    const prev = pointers.current.get(e.pointerId);
    if (!prev) return;
    const now = { x: e.clientX, y: e.clientY };
    const others = [...pointers.current].filter(([id]) => id !== e.pointerId).map(([, p]) => p);
    pointers.current.set(e.pointerId, now);
    moved.current += Math.abs(now.x - prev.x) + Math.abs(now.y - prev.y);
    // Capture drags after they move, so a plain click still reaches its instruction or block.
    if (moved.current < 4 && !others.length) return;
    box.current?.setPointerCapture(e.pointerId);
    if (others.length === 1) {
      const o = others[0], r = box.current!.getBoundingClientRect();
      const before = Math.hypot(prev.x - o.x, prev.y - o.y), after = Math.hypot(now.x - o.x, now.y - o.y);
      if (before > 0) zoomAt(after / before, (now.x + o.x) / 2 - r.left, (now.y + o.y) / 2 - r.top);
    } else {
      touched.current = true;
      setView((v) => ({ ...v, x: v.x + now.x - prev.x, y: v.y + now.y - prev.y }));
    }
  };
  const onUp = (e: React.PointerEvent) => {
    pointers.current.delete(e.pointerId);
    if (!pointers.current.size) setPanning(false);
  };

  // Include one viewport around the pane so panning mounts blocks before they enter it.
  const visible = {
    left: (-view.x - size.w) / view.k, top: (-view.y - size.h) / view.k,
    right: (-view.x + size.w * 2) / view.k, bottom: (-view.y + size.h * 2) / view.k,
  };
  const visibleNodes = size.w && size.h ? layout.nodes.filter((p) =>
    p.x + p.w >= visible.left && p.x <= visible.right && p.y + p.h >= visible.top && p.y <= visible.bottom) : [];

  const edgeActive = (from: number, to: number) => picked !== null && (from === picked || to === picked);

  if (!cfg.blocks.length) return <p className="fine">No instruction listing.</p>;

  return (
    <div className="gv">
      <div className="graph-tools">
        <button onClick={() => zoomCenter(1 / 1.25)} aria-label="Zoom out">−</button>
        <span>{Math.round(view.k * 100)}%</span>
        <button onClick={() => zoomCenter(1.25)} aria-label="Zoom in">+</button>
        <button onClick={fit} title="Fit the whole graph in the pane">Fit</button>
        <small>{cfg.blocks.length} blocks · {cfg.edges.length} edges</small>
      </div>
      <div className="graph-legend"><i style={{ background: EDGE_VAR.true }} />true<i style={{ background: EDGE_VAR.false }} />false<i style={{ background: EDGE_VAR.jump }} />jump / fall-through</div>
      <div ref={box} className={"graph-view" + (panning ? " panning" : "")} onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp}
        onPointerLeave={(e) => { if (!e.currentTarget.hasPointerCapture(e.pointerId)) onUp(e); }}
        onClick={(e) => { if (moved.current < 4 && !(e.target as HTMLElement).closest(".gb")) setPicked(null); }}>
        <div className="graph-canvas" style={{ width: layout.width, height: layout.height, transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})` }}>
          <svg width={layout.width} height={layout.height} aria-hidden>
            <defs>
              {(Object.keys(EDGE_VAR) as EdgeKind[]).map((k) => (
                <marker key={k} id={"arrow-" + k} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">
                  <path d="M0 1 L10 5 L0 9 z" fill={EDGE_VAR[k]} />
                </marker>
              ))}
            </defs>
            {layout.routes.map((r, i) => {
              const on = edgeActive(r.edge.from, r.edge.to);
              return (
                <path key={i} d={"M" + r.pts.map((p) => p.join(" ")).join(" L")} fill="none" stroke={EDGE_VAR[r.edge.kind]}
                  strokeWidth={on ? 2.4 : 1.5} strokeLinejoin="round" strokeDasharray={r.back ? "5 3" : undefined}
                  opacity={picked === null || on ? 1 : 0.25} markerEnd={`url(#arrow-${r.edge.kind})`} />
              );
            })}
          </svg>
          {visibleNodes.map((p) => {
            const b = cfg.blocks[p.id];
            const bcaps = caps.get(b.id) ?? [];
            return (
              <div key={b.id} className={"gb" + (picked === b.id ? " on" : "") + (b.addr === self ? " entry" : "")} role="button" tabIndex={0} aria-pressed={picked === b.id}
                aria-label={(b.addr === self ? name : "loc_" + b.addr.toString(16)) + `, ${b.rows.length} instructions`}
                style={{ left: p.x, top: p.y, width: p.w, height: p.h }}
                onKeyDown={(e) => { if ((e.key === "Enter" || e.key === " ") && e.target === e.currentTarget) { e.preventDefault(); setPicked(picked === b.id ? null : b.id); } }}
                onClick={(e) => { if (moved.current < 4) { e.stopPropagation(); setPicked(picked === b.id ? null : b.id); } }}>
                <div className="gb-head">{b.addr === self ? name : "loc_" + b.addr.toString(16).padStart(8, "0")}</div>
                {bcaps.map((c) => <div key={c} className="gb-cap" title={c}>{c}</div>)}
                <div className="gb-body">
                  {b.rows.map(([ad, hexBytes, text]) => <Insn key={ad} ad={ad} text={text} branch={branchTarget([ad, hexBytes, text], arch)} onBranch={(v) => (rows.some((r) => r[0] === v) ? onCursor : onCode)?.(v)} self={self} resolve={resolve} label={label} strAt={strAt} textAt={textAt} onGoto={onGoto} slot={slot} onImport={onImport} isData={isData} onData={onData} active={ad === cursor || !!marked?.has(ad)} onPick={() => { if (moved.current < 4) onCursor?.(ad); }} />)}
                </div>
              </div>
            );
          })}
        </div>
        {(layout.width * view.k > size.w || layout.height * view.k > size.h) && <Minimap layout={layout} entry={self} blocks={cfg.blocks} view={view} size={size} onCenter={(x, y) => { touched.current = true; centerOn(x, y, view.k); }} />}
      </div>
    </div>
  );
}

/** The whole graph in small, with the visible area marked; click or drag to move there. */
function Minimap({ layout, entry, blocks, view, size, onCenter }: {
  layout: { width: number; height: number; nodes: { id: number; x: number; y: number; w: number; h: number }[] };
  entry: number; blocks: { addr: number }[]; view: View; size: { w: number; h: number }; onCenter: (x: number, y: number) => void;
}) {
  // Keep every block in the overview using two paths rather than one DOM node per block.
  const paths = useMemo(() => {
    const out = { entry: "", other: "" };
    for (const p of layout.nodes) out[blocks[p.id].addr === entry ? "entry" : "other"] += `M${p.x} ${p.y}h${p.w}v${p.h}h${-p.w}z`;
    return out;
  }, [layout, blocks, entry]);
  const k = Math.min(MINI_W / layout.width, MINI_H / layout.height);
  const w = layout.width * k, h = layout.height * k;
  const to = (e: React.PointerEvent<SVGSVGElement>) => { const r = e.currentTarget.getBoundingClientRect(); onCenter((e.clientX - r.left) / k, (e.clientY - r.top) / k); };
  return (
    <svg className="gmini" width={w} height={h} viewBox={`0 0 ${layout.width} ${layout.height}`} aria-hidden
      onPointerDown={(e) => { e.stopPropagation(); e.currentTarget.setPointerCapture(e.pointerId); to(e); }}
      onPointerMove={(e) => { if (e.buttons) to(e); }}
      onClick={(e) => e.stopPropagation()}>
      <path className="gmini-blocks" d={paths.other} />
      <path className="gmini-blocks entry" d={paths.entry} />
      <rect className="gmini-view" x={-view.x / view.k} y={-view.y / view.k} width={size.w / view.k} height={size.h / view.k} />
    </svg>
  );
}

const branchTarget = (row: AsmRow, arch: Arch) => {
  const flow = rowFlow(row, arch);
  return flow.kind === "jump" || flow.kind === "cond" || flow.kind === "call" ? flow.target : undefined;
};

function Insn({ ad, text, branch, onBranch, self, resolve, label, strAt, textAt, onGoto, slot, onImport, isData, onData, active, onPick }: { ad: number; text: string; branch?: number; onBranch: (va: number) => void; active: boolean; onPick: () => void } & Pick<Props, "self" | "resolve" | "label" | "strAt" | "textAt" | "onGoto" | "slot" | "onImport" | "isData" | "onData">) {
  const notes = useNotes();
  const sp = text.indexOf(" ");
  const mnem = sp < 0 ? text : text.slice(0, sp), ops = sp < 0 ? "" : text.slice(sp);
  const parts: React.ReactNode[] = [];
  let last = 0, k = 0, note: string | undefined;
  for (const m of ops.matchAll(ADDR_IN_ASM)) {
    const v = asmAddress(m), lit = "0x" + v.toString(16), target = resolve(lit);
    parts.push(<span key={k++}>{tokenized(ops.slice(last, m.index))}</span>);
    const held = slot?.(v);
    parts.push(target !== undefined && target !== self
      ? <a key={k++} href={"#" + lit} className="xref tk-f" data-tok={tokKey(label(target))} data-fn={target} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onGoto(target); }}>{label(target)}</a>
      : held
        ? <a key={k++} href={"#" + lit} className="xref tk-f" data-tok={importKey(held)} title={held.dll + " · " + lit} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onImport?.(held.name); }}>{held.name}</a>
      : v === branch
        ? <a key={k++} href={"#" + lit} className="xref tk-n" data-tok={tokKey(lit)} title="Go to this instruction" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onBranch(v); }}>{lit}</a>
      : isData?.(v)
        ? <a key={k++} href={"#" + lit} className="xref tk-n" data-tok={tokKey(lit)} title="Show in the Listing" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onData?.(v); }}>{lit}</a>
        : <span key={k++} className="tk-n" data-tok={tokKey(lit)}>{lit}</span>);
    last = m.index! + m[0].length;
    note ??= operandNote(ops, m.index!, v, strAt, v === branch ? undefined : textAt);
  }
  parts.push(<span key={k++}>{tokenized(ops.slice(last))}</span>);
  const own = notes.commentAt(ad, true);
  return (
    <div className={"gi" + (active ? " hl" : "")} onClick={onPick}>
      <code className="ia">{ad.toString(16).padStart(8, "0")}</code>
      <code><span className="tk-k" data-tok={mnem}>{mnem}</span>{parts}{note && <span className="tk-c">  ; {JSON.stringify(note.length > 40 ? note.slice(0, 40) + "…" : note)}</span>}{ad !== self && own && <span className="tk-c ucm" title={own}>  ; {own.length > 60 ? own.slice(0, 60) + "…" : own}</span>}</code>
    </div>
  );
}
