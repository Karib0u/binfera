import { useEffect, useMemo, useRef, useState } from "react";

const NODE_H = 28, GAP = 10, PAD = 24, MAX_PER_LEVEL = 40;
const hex = (n: number) => "0x" + n.toString(16);

interface Node { id: number; level: number; row: number; more?: number }

/** The call graph around one function: its callers to the left, its callees to the right, a few levels deep. */
export default function CallGraph({ order, callees, callers, center, setCenter, label, caps, onOpen, ready, compact }: {
  /** The narrow form that sits in a function's side panel: no title bar, tighter columns. */
  compact?: boolean;
  order: number[]; callees: Map<number, number[]>; callers: Map<number, number[]>;
  center: number | null; setCenter: (ad: number) => void; label: (ad: number) => string;
  /** Capability names matched in a function. */
  caps: (ad: number) => string[]; onOpen: (ad: number) => void; ready: boolean;
}) {
  const COL = compact ? 158 : 250, NODE_W = compact ? 134 : 210;
  const [depth, setDepth] = useState(compact ? 1 : 2);
  const [dir, setDir] = useState<"both" | "callers" | "callees">("both");
  const start = center ?? order[0] ?? null;
  const [zoom, setZoom] = useState(1);
  const [panning, setPanning] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; left: number; top: number; moved: boolean } | null>(null);
  const clamp = (z: number) => Math.min(2, Math.max(0.2, z));

  // Ctrl/pinch-wheel zooms around the cursor; a plain wheel scrolls as usual.
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      const r = el.getBoundingClientRect();
      const px = e.clientX - r.left, py = e.clientY - r.top;
      setZoom((z) => {
        const nz = clamp(z * Math.exp(-e.deltaY * 0.01));
        const k = nz / z;
        el.scrollLeft = (el.scrollLeft + px) * k - px;
        el.scrollTop = (el.scrollTop + py) * k - py;
        return nz;
      });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  });

  // Drag anywhere on the canvas to pan; a drag that moved never counts as a node click.
  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    const el = e.currentTarget;
    drag.current = { x: e.clientX, y: e.clientY, left: el.scrollLeft, top: el.scrollTop, moved: false };
  };
  const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d) return;
    const dx = e.clientX - d.x, dy = e.clientY - d.y;
    if (!d.moved) {
      if (Math.abs(dx) + Math.abs(dy) < 4) return;
      d.moved = true;
      setPanning(true);
      e.currentTarget.setPointerCapture(e.pointerId);
    }
    e.currentTarget.scrollLeft = d.left - dx;
    e.currentTarget.scrollTop = d.top - dy;
  };
  const endDrag = () => { setPanning(false); };
  const onClickCapture = (e: React.MouseEvent) => {
    if (drag.current?.moved) { e.stopPropagation(); e.preventDefault(); }
    drag.current = null;
  };

  const layout = useMemo(() => {
    if (start === null) return null;
    const level = new Map<number, number>([[start, 0]]);
    const hidden = new Map<number, number>(); // level -> nodes dropped for space
    const walk = (sign: 1 | -1, edges: Map<number, number[]>) => {
      let frontier = [start];
      for (let d = 1; d <= depth; d++) {
        const next: number[] = [];
        for (const f of frontier) for (const c of edges.get(f) ?? []) if (!level.has(c)) { level.set(c, sign * d); next.push(c); }
        const keep = next.slice(0, MAX_PER_LEVEL);
        for (const dropped of next.slice(MAX_PER_LEVEL)) level.delete(dropped);
        if (next.length > keep.length) hidden.set(sign * d, next.length - keep.length);
        frontier = keep;
      }
    };
    if (dir !== "callers") walk(1, callees);
    if (dir !== "callees") walk(-1, callers);
    const byLevel = new Map<number, number[]>();
    for (const [id, l] of level) byLevel.set(l, [...(byLevel.get(l) ?? []), id]);
    const nodes = new Map<number, Node>();
    for (const [l, ids] of byLevel) ids.sort((x, y) => x - y).forEach((id, row) => nodes.set(id, { id, level: l, row }));
    const levels = [...byLevel.keys()];
    const minL = Math.min(...levels), maxL = Math.max(...levels);
    const rowsMax = Math.max(...[...byLevel.values()].map((v) => v.length + 0));
    const edges: [number, number][] = [];
    for (const id of nodes.keys()) for (const c of callees.get(id) ?? []) if (nodes.has(c) && c !== id) edges.push([id, c]);
    return { nodes, edges, minL, maxL, rowsMax, hidden };
  }, [start, depth, dir, callees, callers]);

  if (!ready) return <div className="view"><h1>Call graph</h1><p className="fine">Calls are known once decompilation finishes.</p></div>;
  if (!layout || start === null) return <div className="view"><h1>Call graph</h1><p className="empty">No functions.</p></div>;
  const { nodes, edges, minL, maxL, rowsMax, hidden } = layout;
  const x = (l: number) => PAD + (l - minL) * COL;
  const y = (r: number) => PAD + 28 + r * (NODE_H + GAP);
  const width = PAD * 2 + (maxL - minL) * COL + NODE_W, height = PAD * 2 + 28 + rowsMax * (NODE_H + GAP) + 20;
  const total = nodes.size;

  return (
    <div className={"cg" + (compact ? " compact" : "")}>
      <div className="cg-bar">
        <label>Depth
          <select value={depth} onChange={(e) => setDepth(Number(e.target.value))}>{[1, 2, 3, 4].map((d) => <option key={d} value={d}>{d}</option>)}</select>
        </label>
        <div className="seg">
          {(["callers", "both", "callees"] as const).map((d) => <button key={d} className={dir === d ? "on" : ""} onClick={() => setDir(d)}>{d === "both" ? "Both" : d === "callers" ? "Callers" : "Callees"}</button>)}
        </div>
        <div className="seg">
          <button onClick={() => setZoom((z) => clamp(z / 1.25))} aria-label="Zoom out">−</button>
          <button onClick={() => setZoom(1)} aria-label="Reset zoom">{Math.round(zoom * 100)}%</button>
          <button onClick={() => setZoom((z) => clamp(z * 1.25))} aria-label="Zoom in">+</button>
        </div>
        <span className="fine">{total} functions · {compact ? "click to open" : "drag to move, click to re-center, double-click to open"}</span>
      </div>
      <div className={"cg-scroll" + (panning ? " panning" : "")} ref={scroller}
        onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={endDrag} onPointerCancel={() => { drag.current = null; endDrag(); }}
        onClickCapture={onClickCapture}>
        <svg width={width * zoom} height={height * zoom} viewBox={`0 0 ${width} ${height}`} role="group" aria-label="Call graph">
          <defs><marker id="cg-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L8 4L0 8z" className="cg-head" /></marker></defs>
          {[...new Set([...nodes.values()].map((n) => n.level))].sort((p, q) => p - q).map((l) => (
            <text key={l} x={x(l)} y={PAD + 8} className="cg-col">{l === 0 ? "selected" : l < 0 ? `callers ${-l}` : `callees ${l}`}</text>
          ))}
          {edges.map(([from, to], i) => {
            const f = nodes.get(from)!, t = nodes.get(to)!;
            const forward = t.level > f.level;
            const x1 = forward ? x(f.level) + NODE_W : x(f.level), y1 = y(f.row) + NODE_H / 2;
            const x2 = forward ? x(t.level) : x(t.level) + NODE_W, y2 = y(t.row) + NODE_H / 2;
            const mid = (x1 + x2) / 2;
            const focus = from === start || to === start;
            return <path key={i} d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`} className={"cg-edge" + (focus ? " focus" : "")} markerEnd="url(#cg-arrow)" />;
          })}
          {[...nodes.values()].map((nd) => {
            const c = caps(nd.id);
            return (
              <g key={nd.id} className={"cg-node" + (nd.id === start ? " center" : "") + (c.length ? " caps" : "")} transform={`translate(${x(nd.level)},${y(nd.row)})`}
                role="button" tabIndex={0} aria-label={label(nd.id)}
                onClick={() => setCenter(nd.id)} onDoubleClick={() => onOpen(nd.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setCenter(nd.id); } }}>
                <title>{label(nd.id)} {hex(nd.id)}{c.length ? "\n" + c.join("\n") : ""}</title>
                <rect width={NODE_W} height={NODE_H} rx={7} />
                <text x={10} y={18}>{label(nd.id).length > (compact ? 15 : 24) ? label(nd.id).slice(0, compact ? 14 : 23) + "…" : label(nd.id)}</text>
                {c.length > 0 && !compact && <text x={NODE_W - 10} y={18} textAnchor="end" className="cg-n">{c.length} capa</text>}
              </g>
            );
          })}
          {[...hidden].map(([l, count]) => <text key={"h" + l} x={x(l)} y={y(rowsMax) + 8} className="cg-col">+{count} more at this level</text>)}
        </svg>
      </div>
    </div>
  );
}
