import { rowFlow, type Arch, type AsmRow } from "./graph";

/** A branch to another instruction of the same function, as IDA draws them beside its text views. */
export interface Arrow { from: number; to: number; kind: "jump" | "cond"; lane: number }

const LANE = 8, PAD = 12;
export const MAX_ARROW_LANES = 8;
export const gutterWidth = (lanes: number) => (lanes ? PAD + lanes * LANE : 0);

/** The branches inside one function. Shorter ones take the lanes nearest the text, so nested branches do not cross. */
export function functionArrows(rows: AsmRow[], arch: Arch): Arrow[] {
  const own = new Set(rows.map((r) => r[0])), found: Omit<Arrow, "lane">[] = [];
  for (const row of rows) {
    const { kind, target } = rowFlow(row, arch);
    if ((kind === "jump" || kind === "cond") && target !== undefined && target !== row[0] && own.has(target)) found.push({ from: row[0], to: target, kind });
  }
  found.sort((x, y) => Math.abs(x.to - x.from) - Math.abs(y.to - y.from));
  const lanes: [number, number][][] = [];
  return found.map((b) => {
    const lo = Math.min(b.from, b.to), hi = Math.max(b.from, b.to);
    let lane = lanes.findIndex((l) => !l.some(([p, q]) => lo <= q && p <= hi));
    if (lane < 0) lane = Math.min(lanes.length, MAX_ARROW_LANES - 1);
    (lanes[lane] ??= []).push([lo, hi]);
    return { ...b, lane };
  });
}

const arrowCache = new WeakMap<AsmRow[], { arch: Arch; arrows: Arrow[] }>();

export function cachedFunctionArrows(rows: AsmRow[], arch: Arch): Arrow[] {
  const cached = arrowCache.get(rows);
  if (cached?.arch === arch) return cached.arrows;
  const arrows = functionArrows(rows, arch);
  arrowCache.set(rows, { arch, arrows });
  return arrows;
}

/** Draws arrows between rows, given each one's y; clicking an arrow goes to its other end. */
export function ArrowPaths({ arrows, width, active, onPick, visible }: {
  visible?: { top: number; bottom: number };
  arrows: (Arrow & { y1: number; y2: number })[]; width: number; active: Set<number>; onPick: (address: number, e: React.MouseEvent) => void;
}) {
  return (
    <>
      {arrows.map((r) => {
        if (visible && (Math.max(r.y1, r.y2) < visible.top || Math.min(r.y1, r.y2) > visible.bottom)) return null;
        const x = width - PAD + 4 - r.lane * LANE, on = active.has(r.from) || active.has(r.to);
        const line = `M${width} ${r.y1} H${x} V${r.y2} H${width - 2}`;
        const color = r.kind === "cond" ? "var(--c-str)" : "var(--c-fn)";
        return (
          <g key={r.from + ":" + r.to} className={"arrow" + (on ? " on" : "")} style={{ color }}>
            <title>{(r.kind === "cond" ? "Conditional branch" : "Jump") + ` from 0x${r.from.toString(16)} to 0x${r.to.toString(16)}`}</title>
            <path className="arrow-line" d={line} strokeDasharray={r.to < r.from ? "4 2" : undefined} />
            <path className="arrow-head" d={`M${width - 5} ${r.y2 - 3.5} L${width} ${r.y2} L${width - 5} ${r.y2 + 3.5} z`} />
            <path className="arrow-hit" d={line} onClick={(e) => { e.stopPropagation(); onPick(active.has(r.to) ? r.from : r.to, e); }} />
          </g>
        );
      })}
    </>
  );
}
