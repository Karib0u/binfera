import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";
import { panesOf, VIEW_NAMES, type CodeView } from "./location";
import { Splitter } from "./panels";
import { toast } from "../Toast";
import { applyLayout, dropSideAt, movePane, panesIn, peekTree, splitPane, treeOf, updatePane, withoutPane, type Axis, type DropSide, type Pane, type PanePlace, type PaneTree } from "./paneTree";

export type { PanePlace } from "./paneTree";
export interface PaneRenderer {
  (view: CodeView, place: PanePlace, navigate: (va: number) => void, active: boolean, asm: {
    onShowAsm: (va: number) => void; asmJump?: { va: number };
  }): ReactNode;
}

function ViewIcon({ view }: { view: CodeView }) {
  return <svg className="pane-type-icon" viewBox="0 0 20 20" aria-hidden>
    {view === "graph" || view === "calls" ? <><rect x="7" y="2" width="6" height="4" rx="1" /><rect x="2" y="14" width="5" height="4" rx="1" /><rect x="13" y="14" width="5" height="4" rx="1" /><path d="M10 6v4H4.5v4M10 10h5.5v4" /></>
      : view === "strings" ? <path d="M3 5h14M10 5v11M7 16h6" />
        : view === "hex" ? <path d="M7 3L5 17M14 3l-2 14M3 7h14M2 13h14" />
          : view === "imports" ? <path d="M11 3h6v14h-6M2 10h10M8 6l4 4-4 4" />
            : <path d="M7 5l-4 5 4 5M13 5l4 5-4 5" />}
  </svg>;
}

function minimum(node: PaneTree): { width: number; height: number } {
  if ("view" in node) return { width: 200, height: 120 };
  const a = minimum(node.first), b = minimum(node.second);
  return node.axis === "vertical" ? { width: a.width + b.width, height: Math.max(a.height, b.height) }
    : { width: Math.max(a.width, b.width), height: a.height + b.height };
}

function SplitGroup({ node, onChange, render }: { node: PaneTree; onChange: (tree: PaneTree) => void; render: (pane: Pane) => ReactNode }) {
  const box = useRef<HTMLDivElement>(null);
  const [extent, setExtent] = useState(0);
  const horizontal = !("view" in node) && node.axis === "horizontal";
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => setExtent(horizontal ? el.clientHeight : el.clientWidth);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, [horizontal, "view" in node]);
  if ("view" in node) return render(node);
  const firstMin = minimum(node.first), secondMin = minimum(node.second);
  const min = horizontal ? firstMin.height : firstMin.width, max = extent - (horizontal ? secondMin.height : secondMin.width);
  const ratio = extent ? Math.max(min / extent, Math.min(max / extent, node.ratio)) : node.ratio;
  return <div className={"pane-split" + (horizontal ? " horizontal" : "")} ref={box}>
    <div className="pane-branch" style={{ flex: ratio }}><SplitGroup node={node.first} onChange={(first) => onChange({ ...node, first })} render={render} /></div>
    <div className="pane-branch" style={{ flex: 1 - ratio }}><SplitGroup node={node.second} onChange={(second) => onChange({ ...node, second })} render={render} /></div>
    <Splitter horizontal={horizontal} label={horizontal ? "Resize horizontal split" : "Resize vertical split"} value={extent * ratio} min={min} max={Math.max(min, max)}
      style={horizontal ? { top: extent * ratio, bottom: "auto" } : { left: extent * ratio }} onChange={(value) => { if (extent) onChange({ ...node, ratio: value / extent }); }} onReset={() => onChange({ ...node, ratio: .5 })} />
  </div>;
}

function savedTree(layout: string): PaneTree | null {
  try {
    const tree = JSON.parse(localStorage.getItem("binfera-ui:pane-tree") ?? "null");
    const valid = (n: any, depth = 0): boolean => n && depth < 40 && ("view" in n
      ? Number.isSafeInteger(n.id) && n.id >= 0 && Object.hasOwn(VIEW_NAMES, n.view)
      : (n.axis === "vertical" || n.axis === "horizontal") && Number.isFinite(n.ratio) && n.ratio > 0 && n.ratio < 1 && valid(n.first, depth + 1) && valid(n.second, depth + 1));
    if (!valid(tree)) return null;
    const panes = panesIn(tree);
    if (panes.map((p) => p.view).join("+") !== panesOf(layout).join("+") || new Set(panes.map((p) => p.id)).size !== panes.length) return null;
    return panes.reduce((t, p) => updatePane(t, p.id, (pane) => ({ ...pane, place: null })), tree as PaneTree);
  } catch { return null; }
}

/** Linked panes share a location; independent panes keep their own location when moved. */
export default function CodePanes({ layout, setLayout, place, onNavigate, locate, render, fileName, fileTitle = fileName, label, outside, peek, peekSeen }: {
  layout: string; setLayout: (v: string) => void; place: PanePlace; onNavigate: (va: number, fn?: number) => void;
  locate: (va: number, current: PanePlace) => PanePlace; render: PaneRenderer; fileName: string; fileTitle?: string; label: (va: number) => string;
  /** Where the cursor is when it is not inside the function a pane shows (a header, data, another function); null when it is inside. */
  outside?: (fn: number, va: number) => string | null;
  /** Show a view the analyst did not open (bytes, a string, an import): bumped by the workspace. */
  peek?: { view: CodeView; n: number } | null;
  /** The last peek request handled, kept by the workspace so a request made before these panes mounted still lands. */
  peekSeen?: React.MutableRefObject<number>;
}) {
  const [tree, setTree] = useState<PaneTree>(() => savedTree(layout) ?? treeOf(panesOf(layout).map((view, id) => ({ id, view, place: null }))));
  const nextId = useRef(Math.max(...panesIn(tree).map((p) => p.id)) + 1);
  const [active, setActive] = useState<number | null>(null);
  const [asmJump, setAsmJump] = useState<{ id: number; va: number } | null>(null);
  // A jump also reveals the instruction when the shared cursor is already there.
  useEffect(() => { if (asmJump) setAsmJump(null); }, [asmJump]);
  const [drag, setDrag] = useState<{ id: number; x: number; y: number; over: { id: number; side: DropSide } | null } | null>(null);
  const treeRef = useRef(tree);
  treeRef.current = tree;
  const stopDrag = useRef<(() => void) | null>(null);
  useEffect(() => () => stopDrag.current?.(), []);
  const panes = panesIn(tree), activeId = panes.some((p) => p.id === active) ? active : panes[0].id;
  // A layout set from outside (a link, a toolbar toggle, a view revealed beside the code) changes as
  // little as it can: panes that stay keep their place and size, a dropped pane's slot takes a new
  // view in place, and only views beyond that are added as a column at the right edge, around the
  // existing arrangement. Rebuilding the tree would throw that arrangement away.
  useEffect(() => { setTree((old) => applyLayout(old, panesOf(layout), () => nextId.current++)); }, [layout]);
  useEffect(() => {
    const clean = panesIn(tree).reduce((t, p) => updatePane(t, p.id, (pane) => ({ ...pane, place: null })), tree);
    try { localStorage.setItem("binfera-ui:pane-tree", JSON.stringify(clean)); } catch { /* session only */ }
  }, [tree]);
  const update = (next: PaneTree) => { setTree(next); setLayout(panesIn(next).map((p) => p.view).join("+")); };
  // A peek never rearranges the analyst's panes. A pane already showing the view is used as is; an
  // earlier peek pane switches view; otherwise one column opens at the right edge of the whole
  // workspace, outside the arrangement, so closing it gives back exactly the layout there was.
  const ownSeen = useRef(0), seen = peekSeen ?? ownSeen;
  useEffect(() => {
    if (!peek || peek.n === seen.current) return;
    seen.current = peek.n;
    const now = treeRef.current, peeked = peekTree(now, peek.view, () => nextId.current++);
    if (!peeked) return;
    update(peeked.tree);
    const reuse = peeked.reused;
    toast(reuse ? `${VIEW_NAMES[peek.view]} in the side pane` : `Opened ${VIEW_NAMES[peek.view]} at the side · close it to restore your layout`, { label: "Undo", run: () => update(now) });
  }, [peek?.n]);
  const split = (pane: Pane, axis: Axis) => {
    const added: Pane = { id: nextId.current++, view: pane.view, place: null };
    setActive(added.id);
    update(splitPane(tree, pane.id, added, axis));
  };
  /** Pointer-driven so the drag works the same everywhere: a small threshold, a live landing preview, Escape to cancel. */
  const startDrag = (e: ReactPointerEvent<HTMLElement>, pane: Pane) => {
    if (e.button !== 0 || (e.target as Element).closest("button, select, a, input") || panesIn(treeRef.current).length < 2) return;
    const sx = e.clientX, sy = e.clientY;
    let started = false;
    const hit = (x: number, y: number) => {
      const slot = document.elementFromPoint(x, y)?.closest<HTMLElement>("[data-pane-id]");
      const id = slot ? Number(slot.dataset.paneId) : NaN;
      if (!slot || id === pane.id) return null;
      const r = slot.getBoundingClientRect();
      return { id, side: dropSideAt((x - r.left) / r.width, (y - r.top) / r.height) };
    };
    const move = (ev: PointerEvent) => {
      if (!started) {
        if (Math.hypot(ev.clientX - sx, ev.clientY - sy) < 6) return;
        started = true;
        document.body.classList.add("pane-dragging");
      }
      setDrag({ id: pane.id, x: ev.clientX, y: ev.clientY, over: hit(ev.clientX, ev.clientY) });
    };
    const end = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up, true);
      window.removeEventListener("pointercancel", cancel, true);
      window.removeEventListener("keydown", key, true);
      document.body.classList.remove("pane-dragging");
      stopDrag.current = null;
      setDrag(null);
    };
    const up = (ev: PointerEvent) => {
      const over = started ? hit(ev.clientX, ev.clientY) : null;
      end();
      if (over) { setActive(pane.id); update(movePane(treeRef.current, pane.id, over.id, over.side)); }
    };
    const cancel = () => end();
    const key = (ev: KeyboardEvent) => { if (ev.key === "Escape") { ev.stopPropagation(); end(); } };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up, true);
    window.addEventListener("pointercancel", cancel, true);
    window.addEventListener("keydown", key, true);
    stopDrag.current = end;
  };
  const minSize = minimum(tree);
  return <div className={"code-panes" + (drag ? " is-dragging" : "")}><div className="pane-surface" style={{ minWidth: minSize.width, minHeight: minSize.height }}>
    <SplitGroup node={tree} onChange={update} render={(pane) => {
      const here = pane.place ?? place;
      const over = drag?.over?.id === pane.id ? drag.over : null;
      const go = (va: number) => {
        if (pane.place === null) onNavigate(va);
        else setTree((t) => updatePane(t, pane.id, (p) => ({ ...p, place: locate(va, here) })));
      };
      const onShowAsm = (va: number) => {
        let id = pane.id;
        if (pane.place) {
          update(updatePane(tree, id, (p) => ({ ...p, view: "asm", place: { address: here.address, cursor: va } })));
        } else {
          const existing = panes.find((p) => p.view === "asm" && p.place === null);
          id = existing?.id ?? nextId.current++;
          if (!existing) update(splitPane(tree, pane.id, { id, view: "asm", place: null }, "vertical"));
          onNavigate(va, here.address);
        }
        setActive(id);
        setAsmJump({ id, va });
      };
      const away = here.cursor != null ? outside?.(here.address, here.cursor) ?? null : null;
      return <section key={pane.id} data-pane-id={pane.id} className={"cp-slot editor-group" + (pane.place ? " unlinked" : "") + (activeId === pane.id ? " is-active" : "") + (drag?.id === pane.id ? " is-lifted" : "")} aria-label={VIEW_NAMES[pane.view] + " pane"}
        onPointerDownCapture={() => setActive(pane.id)} onFocusCapture={() => setActive(pane.id)}>
        <div className="editor-group-head" onPointerDown={(e) => startDrag(e, pane)}>
          <span className="pane-grip" title="Drag to rearrange" aria-hidden><svg viewBox="0 0 12 16"><path d="M4 4h.01M8 4h.01M4 8h.01M8 8h.01M4 12h.01M8 12h.01" /></svg></span>
          <ViewIcon view={pane.view} />
          <div className="pane-view-picker"><select className="pane-view" aria-label="Pane view" title="Change pane view" value={pane.view} onChange={(e) => update(updatePane(tree, pane.id, (p) => ({ ...p, view: e.target.value as CodeView, peek: false })))}>
            {(Object.keys(VIEW_NAMES) as CodeView[]).map((v) => <option key={v} value={v}>{VIEW_NAMES[v]}</option>)}
          </select><svg viewBox="0 0 12 12" aria-hidden><path d="M3 4.5l3 3 3-3" /></svg></div>
          <div className="pane-actions">
            <button className="pane-icon pane-sync" aria-label={pane.place ? "Enable pane sync" : "Disable pane sync"} aria-pressed={pane.place === null} title={pane.place ? "Unlinked: click to sync with the workspace" : "Synced: click to navigate independently"}
              onClick={() => setTree((t) => updatePane(t, pane.id, (p) => ({ ...p, place: p.place ? null : { ...place } })))}>
              <svg viewBox="0 0 20 20" aria-hidden><path d="M8 12l4-4M6.5 13.5l-1 1a3 3 0 01-4-4l3-3a3 3 0 014 0M11.5 12.5a3 3 0 004 0l3-3a3 3 0 00-4-4l-1 1" />{pane.place && <path d="M3 2l14 16" />}</svg>
            </button>
            <button className="pane-icon" aria-label="Split right" title="Split vertically: add a pane to the right" onClick={() => split(pane, "vertical")}><svg viewBox="0 0 20 20" aria-hidden><rect x="3" y="3" width="14" height="14" rx="1" /><path d="M10 3v14" /></svg></button>
            <button className="pane-icon" aria-label="Split down" title="Split horizontally: add a pane below" onClick={() => split(pane, "horizontal")}><svg viewBox="0 0 20 20" aria-hidden><rect x="3" y="3" width="14" height="14" rx="1" /><path d="M3 10h14" /></svg></button>
            {panes.length > 1 && <button className="pane-icon" aria-label="Close pane" title="Close pane" onClick={() => { const next = withoutPane(tree, pane.id); if (next) update(next); }}><svg viewBox="0 0 20 20" aria-hidden><path d="M6 6l8 8M14 6l-8 8" /></svg></button>}
          </div>
        </div>
        {away !== null && here.cursor != null
          ? <div className="pane-breadcrumb outside" title={`The cursor is at 0x${here.cursor.toString(16)}, ${away}, not in ${label(here.address)}`}><span title={fileTitle}>{fileName}</span><i aria-hidden>›</i><code>0x{here.cursor.toString(16)}</code><em>{away}</em><button onClick={() => go(here.address)}>Back to {label(here.address)}</button></div>
          : pane.place && <div className="pane-breadcrumb" title={`${fileTitle} / ${label(here.address)} / 0x${(here.cursor ?? here.address).toString(16)}`}><span title={fileTitle}>{fileName}</span><i aria-hidden>›</i><span>{label(here.address)}</span><i aria-hidden>›</i><code>0x{(here.cursor ?? here.address).toString(16)}</code></div>}
        <div className="pane-content">{render(pane.view, here, go, activeId === pane.id, { onShowAsm, asmJump: asmJump?.id === pane.id ? asmJump : undefined })}</div>
        {over && <div className={"pane-drop-zone drop-" + over.side}><span>{over.side === "center" ? "Swap places" : `Dock ${over.side}`}</span></div>}
      </section>;
    }} />
    {drag && <div className="pane-ghost" style={{ left: drag.x + 14, top: drag.y + 14 }}>
      <ViewIcon view={panes.find((p) => p.id === drag.id)?.view ?? "c"} />{VIEW_NAMES[panes.find((p) => p.id === drag.id)?.view ?? "c"]}
    </div>}
  </div></div>;
}
