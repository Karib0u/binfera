import { useCallback, useEffect, useRef, useState } from "react";

/** Reveal a selection inside its pane without scrolling the surrounding workspace. */
export function revealIn(container: HTMLElement | null | undefined, selector: string, center = false) {
  const target = container?.querySelector<HTMLElement>(selector);
  if (!container || !target) return;
  const row = target.getBoundingClientRect(), box = container.getBoundingClientRect();
  if (center || row.top < box.top || row.bottom > box.bottom) container.scrollTop += row.top - box.top - (center ? (container.clientHeight - row.height) / 2 : 0);
}

/** A layout preference kept in this browser. */
export function useStored<T>(key: string, initial: T): [T, (v: T) => void] {
  const [value, set] = useState<T>(() => {
    try { const raw = localStorage.getItem("binfera-ui:" + key); return raw === null ? initial : JSON.parse(raw) as T; } catch { return initial; }
  });
  const put = useCallback((v: T) => { set(v); try { localStorage.setItem("binfera-ui:" + key, JSON.stringify(v)); } catch { /* lasts for this tab */ } }, [key]);
  return [value, put];
}

export function useMedia(query: string) {
  const [matches, setMatches] = useState(() => matchMedia(query).matches);
  useEffect(() => {
    const mq = matchMedia(query);
    const onChange = () => setMatches(mq.matches);
    onChange();
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}

/** The current width of an element; 0 until it is measured. */
export function useWidth<T extends HTMLElement>() {
  const [el, ref] = useState<T | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    if (!el) return;
    setWidth(el.clientWidth);
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    return () => ro.disconnect();
  }, [el]);
  return [ref, width] as const;
}

/** A draggable divider between two panes; the arrow keys move it too. `invert` is for a pane sized from the right. */
export function Splitter({ label, value, min, max, onChange, invert, style, horizontal = false, onReset }: {
  label: string; onReset?: () => void; value: number; min: number; max: number; onChange: (v: number) => void; invert?: boolean; style: React.CSSProperties; horizontal?: boolean;
}) {
  const start = useRef<{ x: number; v: number } | null>(null);
  const clamp = (v: number) => Math.round(Math.min(max, Math.max(min, v)));
  const end = () => { start.current = null; document.body.classList.remove("resizing"); };
  return (
    <div className={"splitter" + (horizontal ? " horizontal" : "")} role="separator" aria-orientation={horizontal ? "horizontal" : "vertical"} aria-label={label} tabIndex={0} style={style}
      aria-valuenow={Math.round(value)} aria-valuemin={Math.round(min)} aria-valuemax={Math.round(max)}
      onPointerDown={(e) => { e.preventDefault(); e.currentTarget.setPointerCapture(e.pointerId); start.current = { x: horizontal ? e.clientY : e.clientX, v: value }; document.body.classList.add("resizing"); }}
      onPointerMove={(e) => { if (start.current) { const d = (horizontal ? e.clientY : e.clientX) - start.current.x; onChange(clamp(start.current.v + (invert ? -d : d))); } }}
      onPointerUp={end} onPointerCancel={end} onDoubleClick={onReset} title={onReset ? "Drag to resize, double-click to reset" : undefined}
      onKeyDown={(e) => {
        if (horizontal ? e.key !== "ArrowUp" && e.key !== "ArrowDown" : e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
        e.preventDefault();
        onChange(clamp(value + ((e.key === "ArrowRight" || e.key === "ArrowDown") !== !!invert ? 16 : -16)));
      }} />
  );
}
