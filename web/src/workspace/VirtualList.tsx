import { useCallback, useEffect, useImperativeHandle, useLayoutEffect, useMemo, useRef, useState, type ReactNode, type Ref } from "react";

export interface VirtualListHandle { scrollToIndex: (index: number, center?: boolean) => void }

/** A long list that renders only the rows in view and keeps the selected row showing. Rows may differ in height. */
export default function VirtualList<T>({ items, rowHeight, render, selected, empty, className = "", listRef, scrollParent, overlay }: {
  items: T[]; rowHeight: number | ((item: T, index: number) => number); render: (item: T, index: number) => ReactNode; selected?: number; empty?: ReactNode; className?: string;
  listRef?: Ref<VirtualListHandle>;
  /** A full-height layer, with the visible range available for culling its contents. */
  overlay?: (top: number, height: number) => ReactNode;
  /** Use an existing scroll pane instead of making this list a scroll container. */
  scrollParent?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0), [height, setHeight] = useState(600);
  const scroller = useCallback(() => scrollParent ? box.current?.closest<HTMLElement>(scrollParent) : box.current, [scrollParent]);
  const offset = (el: HTMLElement) => el === box.current ? 0 : box.current!.getBoundingClientRect().top - el.getBoundingClientRect().top + el.scrollTop - el.clientTop;
  // offsets[i] is where row i starts; the last entry is the total height.
  const offsets = useMemo(() => {
    const out = new Float64Array(items.length + 1);
    for (let i = 0; i < items.length; i++) out[i + 1] = out[i] + (typeof rowHeight === "number" ? rowHeight : rowHeight(items[i], i));
    return out;
  }, [items, rowHeight]);
  const rowAt = (y: number) => {
    let lo = 0, hi = items.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (offsets[mid + 1] <= y) lo = mid + 1; else hi = mid; }
    return lo;
  };
  const scrollToIndex = useCallback((index: number, center = false) => {
    const el = scroller();
    if (!el || index < 0 || index >= items.length) return;
    const start = offset(el), y = start + offsets[index], h = offsets[index + 1] - offsets[index];
    if (center) el.scrollTop = Math.max(0, y - (el.clientHeight - h) / 2);
    else if (y < el.scrollTop) el.scrollTop = y;
    else if (y + h > el.scrollTop + el.clientHeight) el.scrollTop = y + h - el.clientHeight;
    setTop(el.scrollTop - start);
  }, [scroller, offsets, items.length]);
  useImperativeHandle(listRef, () => ({ scrollToIndex }), [scrollToIndex]);
  useLayoutEffect(() => {
    const el = scroller();
    if (!el) return;
    const measure = () => { setHeight(el.clientHeight); setTop(el.scrollTop - offset(el)); };
    measure();
    el.addEventListener("scroll", measure, { passive: true });
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    if (box.current !== el) ro.observe(box.current!);
    return () => { el.removeEventListener("scroll", measure); ro.disconnect(); };
  }, [scroller]);
  // Bring the selected row into view when the selection changes, not on every scroll.
  useEffect(() => {
    const el = scroller();
    if (!el || selected === undefined || selected < 0 || selected >= items.length) return;
    const start = offset(el), y = start + offsets[selected], h = offsets[selected + 1] - offsets[selected];
    if (y < el.scrollTop || y + h > el.scrollTop + el.clientHeight) { el.scrollTop = Math.max(0, y - el.clientHeight / 3); setTop(el.scrollTop - start); }
  }, [selected]); // eslint-disable-line react-hooks/exhaustive-deps
  const first = Math.max(0, rowAt(top) - 6), last = Math.min(items.length, rowAt(top + height) + 7);
  const rows: ReactNode[] = [];
  for (let i = first; i < last; i++) rows.push(<div className="vrow" key={i} style={{ top: offsets[i], height: offsets[i + 1] - offsets[i] }}>{render(items[i], i)}</div>);
  return (
    <div className={(scrollParent ? "" : "list virtual ") + className} ref={box}>
      {items.length ? <div style={{ height: offsets[items.length], position: "relative" }}>{overlay?.(top, height)}{rows}</div> : empty}
    </div>
  );
}
