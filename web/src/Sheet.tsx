import { useEffect, useRef } from "react";

/**
 * A bottom sheet for phones: dim backdrop, grab handle, swipe down or tap outside to close.
 * It stays inside thumb reach, unlike a popover anchored to a corner button.
 */
export default function Sheet({ title, onClose, children }: { title?: string; onClose: () => void; children: React.ReactNode }) {
  const panel = useRef<HTMLDivElement>(null);
  const drag = useRef<{ y: number; dy: number } | null>(null);
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", esc);
    const opener = document.activeElement as HTMLElement | null;
    return () => { document.removeEventListener("keydown", esc); opener?.focus?.(); };
  }, [onClose]);
  const move = (y: number) => {
    if (!drag.current) return;
    drag.current.dy = Math.max(0, y - drag.current.y);
    if (panel.current) { panel.current.style.transition = "none"; panel.current.style.transform = `translateY(${drag.current.dy}px)`; }
  };
  const end = () => {
    const d = drag.current; drag.current = null;
    if (!d || !panel.current) return;
    panel.current.style.transition = "";
    if (d.dy > 90) onClose(); else panel.current.style.transform = "";
  };
  return (
    <div className="sheet-back" onPointerDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="sheet" role="dialog" aria-modal="true" aria-label={title} ref={panel}>
        <div className="sheet-grab"
          onPointerDown={(e) => { drag.current = { y: e.clientY, dy: 0 }; e.currentTarget.setPointerCapture(e.pointerId); }}
          onPointerMove={(e) => move(e.clientY)} onPointerUp={end} onPointerCancel={end}>
          <i />
        </div>
        {title && <h2 className="sheet-title">{title}</h2>}
        <div className="sheet-body">{children}</div>
      </div>
    </div>
  );
}
