import { useEffect, useRef, useState } from "react";
import Sheet from "./Sheet";
import { useMobile } from "./workspace/useMobile";

export interface MenuItem { label: string; onClick: () => void; disabled?: boolean }

/** The ⋯ button and the sheet it opens, for actions a phone screen has no room to show. */
export default function MoreMenu({ items }: { items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const mobile = useMobile();
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open || mobile) return;
    const close = (e: Event) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("pointerdown", close);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("pointerdown", close); document.removeEventListener("keydown", esc); };
  }, [open, mobile]);
  return (
    <div className="more-menu" ref={box}>
      <button className="m-icon" aria-label="More actions" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <svg viewBox="0 0 24 24" aria-hidden><circle cx="5" cy="12" r="1.6" /><circle cx="12" cy="12" r="1.6" /><circle cx="19" cy="12" r="1.6" /></svg>
      </button>
      {open && mobile && (
        <Sheet onClose={() => setOpen(false)}>
          <div className="sheet-menu" role="menu">
            {items.map((it) => (
              <button key={it.label} role="menuitem" disabled={it.disabled} onClick={() => { setOpen(false); it.onClick(); }}>{it.label}</button>
            ))}
          </div>
        </Sheet>
      )}
      {open && !mobile && (
        <div className="more-sheet" role="menu">
          {items.map((it) => (
            <button key={it.label} role="menuitem" disabled={it.disabled} onClick={() => { setOpen(false); it.onClick(); }}>{it.label}</button>
          ))}
        </div>
      )}
    </div>
  );
}
