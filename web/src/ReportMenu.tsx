import { useEffect, useRef, useState } from "react";

export interface ReportItem { label: string; note?: string; onClick: () => void }

/** One button for everything that leaves the app: a readable report first, then tables and the raw data. */
export default function ReportMenu({ groups, disabled }: { groups: { title: string; items: ReportItem[] }[]; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: Event) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("pointerdown", close);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("pointerdown", close); document.removeEventListener("keydown", esc); };
  }, [open]);
  return (
    <div className="dropmenu" ref={box}>
      <button className="ghost" aria-haspopup="menu" aria-expanded={open} disabled={disabled} onClick={() => setOpen((o) => !o)} title="Save a report, or the analysis as tables">Report <span aria-hidden>▾</span></button>
      {open && (
        <div className="dropsheet" role="menu">
          {groups.map((g) => (
            <div key={g.title} role="group" aria-label={g.title}>
              <div className="drop-title">{g.title}</div>
              {g.items.map((it) => (
                <button key={it.label} role="menuitem" onClick={() => { setOpen(false); it.onClick(); }}>
                  <span>{it.label}</span>{it.note && <small>{it.note}</small>}
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
