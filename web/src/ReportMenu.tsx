import { useRef, useState } from "react";
import { moveInMenu, openOnArrow, useMenu } from "./menu";

export interface ReportItem { label: string; note?: string; onClick: () => void }

/** One button for everything that leaves the app: a readable report first, then tables and the raw data. */
export default function ReportMenu({ groups, disabled }: { groups: { title: string; items: ReportItem[] }[]; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null), trigger = useRef<HTMLButtonElement>(null), menu = useRef<HTMLDivElement>(null);
  useMenu(open, setOpen, box, trigger, menu);
  return (
    <div className="dropmenu" ref={box}>
      <button ref={trigger} className="ghost" aria-haspopup="menu" aria-expanded={open} disabled={disabled} onClick={() => setOpen(!open)} onKeyDown={openOnArrow(open, setOpen)} title="Save a report, or the analysis as tables">Report <span aria-hidden>▾</span></button>
      {open && (
        <div className="dropsheet" role="menu" aria-label="Report" ref={menu} onKeyDown={moveInMenu}>
          {groups.map((g) => (
            <div key={g.title} role="group" aria-label={g.title}>
              <div className="drop-title" aria-hidden>{g.title}</div>
              {g.items.map((it) => (
                <button key={it.label + (it.note ?? "")} role="menuitem" onClick={() => { trigger.current?.focus(); setOpen(false); it.onClick(); }}>
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
