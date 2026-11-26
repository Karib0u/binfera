import { useRef, useState } from "react";
import Sheet from "./Sheet";
import { useMobile } from "./workspace/useMobile";
import { moveInMenu, openOnArrow, useMenu } from "./menu";

export interface MenuItem { label: string; onClick: () => void; disabled?: boolean }

/** The ⋯ button and its menu: a bottom sheet on a phone, a drop-down on a desktop. */
export default function MoreMenu({ items, label = "More actions" }: { items: MenuItem[]; label?: string }) {
  const [open, setOpen] = useState(false);
  const mobile = useMobile();
  const box = useRef<HTMLDivElement>(null), trigger = useRef<HTMLButtonElement>(null), menu = useRef<HTMLDivElement>(null);
  // A phone's sheet is a dialog with its own keys; the drop-down needs the menu's.
  useMenu(open, setOpen, box, trigger, menu, !mobile);
  const choose = (it: MenuItem) => () => { trigger.current?.focus(); setOpen(false); it.onClick(); };
  const list = (className: string) => (
    <div className={className} role="menu" aria-label={label} ref={menu} onKeyDown={moveInMenu}>
      {items.map((it) => <button key={it.label} role="menuitem" disabled={it.disabled} onClick={choose(it)}>{it.label}</button>)}
    </div>
  );
  return (
    <div className="more-menu" ref={box}>
      <button ref={trigger} className="m-icon" aria-label={label} title={label} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)} onKeyDown={openOnArrow(open, setOpen)}>
        <svg viewBox="0 0 24 24" aria-hidden><circle cx="5" cy="12" r="1.6" /><circle cx="12" cy="12" r="1.6" /><circle cx="19" cy="12" r="1.6" /></svg>
      </button>
      {open && mobile && <Sheet onClose={() => setOpen(false)}>{list("sheet-menu")}</Sheet>}
      {open && !mobile && list("more-sheet")}
    </div>
  );
}
