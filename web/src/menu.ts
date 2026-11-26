import { useEffect, type RefObject } from "react";

const itemsIn = (menu: HTMLElement) => [...menu.querySelectorAll<HTMLElement>('[role="menuitem"]:not(:disabled)')];

/** Arrow keys, Home and End move between a menu's items, wrapping at either end. For the menu's onKeyDown. */
export function moveInMenu(e: React.KeyboardEvent<HTMLElement>) {
  const items = itemsIn(e.currentTarget);
  if (!items.length) return;
  const i = items.indexOf(document.activeElement as HTMLElement);
  const next = e.key === "ArrowDown" ? (i + 1) % items.length
    : e.key === "ArrowUp" ? (i <= 0 ? items.length - 1 : i - 1)
    : e.key === "Home" ? 0 : e.key === "End" ? items.length - 1 : -1;
  if (next < 0) return;
  e.preventDefault();
  e.stopPropagation();
  items[next].focus();
}

/** ArrowDown or ArrowUp on a closed menu's button opens it, as Enter and Space do. */
export const openOnArrow = (open: boolean, setOpen: (v: boolean) => void) => (e: React.KeyboardEvent) => {
  if (open || (e.key !== "ArrowDown" && e.key !== "ArrowUp")) return;
  e.preventDefault();
  setOpen(true);
};

/**
 * A drop-down menu while it is open: its first item takes focus; a click outside closes it; Escape closes it
 * and puts focus back on its button; Tab from an item closes it on the button too, so focus is never lost.
 */
export function useMenu(open: boolean, setOpen: (v: boolean) => void, box: RefObject<HTMLElement | null>, trigger: RefObject<HTMLElement | null>, menu: RefObject<HTMLElement | null>, enabled = true) {
  useEffect(() => {
    if (!open || !enabled) return;
    if (menu.current) itemsIn(menu.current)[0]?.focus();
    const outside = (e: Event) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); setOpen(false); trigger.current?.focus(); }
      else if (e.key === "Tab" && menu.current?.contains(document.activeElement)) { e.preventDefault(); setOpen(false); trigger.current?.focus(); }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", key);
    return () => { document.removeEventListener("pointerdown", outside); document.removeEventListener("keydown", key); };
  }, [open, enabled]);
}
