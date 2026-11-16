import { useEffect, useLayoutEffect, useRef, useState } from "react";

export type MenuEntry = { label: string; onClick: () => void; hint?: string; disabled?: boolean } | "separator";

/** A right-click menu at a point. Arrow keys move, Enter chooses, Escape or a click elsewhere closes it. */
export default function ContextMenu({ x, y, items, onClose }: { x: number; y: number; items: MenuEntry[]; onClose: () => void }) {
  const box = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x, top: y });
  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    const { width, height } = el.getBoundingClientRect();
    setPos({ left: Math.max(4, Math.min(x, innerWidth - width - 4)), top: Math.max(4, Math.min(y, innerHeight - height - 4)) });
    el.querySelector<HTMLButtonElement>("button:not(:disabled)")?.focus();
  }, [x, y]);
  useEffect(() => {
    const away = (e: Event) => { if (!box.current?.contains(e.target as Node)) onClose(); };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); return; }
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "Home" && e.key !== "End") return;
      e.preventDefault();
      const all = [...(box.current?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") ?? [])];
      if (!all.length) return;
      const i = all.indexOf(document.activeElement as HTMLButtonElement);
      all[e.key === "Home" ? 0 : e.key === "End" ? all.length - 1 : (i + (e.key === "ArrowDown" ? 1 : -1) + all.length) % all.length].focus();
    };
    document.addEventListener("pointerdown", away, true);
    document.addEventListener("keydown", key, true);
    addEventListener("blur", onClose);
    addEventListener("resize", onClose);
    addEventListener("wheel", onClose, { passive: true });
    return () => {
      document.removeEventListener("pointerdown", away, true);
      document.removeEventListener("keydown", key, true);
      removeEventListener("blur", onClose); removeEventListener("resize", onClose); removeEventListener("wheel", onClose);
    };
  }, [onClose]);
  return (
    <div className="ctxmenu" ref={box} role="menu" style={pos} onContextMenu={(e) => e.preventDefault()}>
      {items.map((it, i) => it === "separator"
        ? <hr key={i} />
        : <button key={i} role="menuitem" disabled={it.disabled} onClick={() => { onClose(); it.onClick(); }}><span>{it.label}</span>{it.hint && <kbd>{it.hint}</kbd>}</button>)}
    </div>
  );
}

export async function copyText(text: string) {
  try { await navigator.clipboard.writeText(text); return; } catch { /* fall back below */ }
  const area = Object.assign(document.createElement("textarea"), { value: text });
  area.style.position = "fixed"; area.style.opacity = "0";
  document.body.append(area);
  area.select();
  try { document.execCommand("copy"); } finally { area.remove(); }
}
