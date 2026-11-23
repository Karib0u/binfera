import { useEffect, useMemo, useRef, useState } from "react";
import { useKeyboardInset } from "./keyboard";

export interface PaletteItem { kind: string; title: string; detail?: string; run: () => void }

const SCOPES = [["", "All"], ["f", "Functions"], ["s", "Strings"], ["c", "Code"], ["a", "Asm"], ["i", "Imports"], ["x", "References"]] as const;
const SCOPED = /^([cafsix]):\s*/i;

/** One box for everything: functions, strings, imports, exports, capabilities, and addresses to go to. */
export default function Palette({ initial, search, onClose, placeholder }: { initial: string; search: (q: string) => PaletteItem[]; onClose: () => void;
  /** A palette for choosing one thing: this prompt instead of the search scopes. */
  placeholder?: string }) {
  useKeyboardInset();
  const [q, setQ] = useState(initial);
  const [i, setI] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    input.current?.focus();
    input.current?.setSelectionRange(q.length, q.length);
    return () => before?.focus?.();
  }, []);
  const items = useMemo(() => search(q), [q, search]);
  useEffect(() => setI(0), [q]);
  const go = (it?: PaletteItem) => { if (!it) return; onClose(); it.run(); };
  const scope = SCOPED.exec(q)?.[1].toLowerCase() ?? "";
  const pick = (s: string) => { setQ((s ? s + ": " : "") + q.replace(SCOPED, "")); input.current?.focus(); };
  const empty = !q.replace(SCOPED, "").trim() ? (scope === "x" ? "Type an address." : "Start typing, or enter an address.") : (scope === "c" || scope === "a") && q.replace(SCOPED, "").trim().length < 3 ? "Type at least 3 characters." : "No matches.";
  return (
    <div className="palette-back" onMouseDown={onClose}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Search" onMouseDown={(e) => e.stopPropagation()}>
        <input
          ref={input} value={q} placeholder={placeholder ?? "Search, or type an address"} role="combobox" aria-expanded={items.length > 0} aria-controls="palette-list" aria-autocomplete="list"
          aria-activedescendant={items[i] ? `palette-${i}` : undefined} aria-label="Search functions, strings, code and addresses"
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") onClose();
            else if (e.key === "Tab") e.preventDefault();
            else if (e.key === "ArrowDown") { e.preventDefault(); setI((n) => Math.min(items.length - 1, n + 1)); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setI((n) => Math.max(0, n - 1)); }
            else if (e.key === "Enter") go(items[i]);
          }}
        />
        {!placeholder && <div className="palette-scopes" role="group" aria-label="Search in">
          {SCOPES.map(([s, name]) => <button key={s} tabIndex={-1} className={scope === s ? "on" : ""} aria-pressed={scope === s} onMouseDown={(e) => e.preventDefault()} onClick={() => pick(s)} title={s ? `Type ${s}: to search here` : undefined}>{name}</button>)}
        </div>}
        <div className="palette-list" id="palette-list" role="listbox">
          {items.map((it, n) => (
            <button key={n} id={`palette-${n}`} role="option" aria-selected={n === i} tabIndex={-1} className={n === i ? "on" : ""} onMouseMove={() => setI(n)} onClick={() => go(it)} ref={(el) => { if (el && n === i) el.scrollIntoView({ block: "nearest" }); }}>
              <i>{it.kind}</i><span>{it.title}</span>{it.detail && <code>{it.detail}</code>}
            </button>
          ))}
          {!items.length && <p className="fine" style={{ padding: 14 }}>{empty}</p>}
        </div>
      </div>
    </div>
  );
}
