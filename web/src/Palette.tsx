import { useEffect, useMemo, useRef, useState } from "react";
import { useKeyboardInset } from "./keyboard";

export interface PaletteItem { kind: string; title: string; detail?: string; run: () => void }
/** A titled group of results, such as Recent or Starred. */
export interface PaletteSection { title: string; items: PaletteItem[] }

/** Search scopes in Tab order. */
const SCOPES = [["", "All"], ["f", "Functions"], ["s", "Strings"], ["c", "Code"], ["a", "Asm"], ["i", "Imports"], ["x", "References"]] as const;
const SCOPED = /^([cafsix]):\s*/i;

/** Every word of the query appears in the text, in any order. */
const matches = (text: string, q: string) => { const t = text.toLowerCase(); return q.toLowerCase().split(/\s+/).every((w) => !w || t.includes(w)); };

/**
 * One box for everything: functions, strings, imports, exports, capabilities, and addresses to go to.
 * Empty, it lists `home` (recent and starred functions, the main views). A leading `>` lists `commands`.
 */
export default function Palette({ initial, search, onClose, placeholder, home, commands }: {
  initial: string; search: (q: string) => PaletteItem[]; onClose: () => void;
  /** A palette for choosing one thing: this prompt instead of the search scopes. */
  placeholder?: string;
  /** What an empty box offers. */
  home?: () => PaletteSection[];
  /** What `>` offers. */
  commands?: () => PaletteItem[];
}) {
  useKeyboardInset();
  const [q, setQ] = useState(initial);
  const [i, setI] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const before = useRef<HTMLElement | null>(null);
  useEffect(() => {
    before.current = document.activeElement as HTMLElement | null;
    input.current?.focus();
    input.current?.setSelectionRange(q.length, q.length);
    return () => before.current?.focus?.();
  }, []);
  const commandMode = !placeholder && !!commands && q.startsWith(">");
  const sections = useMemo<PaletteSection[]>(() => {
    if (commandMode) return [{ title: "", items: commands!().filter((c) => matches(c.title + " " + (c.detail ?? ""), q.slice(1).trim())) }];
    if (!placeholder && home && !q.trim()) return home().filter((s) => s.items.length);
    return [{ title: "", items: search(q) }];
  }, [q, search, home, commands]);
  const items = useMemo(() => sections.flatMap((s) => s.items), [sections]);
  useEffect(() => setI(0), [q]);
  // Focus goes back where it was before the item runs, so a dialog the item opens returns focus there too.
  const go = (it?: PaletteItem) => { if (!it) return; before.current?.focus?.(); onClose(); it.run(); };
  const scope = commandMode ? null : SCOPED.exec(q)?.[1].toLowerCase() ?? "";
  const rest = commandMode ? q.slice(1).trimStart() : q.replace(SCOPED, "");
  const pick = (s: string) => { setQ((s ? s + ": " : "") + rest); input.current?.focus(); };
  const cycle = (by: 1 | -1) => {
    const at = SCOPES.findIndex(([s]) => s === scope);
    pick(SCOPES[at < 0 ? (by > 0 ? 0 : SCOPES.length - 1) : (at + by + SCOPES.length) % SCOPES.length][0]);
  };
  const scopeName = SCOPES.find(([s]) => s === scope)?.[1];
  const empty = commandMode ? "No matching commands."
    : !rest.trim() ? (scope === "x" ? "Type an address." : "Start typing, or enter an address.")
    : (scope === "c" || scope === "a") && rest.trim().length < 3 ? "Type at least 3 characters." : "No matches.";
  let n = -1;
  const option = (it: PaletteItem) => {
    const k = ++n;
    return (
      <button key={k} id={`palette-${k}`} role="option" aria-selected={k === i} tabIndex={-1} className={k === i ? "on" : ""} onMouseMove={() => setI(k)} onClick={() => go(it)} ref={(el) => { if (el && k === i) el.scrollIntoView({ block: "nearest" }); }}>
        <i>{it.kind}</i><span>{it.title}</span>{it.detail && <code>{it.detail}</code>}
      </button>
    );
  };
  return (
    <div className="palette-back" onMouseDown={onClose}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Search" onMouseDown={(e) => e.stopPropagation()}>
        <input
          ref={input} value={q} placeholder={placeholder ?? (commandMode ? "Run a command" : "Search, or type an address")} role="combobox" aria-expanded={items.length > 0} aria-controls="palette-list" aria-autocomplete="list"
          aria-activedescendant={items[i] ? `palette-${i}` : undefined} aria-label={commandMode ? "Commands" : "Search functions, strings, code and addresses"}
          aria-describedby={placeholder ? undefined : "palette-hint"}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") onClose();
            else if (e.key === "Tab") { e.preventDefault(); if (!placeholder) cycle(e.shiftKey ? -1 : 1); }
            else if (e.key === "ArrowDown") { e.preventDefault(); setI((n) => Math.min(items.length - 1, n + 1)); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setI((n) => Math.max(0, n - 1)); }
            else if (e.key === "Enter") go(items[i]);
          }}
        />
        {!placeholder && <div className="palette-scopes" role="group" aria-label="Search in">
          {SCOPES.map(([s, name]) => <button key={s} tabIndex={-1} className={scope === s ? "on" : ""} aria-pressed={scope === s} onMouseDown={(e) => e.preventDefault()} onClick={() => pick(s)} title={s ? `Type ${s}: to search here` : undefined}>{name}</button>)}
        </div>}
        <div className="palette-list" id="palette-list" role="listbox" aria-label={commandMode ? "Commands" : "Results"}>
          {sections.map((s, g) => s.title ? (
            <div key={s.title} role="group" aria-labelledby={`palette-sec-${g}`}>
              <div className="palette-sec" id={`palette-sec-${g}`}>{s.title}</div>
              {s.items.map(option)}
            </div>
          ) : s.items.map(option))}
          {!items.length && <p className="fine" style={{ padding: 14 }}>{empty}</p>}
        </div>
        {!placeholder && (
          <div className="palette-foot" id="palette-hint">
            <span><kbd>Tab</kbd> next scope</span>
            {commands && <span><kbd>&gt;</kbd> commands</span>}
            <span><kbd>↵</kbd> open</span>
          </div>
        )}
        {!placeholder && <span className="sr-only" aria-live="polite">{commandMode ? "Commands" : `Searching ${scopeName}`}</span>}
      </div>
    </div>
  );
}
