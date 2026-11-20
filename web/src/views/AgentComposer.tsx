import { useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";

export interface SymbolRef { address: number; name: string }
/** A command in the "/" menu. `run` may return text to put in the box (a canned request the analyst can edit). */
export interface SlashItem { id: string; title: string; about: string; run: () => string | void }

const MENU_ROWS = 8;
const hex = (n: number) => "0x" + n.toString(16);

/**
 * The message box of the agent dock: "/" opens the commands and canned requests, "@" a function or address
 * to mention, Enter sends (or queues, while the agent works) and Esc interrupts.
 */
export default function Composer({ text, onText, onSend, onInterrupt, busy, disabled, placeholder, queue, onUnqueue, symbols, slash, bar, inputRef }: {
  text: string; onText: (t: string) => void; onSend: (t: string) => void; onInterrupt: () => void;
  busy: boolean; disabled: boolean; placeholder: string;
  queue: string[]; onUnqueue: (i: number) => void;
  symbols: () => SymbolRef[]; slash: SlashItem[]; bar: ReactNode; inputRef: RefObject<HTMLTextAreaElement | null>;
}) {
  const [caret, setCaret] = useState(0);
  const [active, setActive] = useState(0);
  // Escape closes a menu for the text it was open on; typing anything reopens it.
  const [dismissed, setDismissed] = useState<string | null>(null);
  const after = useRef<number | null>(null);

  const menu = useMemo(() => {
    if (dismissed === text) return null;
    if (text.startsWith("/") && !/\s/.test(text)) {
      const q = text.slice(1).toLowerCase();
      const rows = slash.filter((s) => s.id.includes(q) || s.title.toLowerCase().includes(q))
        .sort((a, b) => Number(b.id.startsWith(q)) - Number(a.id.startsWith(q)));
      return rows.length ? { kind: "slash" as const, rows: rows.slice(0, MENU_ROWS), at: 0 } : null;
    }
    const m = /(?:^|\s)@([^\s@]*)$/.exec(text.slice(0, caret));
    if (!m) return null;
    const q = m[1].toLowerCase();
    const all = symbols();
    const hit = q ? all.filter((s) => s.name.toLowerCase().includes(q) || hex(s.address).includes(q)) : all;
    hit.sort((a, b) => Number(b.name.toLowerCase().startsWith(q)) - Number(a.name.toLowerCase().startsWith(q)));
    return hit.length ? { kind: "mention" as const, rows: hit.slice(0, MENU_ROWS), at: caret - m[1].length - 1 } : null;
  }, [text, caret, dismissed, slash, symbols]);
  useEffect(() => setActive(0), [menu?.kind, text]);
  useEffect(() => {
    if (after.current === null) return;
    const el = inputRef.current;
    if (el) { el.focus(); el.setSelectionRange(after.current, after.current); }
    after.current = null;
  });

  const accept = (n: number) => {
    if (!menu) return;
    if (menu.kind === "slash") {
      const r = (menu.rows as SlashItem[])[n].run();
      onText(typeof r === "string" ? r : "");
      after.current = typeof r === "string" ? r.length : 0;
    } else {
      const s = (menu.rows as SymbolRef[])[n];
      const mention = `${s.name} (${hex(s.address)}) `;
      onText(text.slice(0, menu.at) + mention + text.slice(caret));
      after.current = menu.at + mention.length;
    }
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.nativeEvent.isComposing) return;
    if (menu) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); setActive((a) => (a + (e.key === "ArrowDown" ? 1 : menu.rows.length - 1)) % menu.rows.length); return; }
      if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); accept(active); return; }
      if (e.key === "Escape") { e.preventDefault(); setDismissed(text); return; }
    }
    if (e.key === "Escape" && busy) { e.preventDefault(); onInterrupt(); return; }
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); onSend(text); }
  };

  return (
    <form className="ag-compose" onSubmit={(e) => { e.preventDefault(); onSend(text); }}>
      {menu && (
        <ul className="ag-menu" role="listbox" aria-label={menu.kind === "slash" ? "Commands" : "Functions"}>
          {menu.kind === "slash"
            ? (menu.rows as SlashItem[]).map((s, n) => (
              <li key={s.id} role="option" aria-selected={n === active} className={n === active ? "on" : ""} onMouseEnter={() => setActive(n)} onMouseDown={(e) => { e.preventDefault(); accept(n); }}>
                <b>/{s.id}</b><span>{s.about}</span>
              </li>
            ))
            : (menu.rows as SymbolRef[]).map((s, n) => (
              <li key={s.address} role="option" aria-selected={n === active} className={n === active ? "on" : ""} onMouseEnter={() => setActive(n)} onMouseDown={(e) => { e.preventDefault(); accept(n); }}>
                <b>{s.name}</b><span className="mono">{hex(s.address)}</span>
              </li>
            ))}
        </ul>
      )}
      {queue.length > 0 && (
        <ul className="ag-queue" aria-label="Queued messages">
          {queue.map((q, i) => (
            <li key={i}><span>Queued</span><em>{q}</em><button type="button" aria-label="Remove from the queue" onClick={() => onUnqueue(i)}>✕</button></li>
          ))}
        </ul>
      )}
      <textarea ref={inputRef} value={text} rows={Math.min(8, Math.max(2, text.split("\n").length))} placeholder={placeholder} disabled={disabled}
        onChange={(e) => { onText(e.target.value); setCaret(e.target.selectionStart); }}
        onSelect={(e) => setCaret(e.currentTarget.selectionStart)}
        onKeyDown={onKeyDown} />
      {bar}
    </form>
  );
}
