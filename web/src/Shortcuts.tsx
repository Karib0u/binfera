import { useEffect, useRef } from "react";
import { agent } from "./agent/client";

export const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
export const searchKey = isMac ? "⌘K" : "Ctrl K";

const KEYS: [string, [string, string][]][] = [
  ["Find", [[searchKey + "  or  /", "Search everything"], ["g", "Go to an address"]]],
  ["Move", [["j  k", "Next or previous function"], ["↑  ↓", "Move through the focused list, code or bytes"], [(isMac ? "⌥" : "Alt") + " ←  →", "Back and forward"]]],
  ["Work", [["n", "Rename the word you clicked (a local or a called function), else the open function"], ["x", "Show the cross-references to the word you clicked, else to this function"], ["s", "Star the open function"], [";", "Add or edit a comment at the cursor"], [isMac ? "⌘Z" : "Ctrl Z", "Undo your last edit"], ["[  ]", "Show or hide the function list, the function inspector"], ["\\", "Show one pane or restore the layout"], ["f", "Focus: only the code, hiding the list, inspector and agent"], ["?", "This list"]]],
];

/** The keyboard shortcuts, opened with ?. */
export default function Shortcuts({ onClose, extra }: { onClose: () => void; extra?: [string, string][] }) {
  const close = useRef<HTMLButtonElement>(null);
  // Only the desktop app has an agent panel to show.
  const groups = agent ? KEYS.map(([g, rows]) => (g === "Work" ? [g, [...rows, [isMac ? "⌘J" : "Ctrl J", "Show or hide the agent"], [isMac ? "⌘L" : "Ctrl L", "Write to the agent"]]] as [string, [string, string][]] : [g, rows] as [string, [string, string][]])) : KEYS;
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    close.current?.focus();
    return () => before?.focus?.();
  }, []);
  return (
    <div className="palette-back" onMouseDown={onClose} onKeyDown={(e) => { if (e.key === "Escape" || e.key === "?") { e.stopPropagation(); onClose(); } }}>
      <div className="sheet" role="dialog" aria-modal="true" aria-labelledby="keys-title" onMouseDown={(e) => e.stopPropagation()}>
        <div className="sheet-head">
          <h2 id="keys-title">Keyboard shortcuts</h2>
          <button ref={close} className="ghost" onClick={onClose}>Close</button>
        </div>
        {[...(extra?.length ? [["Compare", extra] as [string, [string, string][]]] : []), ...groups].map(([group, rows]) => (
          <section key={group}>
            <h3>{group}</h3>
            <dl>{rows.map(([k, what]) => <div key={k}><dt><kbd>{k}</kbd></dt><dd>{what}</dd></div>)}</dl>
          </section>
        ))}
      </div>
    </div>
  );
}
