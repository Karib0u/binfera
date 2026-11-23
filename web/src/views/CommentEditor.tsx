import { useEffect, useRef, useState } from "react";
import { hex } from "../workspace/labels";
import Sheet from "../Sheet";

/** A small editor beside the selected instruction, shared by the code and listing views. */
export default function CommentEditor({ address, text, rect, onSave, onClose, mobile }: {
  address: number; text: string; rect?: DOMRect; onSave: (text: string) => void; onClose: () => void;
  /** A phone edits in a bottom sheet that rides above the keyboard, not a popover the keyboard would cover. */
  mobile?: boolean;
}) {
  const [value, setValue] = useState(text);
  const input = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    input.current?.focus();
    return () => before?.focus?.();
  }, []);
  const width = Math.min(360, window.innerWidth - 16);
  const left = Math.max(8, Math.min(rect?.left ?? (window.innerWidth - width) / 2, window.innerWidth - width - 8));
  const top = Math.max(8, Math.min(rect?.bottom ?? 120, window.innerHeight - 200));
  const tooLong = new TextEncoder().encode(value.trim()).length > 2000;
  if (mobile) return (
    <Sheet title={"Comment at " + hex(address)} onClose={onClose}>
      <form className="sheet-comment" aria-label={"Comment at " + hex(address)} onSubmit={(e) => { e.preventDefault(); if (!tooLong) onSave(value); }}>
        <label htmlFor="analyst-comment" className="sr-only">Comment at {hex(address)}</label>
        <textarea id="analyst-comment" ref={input} value={value} rows={4} onChange={(e) => setValue(e.target.value)} placeholder="Add a comment…" />
        <small>{tooLong ? "Comments can use at most 2,000 bytes." : "Saving an empty comment removes it"}</small>
        <div className="row"><button type="button" className="ghost" onClick={onClose}>Cancel</button><button type="submit" disabled={tooLong}>Save</button></div>
      </form>
    </Sheet>
  );
  return <form className="comment-editor" aria-label={"Comment at " + hex(address)} style={{ left, top, width }}
    onSubmit={(e) => { e.preventDefault(); if (!tooLong) onSave(value); }}
    onKeyDown={(e) => {
      e.stopPropagation();
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); if (!tooLong) onSave(value); }
    }}>
    <label htmlFor="analyst-comment">Comment at {hex(address)}</label>
    <textarea id="analyst-comment" ref={input} value={value} rows={3} onChange={(e) => setValue(e.target.value)} placeholder="Add a comment…" />
    <small>{tooLong ? "Comments can use at most 2,000 bytes." : "Enter saves · Shift+Enter adds a line · Empty removes"}</small>
    <div><button type="submit" disabled={tooLong}>Save</button><button type="button" className="ghost" onClick={onClose}>Cancel</button></div>
  </form>;
}
