import { useEffect, useRef, useState } from "react";
import { hex } from "../workspace/labels";

/** A small editor beside the selected instruction, shared by the code and listing views. */
export default function CommentEditor({ address, text, rect, onSave, onClose }: {
  address: number; text: string; rect?: DOMRect; onSave: (text: string) => void; onClose: () => void;
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
