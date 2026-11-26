import { useEffect, useRef, useState, type RefObject } from "react";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** The elements Tab can reach inside root, in order. Hidden and visually removed ones are skipped. */
export const focusables = (root: HTMLElement) =>
  [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => !el.closest("[hidden]") && el.getClientRects().length > 0);

/** Open dialogs, oldest first: only the top one answers keys, so Escape closes one layer at a time. */
const stack: object[] = [];

/**
 * A modal dialog's keyboard contract. Escape (or any of `closeKeys`) closes it, from a document listener so it
 * works wherever focus sits; Tab and Shift+Tab stay inside; focus moves in on open and returns to the element
 * that opened it on close. The dialog element should have tabIndex={-1} so it can hold focus when it has no controls.
 */
export function useDialog(ref: RefObject<HTMLElement | null>, onClose: () => void, closeKeys: string[] = ["Escape"]) {
  // Read during the first render, before an autoFocus inside the dialog moves focus.
  const [opener] = useState(() => (typeof document === "undefined" ? null : (document.activeElement as HTMLElement | null)));
  const close = useRef(onClose);
  close.current = onClose;
  const keys = useRef(closeKeys);
  keys.current = closeKeys;
  useEffect(() => {
    const me = {};
    stack.push(me);
    const root = ref.current;
    if (root && !root.contains(document.activeElement)) (focusables(root)[0] ?? root).focus();
    const onKey = (e: KeyboardEvent) => {
      if (stack[stack.length - 1] !== me || !ref.current) return;
      const box = ref.current;
      if (keys.current.includes(e.key) && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        e.stopPropagation();
        close.current();
        return;
      }
      if (e.key !== "Tab") return;
      const items = focusables(box);
      const at = document.activeElement as HTMLElement | null;
      if (!items.length) { e.preventDefault(); box.focus(); return; }
      const first = items[0], last = items[items.length - 1];
      const outside = !at || !box.contains(at);
      if (e.shiftKey && (outside || at === first || at === box)) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (outside || at === last)) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      const i = stack.indexOf(me);
      if (i >= 0) stack.splice(i, 1);
      // Only when focus was lost with the dialog: an action that moved focus elsewhere keeps it there.
      const now = document.activeElement;
      if ((!now || now === document.body || !now.isConnected) && opener?.isConnected) opener.focus();
    };
  }, []);
}

/** A centred desktop dialog over a dim backdrop; a click on the backdrop closes it. */
export function Modal({ className, labelledBy, onClose, closeKeys, children }: {
  className: string; labelledBy: string; onClose: () => void; closeKeys?: string[]; children: React.ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  useDialog(box, onClose, closeKeys);
  return (
    <div className="palette-back" onMouseDown={onClose}>
      <div ref={box} tabIndex={-1} className={className} role="dialog" aria-modal="true" aria-labelledby={labelledBy} onMouseDown={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}
