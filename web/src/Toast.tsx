import { useEffect, useState } from "react";

export interface ToastAction { label: string; run: () => void }
interface ToastDetail { text: string; action?: ToastAction }

/**
 * A brief, non-blocking message: it never takes focus and goes by itself. Any code can post one.
 * An action (such as Undo) keeps it up a little longer and is one click away.
 */
export const toast = (text: string, action?: ToastAction) => window.dispatchEvent(new CustomEvent<ToastDetail>("binfera-toast", { detail: { text, action } }));

export function ToastHost() {
  const [shown, setShown] = useState<(ToastDetail & { id: number }) | null>(null);
  useEffect(() => {
    let id = 0, timer = 0;
    const on = (e: Event) => {
      window.clearTimeout(timer);
      const detail = (e as CustomEvent<ToastDetail | string>).detail;
      const d = typeof detail === "string" ? { text: detail } : detail;
      setShown({ ...d, id: ++id });
      timer = window.setTimeout(() => setShown(null), d.action ? 6000 : 2600);
    };
    window.addEventListener("binfera-toast", on);
    return () => { window.removeEventListener("binfera-toast", on); window.clearTimeout(timer); };
  }, []);
  return (
    <div className="toast-host" role="status" aria-live="polite">
      {shown && (
        <div className={"toast" + (shown.action ? " has-action" : "")} key={shown.id}>
          {shown.text}
          {shown.action && <button type="button" onClick={() => { shown.action!.run(); setShown(null); }}>{shown.action.label}</button>}
        </div>
      )}
    </div>
  );
}
