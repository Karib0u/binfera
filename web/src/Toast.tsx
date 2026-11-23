import { useEffect, useState } from "react";

/** A brief, non-blocking message: it never takes focus and goes by itself. Any code can post one. */
export const toast = (text: string) => window.dispatchEvent(new CustomEvent("binfera-toast", { detail: text }));

export function ToastHost() {
  const [shown, setShown] = useState<{ text: string; id: number } | null>(null);
  useEffect(() => {
    let id = 0, timer = 0;
    const on = (e: Event) => {
      window.clearTimeout(timer);
      setShown({ text: (e as CustomEvent<string>).detail, id: ++id });
      timer = window.setTimeout(() => setShown(null), 2600);
    };
    window.addEventListener("binfera-toast", on);
    return () => { window.removeEventListener("binfera-toast", on); window.clearTimeout(timer); };
  }, []);
  return <div className="toast-host" role="status" aria-live="polite">{shown && <div className="toast" key={shown.id}>{shown.text}</div>}</div>;
}
