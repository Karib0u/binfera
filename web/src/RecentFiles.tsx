import { useEffect, useState } from "react";
import { desktop } from "./project/client";
import type { Recent } from "./project/types";
import { bytes } from "./workspace/labels";

const SHOWN = 6;

/** "3 hours ago", "yesterday", in the user's language. */
function ago(seconds: number) {
  const diff = seconds - Date.now() / 1000;
  const fmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [unit, size] of steps) if (Math.abs(diff) >= size) return fmt.format(Math.round(diff / size), unit);
  return fmt.format(0, "second");
}

/** What the analyst has put into a file, for the line under its name. */
function work(r: Recent) {
  const parts: string[] = [];
  if (r.human) parts.push(`${r.human} of your edits`);
  if (r.ai) parts.push(`${r.ai} by AI`);
  if (r.reports) parts.push(`${r.reports} report${r.reports > 1 ? "s" : ""}`);
  return parts;
}

/** The files opened before: one click returns to a file with its notes, and to its stored analysis. */
export default function RecentFiles({ busy, onOpen, onLocate, onError }: {
  busy: boolean;
  onOpen: (r: Recent) => void;
  /** Finds a file whose path is gone or was never known; it must be the same binary. */
  onLocate: (r: Recent) => void;
  onError: (message: string) => void;
}) {
  const [items, setItems] = useState<Recent[] | null>(null);
  const [all, setAll] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  useEffect(() => {
    desktop?.recent().then(setItems).catch((e) => { setItems([]); onError(String(e?.message ?? e)); });
  }, []);
  if (!desktop || !items?.length) return null;

  const gone = (r: Recent) => !r.retained && (r.path === null || r.missing);
  const forget = async (r: Recent) => {
    setRemoving(null);
    try {
      await desktop!.forget(r.sha256);
      setItems((all) => all?.filter((x) => x.sha256 !== r.sha256) ?? null);
    } catch (e) { onError(String((e as Error)?.message ?? e)); }
  };
  const shown = all ? items : items.slice(0, SHOWN);

  return (
    <section className="recent" aria-labelledby="recent-title">
      <h2 id="recent-title">Recent</h2>
      <ul>
        {shown.map((r) => {
          const mine = work(r);
          const sure = removing === r.sha256;
          const saved = r.retained && (r.path === null || r.missing);
          return (
            <li key={r.sha256} className={gone(r) ? "is-gone" : undefined}>
              <button type="button" className="recent-open" disabled={busy} onClick={() => (gone(r) ? onLocate(r) : onOpen(r))}
                title={saved ? "Saved in Binfera. Click to reopen." : r.path ?? "File unavailable. Locate it to reopen."}>
                <span className="recent-name">{r.name}</span>
                <span className="recent-meta">
                  {[bytes(r.size), ago(r.opened), ...mine].join(" · ")}
                  {saved ? <em>Saved in Binfera</em> : !gone(r) && r.cached && <em>ready</em>}
                  {gone(r) && <em>{r.path === null ? "Locate to reopen" : "Moved or deleted. Locate"}</em>}
                </span>
              </button>
              {sure ? (
                <span className="recent-confirm" role="group" aria-label={`Remove ${r.name}`}>
                  <span>{r.retained ? `Also deletes the saved copy${mine.length ? " and your notes" : ""}.` : mine.length ? "Also deletes your notes." : "Remove?"}</span>
                  <button type="button" onClick={() => forget(r)}>Remove</button>
                  <button type="button" onClick={() => setRemoving(null)}>Keep</button>
                </span>
              ) : (
                <span className="recent-actions">
                  {!gone(r) && <button type="button" onClick={() => desktop!.reveal(r.sha256).catch((e) => onError(String(e?.message ?? e)))}>Show</button>}
                  <button type="button" onClick={() => setRemoving(r.sha256)} aria-label={`Remove ${r.name} from history`}>Remove</button>
                </span>
              )}
            </li>
          );
        })}
      </ul>
      {items.length > SHOWN && <button type="button" className="recent-more" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${items.length}`}</button>}
    </section>
  );
}
