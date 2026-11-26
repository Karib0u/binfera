import type { Analysis } from "../types";
import { hex } from "../workspace/labels";

export function FindingsCard({ a, onPick, onDetails, compact = false }: { a: Analysis; onPick: (va: number) => void; onDetails: () => void; compact?: boolean }) {
  if (!a.image) return null;
  const findings = [...(a.image.details?.anomalies ?? [])].sort((x, y) => Number(y.severity === "warn") - Number(x.severity === "warn"));
  const warnings = findings.filter((f) => f.severity === "warn").length;
  // On a phone: one tappable line, nothing at all when the headers are clean.
  if (compact) return findings.length ? (
    <button className={"ov-alert" + (warnings ? " warn" : "")} onClick={onDetails}>
      <i aria-hidden /><span>{warnings ? `${warnings} header ${warnings === 1 ? "finding" : "findings"} to review` : `${findings.length} header ${findings.length === 1 ? "note" : "notes"}`}</span><b aria-hidden>›</b>
    </button>
  ) : null;
  return (
    <section className="ov-card">
      <header><h2>Findings</h2>{findings.length > 0 && <span className={warnings ? "ov-review" : ""}>{warnings ? `${warnings} to review` : `${findings.length} notes`}</span>}</header>
      {findings.length ? <ul className="ov-findings">
        {findings.slice(0, 3).map((f, n) => <li key={n} className={"finding-" + f.severity}>
          <span className="ov-finding-kind" title={f.severity === "warn" ? "Review" : "Note"}><span className="sr-only">{f.severity === "warn" ? "Review: " : "Note: "}</span></span>
          {f.va !== undefined && a.image!.vaToOff(f.va) !== null ? <button onClick={() => onPick(f.va!)}>{f.text}<code>{hex(f.va)}</code></button> : <p>{f.text}</p>}
        </li>)}
      </ul> : <p className="ov-no-findings">{a.image.details ? "No header anomalies reported." : "No header findings available."}</p>}
      <button className="ov-card-link" onClick={onDetails}>{findings.length > 3 ? `View all ${findings.length} findings` : "View file details"}<span aria-hidden>›</span></button>
    </section>
  );
}
