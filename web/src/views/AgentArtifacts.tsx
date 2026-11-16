import { useCallback, useEffect, useState } from "react";
import { project } from "../project/client";
import type { Activity, Change, Edit, McpSetup, ReportInfo } from "../project/types";
import type { Notes } from "../names";
import Markdown from "../markdown";

const ago = (secs: number) => {
  const d = Math.max(0, Math.floor(Date.now() / 1000) - secs);
  if (d < 90) return "just now";
  if (d < 5400) return `${Math.round(d / 60)} min ago`;
  if (d < 129600) return `${Math.round(d / 3600)} h ago`;
  return new Date(secs * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short" });
};
const runName = (id: string) => (id === "auto-library" ? "Library functions" : id);
const runKind = (workflow: string) => (workflow === "library" ? "named from signatures" : workflow === "autopilot_document" ? "agent run" : workflow);

function CopyLine({ label, text }: { label: string; text: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="ag-copy">
      <span>{label}</span>
      <code>{text}</code>
      <button type="button" onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1400); }).catch(() => {}); }}>{done ? "Copied" : "Copy"}</button>
    </div>
  );
}

/** One change of a run, as a before and after, with a button to take just that one back. */
function ChangeRow({ c, onOpen, onRevert, busy }: { c: Change; onOpen: (address: number) => void; onRevert: (c: Change) => void; busy: boolean }) {
  return (
    <li className={c.undone ? "undone" : undefined}>
      <button type="button" className="ag-addr" onClick={() => onOpen(parseInt(c.target, 16))}>{c.target.split(":")[0]}</button>
      <span>
        {c.kind === "add_comment" ? <i>{c.after}</i> : <>{c.before && <s>{c.before}</s>} {c.after ?? "removed"}</>}
        <small>{c.confidence}</small>
      </span>
      {!c.undone && <button type="button" className="ag-link" disabled={busy} onClick={() => onRevert(c)}>Revert</button>}
    </li>
  );
}

/** What the agent left in this file: reports, and the names and comments of each run, open to review. */
export default function Artifacts({ sha, notes, tick, focus, onOpen }: { sha: string; notes: Notes; tick: number; focus: { tab: "reports" | "changes"; n: number } | null; onOpen: (address: number) => void }) {
  const [activity, setActivity] = useState<Activity | null>(null);
  const [reports, setReports] = useState<ReportInfo[]>([]);
  const [report, setReport] = useState<{ version: number; title: string; markdown: string } | null>(null);
  const [setup, setSetup] = useState<McpSetup | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [reviewing, setReviewing] = useState<string | null>(null);

  const refresh = useCallback(() => {
    if (!project) return;
    project.activity(sha).then((loaded) => { setActivity(loaded); setError(null); }).catch((e) => setError(String(e)));
    project.reports(sha).then(setReports).catch(() => {});
  }, [sha]);
  // `tick` moves whenever the project database changes, so an agent's work shows up as it happens.
  useEffect(refresh, [refresh, tick]);
  // A saved report does not move the annotations' revision, which `tick` follows, so look for new ones too.
  useEffect(() => {
    const id = setInterval(() => { if (document.visibilityState === "visible") project?.reports(sha).then(setReports).catch(() => {}); }, 3000);
    return () => clearInterval(id);
  }, [sha]);
  useEffect(() => { project?.setup().then(setSetup).catch(() => {}); }, []);

  const read = useCallback(async (r: ReportInfo) => {
    try { setReport({ version: r.version, title: r.title, markdown: (await project!.report(sha, r.version)).markdown }); } catch (e) { setError(String(e)); }
  }, [sha]);
  // "Open in Artifacts" from the transcript: the newest report opens straight away; changes open their latest run.
  useEffect(() => {
    if (!focus) return;
    if (focus.tab === "reports" && reports[0]) void read(reports[0]);
    else { setReport(null); if (focus.tab === "changes" && activity?.runs[0]) setReviewing(activity.runs[0].run_id); }
  }, [focus?.n]); // eslint-disable-line react-hooks/exhaustive-deps

  const undo = async (runId: string) => {
    if (!project || !window.confirm(`Revert every change made by "${runName(runId)}"? Edits you made afterwards are kept.`)) return;
    setBusy(runId);
    try { await project.undo(sha, runId); await notes.refreshNow?.(); refresh(); } catch (e) { setError(String(e)); } finally { setBusy(null); }
  };
  const revert = async (c: Change) => {
    if (!project) return;
    setBusy(c.kind + c.target);
    try { await project.remove(sha, [{ kind: c.kind as Edit["kind"], target: c.target }]); await notes.refreshNow?.(); refresh(); } catch (e) { setError(String(e)); } finally { setBusy(null); }
  };

  if (report) {
    return (
      <div className="ag-scroll">
        <div className="ag-crumb">
          <button type="button" onClick={() => setReport(null)}>← Artifacts</button>
          <span>{report.title}<small>v{report.version}</small></span>
          <button type="button" onClick={() => navigator.clipboard?.writeText(report.markdown).catch(() => {})}>Copy</button>
        </div>
        <article className="ag-report"><Markdown text={report.markdown} onAddress={onOpen} /></article>
      </div>
    );
  }

  const counts = activity?.counts;
  const nothing = !reports.length && !activity?.runs.length;
  return (
    <div className="ag-scroll">
      {error && <p className="ag-error" role="alert">{error}</p>}
      {nothing && <p className="ag-empty">Nothing yet. Reports and changes your agent saves to this file appear here.</p>}

      {reports.length > 0 && (
        <section>
          <h4>Reports <em>{reports.length}</em></h4>
          <ul className="ag-list">
            {reports.map((r) => (
              <li key={r.id}><button type="button" onClick={() => read(r)}><b>{r.title}</b><span>v{r.version} · {ago(r.created)}</span></button></li>
            ))}
          </ul>
        </section>
      )}

      {!!activity?.runs.length && (
        <section>
          <h4>Changes <em>{counts ? `${counts.ai} by agents · ${counts.human} by you` : ""}</em></h4>
          <ul className="ag-list">
            {activity.runs.map((r) => {
              const open = reviewing === r.run_id;
              const mine = (activity.changes ?? []).filter((c) => c.run_id === r.run_id);
              return (
                <li key={r.run_id} className="run">
                  <div className="has-act">
                    <button type="button" className="ag-run" aria-expanded={open} onClick={() => setReviewing(open ? null : r.run_id)}>
                      <i aria-hidden>{open ? "▾" : "▸"}</i>
                      <span><b>{runName(r.run_id)}</b><small>{runKind(r.workflow)} · {r.changes} {r.changes === 1 ? "change" : "changes"} · {ago(r.started)}</small></span>
                    </button>
                    <button type="button" className="ag-link" disabled={r.changes === 0 || busy === r.run_id} onClick={() => undo(r.run_id)}>Undo all</button>
                  </div>
                  {open && (
                    mine.length
                      ? <ul className="ag-changes">{mine.map((c, i) => <ChangeRow key={i} c={c} onOpen={onOpen} onRevert={revert} busy={busy === c.kind + c.target} />)}</ul>
                      : <p className="ag-empty small">No changes to show for this run.</p>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      )}

      <details className="ag-more ag-connect">
        <summary>Use another agent</summary>
        <p>Connect OpenCode, Pi, or another MCP-compatible agent to work on this file. Register Binfera once, then use your agent in its own terminal.</p>
        <CopyLine label="OpenCode" text={setup?.opencode ?? "opencode mcp add binfera --global -- binfera mcp"} />
        <CopyLine label="Pi" text={setup?.pi ?? "pi mcp add binfera -- binfera mcp"} />
      </details>
    </div>
  );
}
