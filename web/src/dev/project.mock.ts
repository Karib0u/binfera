// Development only (`vite --mode mock`): the desktop's project client, holding what a real agent run
// left in the WannaCry demo (src/dev/agent-replay.json), so the agent dock and its artifacts can be
// designed in a browser without the Tauri shell. Never part of a real build.
import type { Activity, Annotation, Desktop, ProjectClient, ReportInfo } from "../project/types";
import replay from "./agent-replay.json";

// The recording keeps times relative to its first run, which is placed ten minutes ago.
const start = Math.floor(Date.now() / 1000) - 600;
const saved = replay.project;
const all = saved.annotations as Annotation[];
const allRuns = saved.runs.map((r) => ({ ...r, started: start + r.started }));
const allChanges = (saved.changes as Activity["changes"]).map((c) => ({ ...c, ts: start + c.ts }));
const reports = (saved.reports as (ReportInfo & { markdown: string })[]).map((r) => ({ ...r, created: start + r.created }));
/** Another file has nothing saved. */
const mine = (sha: string) => sha.replace(/^sha256:/, "") === replay.sha256;

// Normally the file opens with everything the recorded runs saved. With `binfera-mock:fresh` set in
// localStorage it opens with only the automatic library names, and each `apply_annotations` the
// replayed agent makes reveals the next revision, so names appear while the agent works.
const fresh = (() => { try { return localStorage.getItem("binfera-mock:fresh") === "1"; } catch { return false; } })();
const revisions = [...new Set(all.map((a) => a.revision))].sort((a, b) => a - b);
let shown = fresh ? revisions[0] ?? 0 : saved.revision;
/** The replayed agent saved its names: show the next revision. */
export function reveal() { shown = revisions.find((r) => r > shown) ?? shown; }

function state() {
  const annotations = all.filter((a) => a.revision <= shown);
  const kinds = (k: string) => annotations.filter((a) => a.kind === k).length;
  const counts = {
    function_names: kinds("rename_function"), variable_names: kinds("rename_variable"), comments: kinds("add_comment"),
    human: annotations.filter((a) => a.source === "human").length, ai: annotations.filter((a) => a.source === "ai").length,
  };
  const changes = allChanges.filter((c) => c.revision <= shown);
  const runs = allRuns.filter((r) => changes.some((c) => c.run_id === r.run_id));
  return { annotations, counts, activity: { revision: shown, counts, runs, changes } as Activity };
}
/** For other modules that want the full picture. */
export const activity: Activity = { revision: saved.revision, counts: saved.counts, runs: allRuns, changes: allChanges };
const none = { function_names: 0, variable_names: 0, comments: 0, human: 0, ai: 0 };

export const project: ProjectClient = {
  load: async (sha) => {
    if (!mine(sha)) return { revision: 0, annotations: [], counts: none };
    const { annotations, counts } = state();
    return { revision: shown, annotations, counts };
  },
  path: async (sha) => `/Users/analyst/samples/${sha}`,
  revision: async (sha) => (mine(sha) ? shown : 0),
  apply: async () => 5,
  remove: async () => 5,
  undo: async () => ({ reverted: 3, skipped: [], revision: 5 }),
  activity: async (sha) => (mine(sha) ? state().activity : { revision: 0, counts: none, runs: [], changes: [] }),
  // A fresh replay saves no report (the recorded triage did not), so none is listed.
  reports: async (sha) => (mine(sha) && !fresh ? reports.map(({ markdown: _, ...r }) => r) : []),
  report: async (_sha, version) => ({ json: "{}", markdown: reports.find((r) => r.version === version)?.markdown ?? "" }),
  setup: async () => ({
    command: "/Applications/Binfera.app/Contents/MacOS/binfera",
    opencode: "opencode mcp add binfera --global -- /Applications/Binfera.app/Contents/MacOS/binfera mcp",
    pi: "pi mcp add binfera -- /Applications/Binfera.app/Contents/MacOS/binfera mcp",
    database: "~/Library/Application Support/binfera/projects.sqlite3",
  }),
};

export const desktop: Desktop | null = null;

export const installNativeDrop = (): void => {};
/** No page zoom to restore in the browser design mode. */
export const installZoom = (): void => {};
