// Development only (`vite --mode mock`): the desktop's project client, holding what a real agent run
// left in the WannaCry demo (src/dev/agent-replay.json), so the agent dock and its artifacts can be
// designed in a browser without the Tauri shell. Never part of a real build.
import type { Activity, Annotation, Desktop, ProjectClient, ReportInfo } from "../project/types";
import replay from "./agent-replay.json";

// The recording keeps times relative to its first run, which is placed ten minutes ago.
const start = Math.floor(Date.now() / 1000) - 600;
const saved = replay.project;
const counts = saved.counts;
const annotations = saved.annotations as Annotation[];
export const activity: Activity = {
  revision: saved.revision,
  counts,
  runs: saved.runs.map((r) => ({ ...r, started: start + r.started })),
  changes: (saved.changes as Activity["changes"]).map((c) => ({ ...c, ts: start + c.ts })),
};
const reports = (saved.reports as (ReportInfo & { markdown: string })[]).map((r) => ({ ...r, created: start + r.created }));
/** Another file has nothing saved. */
const mine = (sha: string) => sha.replace(/^sha256:/, "") === replay.sha256;

export const project: ProjectClient = {
  load: async (sha) => mine(sha) ? { revision: saved.revision, annotations, counts } : { revision: 0, annotations: [], counts: { ...counts, function_names: 0, variable_names: 0, comments: 0, human: 0, ai: 0 } },
  path: async (sha) => `/Users/analyst/samples/${sha}`,
  revision: async (sha) => (mine(sha) ? saved.revision : 0),
  apply: async () => 5,
  remove: async () => 5,
  undo: async () => ({ reverted: 3, skipped: [], revision: 5 }),
  activity: async (sha) => (mine(sha) ? activity : { ...activity, runs: [], changes: [] }),
  reports: async (sha) => (mine(sha) ? reports.map(({ markdown: _, ...r }) => r) : []),
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
