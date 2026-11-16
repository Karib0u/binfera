// Development only (`vite --mode mock`): the desktop's project client with canned data, so the agent
// dock can be designed in a browser without the Tauri shell. Never part of a real build.
import type { Activity, Desktop, ProjectClient, ReportInfo } from "../project/types";

const now = Math.floor(Date.now() / 1000);
const counts = { function_names: 6, variable_names: 2, comments: 9, human: 3, ai: 14 };
export const activity: Activity = {
  revision: 4,
  counts,
  runs: [
    { run_id: "run-triage-3f2a", workflow: "autopilot_document", started: now - 420, changes: 11 },
    { run_id: "auto-library", workflow: "library", started: now - 3600, changes: 3 },
  ],
  changes: [
    { run_id: "run-triage-3f2a", kind: "rename_function", target: "0x100000978", before: "sub_100000978", after: "entry_parse_args", source: "ai", confidence: "likely", revision: 4, ts: now - 400, undone: false },
    { run_id: "run-triage-3f2a", kind: "add_comment", target: "0x1000009c4", before: null, after: "getopt loop over the short flags", source: "ai", confidence: "likely", revision: 4, ts: now - 390, undone: false },
    { run_id: "auto-library", kind: "rename_function", target: "0x100001a40", before: "sub_100001a40", after: "fts_read", source: "ai", confidence: "certain", revision: 2, ts: now - 3500, undone: false },
  ],
};
const reports: ReportInfo[] = [
  { id: 2, version: 2, title: "Static triage of ls", created: now - 300 },
  { id: 1, version: 1, title: "Capabilities mapped to ATT&CK", created: now - 5000 },
];
const markdown = "# Static triage of ls\n\nAn **Apple-signed x86-64 Mach-O** that lists directories. The entry function `0x100000978` parses flags, then walks the tree with `fts_*` (`0x100001a40`).\n\n## Findings\n\n- No network imports\n- Reads extended attributes and ACLs\n\n> Static analysis does not prove runtime behaviour.";

export const project: ProjectClient = {
  load: async () => ({ revision: 4, annotations: [], counts }),
  path: async () => "/Users/analyst/samples/ls",
  revision: async () => 4,
  apply: async () => 5,
  remove: async () => 5,
  undo: async () => ({ reverted: 3, skipped: [], revision: 5 }),
  activity: async () => activity,
  reports: async () => reports,
  report: async (_sha, version) => ({ json: "{}", markdown: version === 1 ? "# Capabilities\n\n- T1083 File and directory discovery" : markdown }),
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
