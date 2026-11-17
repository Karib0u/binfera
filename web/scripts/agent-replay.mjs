// Turns one real agent run into the replay that `vite --mode mock` plays in the agent panel, so the
// panel can be designed and screenshotted without the Tauri shell or a live model.
//
//   node scripts/agent-replay.mjs <claude stream-json log> <projects.sqlite3> [out]
//
// Record the log the way the desktop runs Claude Code (src-tauri/src/agent.rs, `claude_args`), with
// BINFERA_DATA_DIR pointing at an empty folder so the database holds only that run:
//
//   claude -p --output-format stream-json --verbose --strict-mcp-config \
//     --mcp-config '{"mcpServers":{"binfera":{"command":"<binfera>","args":["mcp"]}}}' \
//     --tools "" --allowedTools 'mcp__binfera__*' "<prompt>" > run.jsonl
//
// Events follow `parse_claude` in agent.rs: same kinds, same 4,000-character clip on tool output.
import { readFileSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const [log, dbPath, out = new URL("../src/dev/agent-replay.json", import.meta.url)] = process.argv.slice(2);
if (!log || !dbPath) {
  console.error("usage: node scripts/agent-replay.mjs <run.jsonl> <projects.sqlite3> [out.json]");
  process.exit(2);
}

const OUTPUT_CHARS = 4000;
const clip = (s) => ([...s].length > OUTPUT_CHARS ? [...s].slice(0, OUTPUT_CHARS).join("") + "…" : s);
const text = (c) => (typeof c === "string" ? c : Array.isArray(c) ? c.map((b) => b.text).filter(Boolean).join("\n") : "");

// The run's sample path names the recording machine; the replay shows a neutral one instead.
let samplePath = null;
const lines = readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
for (const v of lines) for (const b of v.message?.content ?? []) if (b.name === "mcp__binfera__open_binary") samplePath ??= b.input?.path;
const neutral = (s) => (samplePath ? s.split(samplePath).join(`/Users/analyst/samples/${samplePath.split("/").pop()}`) : s);
const scrub = (value) => JSON.parse(neutral(JSON.stringify(value)));

// Paced for watching, not the run's real timing: reading is quick, answers take a moment.
const events = [];
let sha = null;
for (const v of lines) {
  if (v.type === "system" && v.subtype === "init") events.push([200, { kind: "session", id: "replay-session" }]);
  if (v.type === "assistant") {
    for (const b of v.message.content) {
      if (b.type === "text" && b.text.trim()) events.push([700, { kind: "text", text: neutral(b.text) }]);
      if (b.type === "tool_use") {
        sha ??= b.input?.project_id?.replace(/^sha256:/, "") ?? null;
        events.push([250, { kind: "tool", id: b.id, name: b.name.replace(/^mcp__binfera__/, ""), input: scrub(b.input), status: "running", output: null }]);
      }
    }
  }
  if (v.type === "user") {
    for (const b of v.message.content) {
      if (b.type !== "tool_result") continue;
      events.push([450, { kind: "tool", id: b.tool_use_id, name: "", input: null, status: b.is_error ? "error" : "done", output: clip(neutral(text(b.content))) }]);
    }
  }
  if (v.type === "result" && !v.is_error) {
    const u = v.usage ?? {};
    events.push([100, { kind: "usage", input: (u.input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0), output: u.output_tokens ?? 0, cost: v.total_cost_usd ?? null }]);
    events.push([100, { kind: "done" }]);
  }
}

// What the run left in the project, so the workspace shows its names and comments.
const db = new DatabaseSync(dbPath, { readOnly: true });
const rows = (sql) => db.prepare(sql).all(sha).map((r) => ({ ...r }));
const annotations = rows("select kind, target, value, source, confidence, run_id, revision from annotations where sha256 = ?");
const runs = rows("select run_id, workflow, started, (select count(*) from changes c where c.run_id = r.run_id and c.sha256 = r.sha256) as changes from runs r where sha256 = ? order by started desc");
const changes = rows("select run_id, kind, target, before, after, source, confidence, revision, ts, undone from changes where sha256 = ? order by id desc")
  .map((c) => ({ ...c, undone: Boolean(c.undone) }));
const reports = rows("select id, version, title, created, markdown from reports where sha256 = ? order by version desc");
const kinds = (k) => annotations.filter((a) => a.kind === k).length;
const counts = {
  function_names: kinds("rename_function"), variable_names: kinds("rename_variable"), comments: kinds("add_comment"),
  human: annotations.filter((a) => a.source === "human").length, ai: annotations.filter((a) => a.source === "ai").length,
};
const revision = Math.max(0, ...annotations.map((a) => a.revision));
const startedAt = runs.at(-1)?.started ?? 0;
// Times are kept relative, so the panel says "minutes ago" whenever it is replayed.
const rel = (t) => t - startedAt;

writeFileSync(out, JSON.stringify(scrub({
  sha256: sha,
  events,
  project: {
    revision, counts, annotations,
    runs: runs.map((r) => ({ ...r, started: rel(r.started) })),
    changes: changes.map((c) => ({ ...c, ts: rel(c.ts) })),
    reports: reports.map((r) => ({ ...r, created: rel(r.created) })),
  },
}), null, 1) + "\n");
console.log(`${events.length} events, ${annotations.length} annotations, ${reports.length} reports → ${out}`);
