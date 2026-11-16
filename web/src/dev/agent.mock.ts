// Development only (`vite --mode mock`): an agent that answers with a scripted turn, tool calls included.
import type { AgentClient, AgentEvent, ModelInfo } from "../agent/types";

const script: [number, AgentEvent][] = [
  [200, { kind: "session", id: "mock-session" }],
  [400, { kind: "text", text: "I'll start with the overview, then look at the entry function." }],
  [300, { kind: "tool", id: "t1", name: "get_overview", input: { project_id: "sha256:ab12" }, status: "running", output: null }],
  [700, { kind: "tool", id: "t1", name: "get_overview", input: { project_id: "sha256:ab12" }, status: "done", output: "{\n  \"format\": \"Mach-O\",\n  \"arch\": \"x86-64\",\n  \"functions\": 50\n}" }],
  [200, { kind: "tool", id: "t2", name: "get_function", input: { project_id: "sha256:ab12", address: "0x100000978" }, status: "running", output: null }],
  [900, { kind: "tool", id: "t2", name: "get_function", input: { project_id: "sha256:ab12", address: "0x100000978" }, status: "done", output: "int entry(int argc, char **argv) { … }" }],
  [200, { kind: "tool", id: "t3", name: "apply_annotations", input: { renames: 3, comments: 4 }, status: "running", output: null }],
  [500, { kind: "tool", id: "t3", name: "apply_annotations", input: { renames: 3, comments: 4 }, status: "done", output: "{\"run_id\":\"run-triage-3f2a\",\"applied\":7}" }],
  [300, { kind: "text", text: "This is the **x86-64 slice of Apple's `ls`**. The function at 0x2101dc does arithmetic, the string at 0x2001c8 is data, and `0x4000` maps to nothing with `fts_read`.\n\n- No network imports\n- Reads extended attributes and ACLs\n\nStatic analysis does not prove runtime behaviour." }],
  [300, { kind: "tool", id: "t4", name: "save_report", input: { title: "Static triage of ls" }, status: "done", output: "{\"version\":2,\"title\":\"Static triage of ls\"}" }],
  [100, { kind: "usage", input: 48200, output: 1300, cost: 0.12 }],
  [100, { kind: "done" }],
];

const levels = ["low", "medium", "high", "xhigh", "max"];
const models: Record<string, ModelInfo[]> = {
  claude: [
    { id: "opus", name: "Opus 5.5", description: "For complex work and everyday tasks", efforts: levels, defaultEffort: null, isDefault: false },
    { id: "sonnet", name: "Sonnet 5.5", description: "Most efficient for simpler tasks", efforts: levels, defaultEffort: null, isDefault: false },
    { id: "fable", name: "Fable 5.1", description: "For your toughest challenges", efforts: levels, defaultEffort: null, isDefault: false },
    { id: "haiku", name: "Haiku 5.5", description: "Fastest for quick answers", efforts: levels, defaultEffort: null, isDefault: false },
    { id: "claude-haiku-4-5-20251001", name: "Haiku 4.5", description: "Fastest for quick answers", efforts: [], defaultEffort: null, isDefault: false },
  ],
  codex: [
    { id: "gpt-6.1-sol", name: "GPT-6.1-Sol", description: "Latest workhorse model for coding and everyday work.", efforts: [...levels, "ultra"], defaultEffort: "low", isDefault: true },
    { id: "gpt-6-astra", name: "GPT-6-Astra", description: "Frontier intelligence for the most demanding work.", efforts: [...levels, "ultra"], defaultEffort: "medium", isDefault: false },
    { id: "gpt-6-luna", name: "GPT-6-Luna", description: "Fast and affordable model for easier tasks.", efforts: levels, defaultEffort: "medium", isDefault: false },
  ],
};

export const agent: AgentClient | null = {
  detect: async () => [
    { id: "claude", name: "Claude Code", path: "/usr/local/bin/claude", version: "2.1.319 (Claude Code)" },
    { id: "codex", name: "Codex", path: "/opt/homebrew/bin/codex", version: "codex-cli 0.167.0" },
  ],
  models: async (provider) => { await new Promise((r) => setTimeout(r, 400)); return models[provider]; },
  run(_turn, onEvent) {
    let stopped = false;
    void (async () => {
      for (const [wait, event] of script) {
        await new Promise((r) => setTimeout(r, wait));
        if (stopped) return;
        onEvent(event);
      }
    })();
    return { started: Promise.resolve(), cancel: () => { stopped = true; onEvent({ kind: "done" }); } };
  },
};
