// Development only (`vite --mode mock`): an agent that replays a recorded run, tool calls included.
import type { AgentClient, AgentEvent, ModelInfo } from "../agent/types";
import replay from "./agent-replay.json";

// A real Claude Code triage of the WannaCry demo, recorded and converted by scripts/agent-replay.mjs.
const script = replay.events as [number, AgentEvent][];

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
