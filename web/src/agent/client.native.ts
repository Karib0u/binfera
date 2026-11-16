// Desktop build's stand-in for client.ts: the agent commands in src-tauri/src/agent.rs.
import { Channel, invoke } from "@tauri-apps/api/core";
import type { AgentClient, AgentEvent, AgentInfo, ModelInfo } from "./types";

let next = 1;

export const agent: AgentClient | null = {
  detect: () => invoke<AgentInfo[]>("agent_detect"),
  models: (provider) => invoke<ModelInfo[]>("agent_models", { provider }),
  run(turn, onEvent) {
    const id = next++;
    const channel = new Channel<AgentEvent>();
    channel.onmessage = onEvent;
    const started = invoke<void>("agent_run", { request: { id, provider: turn.provider, prompt: turn.prompt, session: turn.session, model: turn.model.trim() || null, effort: turn.effort || null }, onEvent: channel });
    return { cancel: () => { void invoke("agent_cancel", { id }); }, started };
  },
};
