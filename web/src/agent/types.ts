/** The agents the desktop app can run, one per supported CLI. */
export type AgentId = "claude" | "codex";

export interface AgentInfo {
  id: AgentId;
  name: string;
  /** Where the CLI was found; null when it is not installed. */
  path: string | null;
  version: string | null;
}

/** What an agent's run reports, the same for every agent (see src-tauri/src/agent.rs). */
export type AgentEvent =
  | { kind: "session"; id: string }
  | { kind: "text"; text: string }
  /** Sent when a tool call starts and again, with the same id, when it ends. */
  | { kind: "tool"; id: string; name: string; input: unknown; status: "running" | "done" | "error"; output: string | null }
  /** What the turn cost, sent just before `done`. */
  | { kind: "usage"; input: number; output: number; cost: number | null }
  | { kind: "done" }
  | { kind: "error"; message: string };

/** What to run. A blank `model` or `effort` leaves the choice to the agent's own settings. */
export interface AgentTurn {
  provider: AgentId;
  prompt: string;
  session: string | null;
  model: string;
  effort: string;
}

/** A model the agent lists for itself (see `agent_models` in src-tauri/src/agent.rs). */
export interface ModelInfo {
  /** What the agent takes as its model setting. */
  id: string;
  name: string;
  description: string;
  /** The reasoning levels this model supports, lowest first; empty when there is none to choose. */
  efforts: string[];
  defaultEffort: string | null;
  /** The agent's own default model. */
  isDefault: boolean;
}

export interface AgentRun {
  /** Stops the run; its events end with `done`. */
  cancel(): void;
  /** Settles when the agent has started (or failed to). */
  started: Promise<void>;
}

/** Desktop only: Binfera runs no model, so this drives the analyst's own Claude Code or Codex. */
export interface AgentClient {
  detect(): Promise<AgentInfo[]>;
  /** The models the agent can run, as it lists them. */
  models(provider: AgentId): Promise<ModelInfo[]>;
  /** One chat turn. Pass the session id of an earlier turn to continue that conversation. */
  run(turn: AgentTurn, onEvent: (e: AgentEvent) => void): AgentRun;
}
