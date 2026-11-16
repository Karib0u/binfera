// The browser build has no agent: running Claude Code or Codex needs the desktop app. The desktop
// build swaps this module for client.native.ts (see vite.config.ts).
import type { AgentClient } from "./types";

export const agent: AgentClient | null = null;
