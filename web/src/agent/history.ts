import type { Item } from "./transcript";
import type { AgentId } from "./types";

/** One conversation with an agent about one file, kept so it can be read again and resumed. */
export interface Conversation {
  id: string;
  provider: AgentId;
  /** The agent's own id for the session; with it the conversation continues where it stopped. */
  session: string | null;
  title: string;
  updated: number;
  items: Item[];
}

const KEEP = 20;
const OUTPUT = 400;

/** The transcript as stored: a long tool output is cut (the agent has its own copy), the rest is kept. */
export function slim(items: Item[]): Item[] {
  return items.map((i) => (i.k === "tool" && i.output && i.output.length > OUTPUT ? { ...i, output: i.output.slice(0, OUTPUT) + "…" } : i));
}

/** Puts a conversation first in the list, replacing its earlier copy, and drops the oldest beyond the limit. */
export function upsert(list: Conversation[], conv: Conversation): Conversation[] {
  return [conv, ...list.filter((c) => c.id !== conv.id)].slice(0, KEEP);
}

export const titleOf = (text: string) => {
  const line = text.trim().split("\n")[0];
  return line.length > 60 ? line.slice(0, 60) + "…" : line;
};
