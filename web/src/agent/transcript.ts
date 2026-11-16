import type { AgentEvent } from "./types";

export type Tool = { k: "tool"; id: string; name: string; input: unknown; status: "running" | "done" | "error"; output: string | null };
/** `shown` is what the transcript displays when it differs from what was sent (a long canned request). */
export type Item = { k: "user"; text: string } | { k: "text"; text: string } | { k: "error"; text: string } | Tool;

/** Applies one event from the agent to the transcript. Usage and session events are not part of it. */
export function apply(items: Item[], e: AgentEvent): Item[] {
  if (e.kind === "text") return [...items, { k: "text", text: e.text }];
  if (e.kind === "error") return [...items, { k: "error", text: e.message }];
  if (e.kind !== "tool") return items;
  const at = items.findIndex((i) => i.k === "tool" && i.id === e.id);
  if (at < 0) return [...items, { k: "tool", id: e.id, name: e.name, input: e.input, status: e.status, output: e.output }];
  // The end of a call may not repeat its name or input (Claude reports only the result).
  const prev = items[at] as Tool;
  return items.map((i, n) => (n === at ? { ...prev, name: e.name || prev.name, input: e.input ?? prev.input, status: e.status, output: e.output ?? prev.output } : i));
}

/** The first argument of a call, short, so a row reads as "get_function 0x100000978". */
export function brief(input: unknown): string {
  if (!input || typeof input !== "object") return "";
  const first = Object.entries(input as Record<string, unknown>).filter(([k]) => k !== "project_id").map(([, v]) => v).find((v) => typeof v === "string" || typeof v === "number");
  const text = first === undefined ? "" : String(first);
  return text.length > 36 ? text.slice(0, 36) + "…" : text;
}

/** Tools whose result is something the analyst keeps; the transcript points at it. */
export const ARTIFACT_TOOLS: Record<string, { label: string; tab: "reports" | "changes" }> = {
  save_report: { label: "Report saved", tab: "reports" },
  apply_annotations: { label: "Names and comments saved", tab: "changes" },
};

/** What is drawn: a message, or a run of consecutive tool calls folded into one group. */
export type Block = { k: "item"; item: Exclude<Item, Tool>; index: number } | { k: "tools"; tools: Tool[]; index: number };

export function blocks(items: Item[]): Block[] {
  const out: Block[] = [];
  items.forEach((item, index) => {
    if (item.k !== "tool") { out.push({ k: "item", item, index }); return; }
    const last = out[out.length - 1];
    if (last?.k === "tools") last.tools.push(item);
    else out.push({ k: "tools", tools: [item], index });
  });
  return out;
}

/** "get_function ×3, get_references, search_symbols": what a folded group did, in a line. */
export function toolSummary(tools: Tool[]): string {
  const counts = new Map<string, number>();
  for (const t of tools) counts.set(t.name, (counts.get(t.name) ?? 0) + 1);
  const parts = [...counts].map(([name, n]) => (n > 1 ? `${name} ×${n}` : name));
  return parts.length > 3 ? `${parts.slice(0, 3).join(", ")} +${parts.length - 3}` : parts.join(", ");
}

/** Tool calls since the analyst's last message: the running count in the "Working" line. */
export function callsThisTurn(items: Item[]): number {
  let n = 0;
  for (let i = items.length - 1; i >= 0 && items[i].k !== "user"; i--) if (items[i].k === "tool") n++;
  return n;
}
