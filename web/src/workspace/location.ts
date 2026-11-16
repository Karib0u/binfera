/** Where the workspace is, as a browser history entry and a shareable URL hash. */
export type Sel = number | "capa" | "strings" | "imports" | "hex" | "file";
export type Tab = "capa" | "functions" | "data";
export interface Loc { sel: Sel; tab: Tab; detail: boolean }
export interface Entry extends Loc { binfera: true; run: number; i: number; at: number | null }
/** What a URL asks for: a demo to open, and the place to show. */
export interface Target { demo?: string; sel?: Sel; layout?: string; at?: number }

const VIEWS: Record<string, Sel> = { overview: "capa", strings: "strings", imports: "imports", sections: "hex", file: "file" };

/** The views in the workspace, written "c+graph+hex" in saved layouts. */
export type CodeView = "c" | "asm" | "graph" | "calls" | "listing" | "hex" | "strings" | "imports";
export type Layout = string;
export const VIEW_NAMES: Record<CodeView, string> = { c: "C", asm: "Asm", graph: "Control flow", calls: "Call graph", listing: "Listing", hex: "Hex", strings: "Strings", imports: "Imports" };

/** The panes a layout names; anything unknown, or nothing, is C beside assembly. "split" is that layout's older name. */
export function panesOf(layout?: string | null): CodeView[] {
  // URLSearchParams reads the + of a hash as a space.
  const named = (layout ?? "").split(/[ +]/).filter((v) => Object.hasOwn(VIEW_NAMES, v)) as CodeView[];
  return named.length ? named : ["c", "asm"];
}

export const locOf = (sel: Sel): Loc => ({ sel, tab: typeof sel === "number" ? "functions" : sel === "capa" ? "capa" : "data", detail: typeof sel === "number" });

export function parseHash(hash = location.hash): Target {
  const p = new URLSearchParams(hash.replace(/^#/, ""));
  const num = (k: string) => { const n = parseInt(p.get(k) ?? "", 16); return Number.isNaN(n) ? undefined : n; };
  const fn = num("fn"), view = p.get("view") ?? "";
  return {
    demo: p.get("demo") ?? undefined,
    sel: fn ?? VIEWS[view],
    layout: fn !== undefined && view ? panesOf(view).join("+") : undefined,
    at: num("at"),
  };
}

export function hashOf(demo: string | undefined, loc: Loc, layout: string, at: number | null) {
  const parts = demo ? [`demo=${encodeURIComponent(demo)}`] : [];
  if (typeof loc.sel === "number") parts.push(`fn=0x${loc.sel.toString(16)}`, `view=${layout}`);
  else if (loc.sel !== "capa") parts.push(`view=${loc.sel === "hex" ? "sections" : loc.sel}`);
  if (at !== null && loc.sel !== "capa") parts.push(`at=0x${at.toString(16)}`);
  return parts.length ? "#" + parts.join("&") : "";
}

export const pageUrl = (hash = "") => location.pathname + location.search + hash;

/** The last place written, so the landing page can return to it after New or browser Back. */
export let lastEntry: { state: Entry; url: string } | null = null;

export function writeEntry(mode: "push" | "replace", state: Entry, url: string) {
  lastEntry = { state, url };
  // Safari throws past 100 history calls in 30 seconds, as holding j can do; the URL just lags then.
  try { history[mode === "push" ? "pushState" : "replaceState"](state, "", url); } catch { /* see above */ }
}
