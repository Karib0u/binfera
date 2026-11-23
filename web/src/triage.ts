// Triage order for the function list: what the MCP server's `list_functions` offers, computed in the browser.

export interface TriageFunction {
  address: number;
  /** Pseudocode line count, or 0 while the function is still being decompiled. */
  lines: number;
  calls: readonly number[];
}

export interface Signals {
  capabilities: number;
  strings: number;
  imports: number;
  callers: number;
  score: number;
}

export interface TriageInput {
  functions: readonly TriageFunction[];
  /** How many non-library capability rules matched at each function. */
  capabilities: ReadonlyMap<number, number>;
  /** Distinct strings each function references. */
  strings: ReadonlyMap<number, number>;
  /** Distinct imported APIs each function references. */
  imports: ReadonlyMap<number, number>;
  callers: ReadonlyMap<number, readonly number[]>;
}

/** What a function does that an analyst would want named first: capability matches weigh most, then imports,
 *  strings, callers and size. Each term is capped so one noisy signal cannot bury the rest. */
export function importance(input: TriageInput): Map<number, Signals> {
  const out = new Map<number, Signals>();
  for (const f of input.functions) {
    const strings = input.strings.get(f.address) ?? 0, imports = input.imports.get(f.address) ?? 0;
    const capabilities = input.capabilities.get(f.address) ?? 0;
    const callers = input.callers.get(f.address)?.length ?? 0;
    const score = capabilities * 10 + Math.min(strings, 10) + Math.min(imports, 10) * 2 + Math.min(callers, 10) + Math.min(Math.floor(f.lines / 40), 5);
    out.set(f.address, { capabilities, strings, imports, callers, score });
  }
  return out;
}

/** Call-graph depth, leaves first, so callees are named before their callers. Calls into a cycle count as depth 0. */
export function callDepths(functions: readonly TriageFunction[]): Map<number, number> {
  const known = new Map(functions.map((f) => [f.address, f]));
  const memo = new Map<number, number>();
  const active = new Set<number>();
  // Iterative post-order walk: a deep call chain must not overflow the stack.
  for (const root of functions) {
    if (memo.has(root.address)) continue;
    const stack: { address: number; next: number; depth: number }[] = [{ address: root.address, next: 0, depth: 0 }];
    active.add(root.address);
    while (stack.length) {
      const top = stack[stack.length - 1];
      const calls = known.get(top.address)!.calls;
      if (top.next < calls.length) {
        const callee = calls[top.next++];
        if (!known.has(callee)) continue;
        const done = memo.get(callee);
        if (done !== undefined) top.depth = Math.max(top.depth, 1 + done);
        else if (!active.has(callee)) { active.add(callee); stack.push({ address: callee, next: 0, depth: 0 }); }
        continue;
      }
      stack.pop();
      active.delete(top.address);
      memo.set(top.address, top.depth);
      const parent = stack[stack.length - 1];
      if (parent) parent.depth = Math.max(parent.depth, 1 + top.depth);
    }
  }
  return memo;
}

export interface Progress {
  total: number;
  /** Functions the analyst opened. */
  examined: number;
  /** Functions with a name, comment or variable name of the analyst's own. */
  documented: number;
}

/** Library functions are not the analyst's to read; progress counts the rest. */
export function progress(order: readonly number[], library: ReadonlySet<number>, examined: (ad: number) => boolean, documented: (ad: number) => boolean): Progress {
  let total = 0, e = 0, d = 0;
  for (const ad of order) {
    if (library.has(ad)) continue;
    total++;
    if (examined(ad)) e++;
    if (documented(ad)) d++;
  }
  return { total, examined: e, documented: d };
}

export type FnSort = "address" | "importance" | "bottom_up" | "caps" | "name";

const lineCounts = new WeakMap<object, number>();
const linesOf = (f: { text?: string }) => {
  if (!f.text) return 0;
  let n = lineCounts.get(f);
  if (n === undefined) { n = f.text.split("\n").length; lineCounts.set(f, n); }
  return n;
};

/** The functions as triage reads them. Calls come from the references pass once it has settled, else from recovery. */
export function triageFunctions(
  a: { order: readonly number[]; functions: ReadonlyMap<number, { text?: string; calls?: number[] }> },
  callees: ReadonlyMap<number, readonly number[]>,
): TriageFunction[] {
  return a.order.map((address) => {
    const f = a.functions.get(address);
    return { address, lines: f ? linesOf(f) : 0, calls: callees.get(address) ?? f?.calls ?? [] };
  });
}
