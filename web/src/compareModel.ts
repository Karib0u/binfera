// What a comparison means to someone reading it: which function goes with which, what to look at
// first, and each change in a few plain words. The engine's document supplies every fact; nothing
// here decides what matches or what differs.
import type { DiffDocument, FunctionMatch, FunctionRef } from "./compare";

export type Side = "a" | "b";
/** A matched pair, or a function that exists on one side only. */
export type Target = { kind: "match"; m: FunctionMatch } | { kind: Side; f: FunctionRef };
export type Mark = "changed" | "added" | "removed" | "same";

export interface Change { key: string; target: Target; status: Exclude<Mark, "same">; reason: string; score: number; size: number }

export const keyOf = (t: Target) => (t.kind === "match" ? `m:${t.m.a_addr}:${t.m.b_addr}` : `${t.kind}:${t.f.address}`);
export const addressOf = (t: Target, side: Side): number | null =>
  t.kind === "match" ? (side === "a" ? t.m.a_addr : t.m.b_addr) : t.kind === side ? t.f.address : null;

/** Pairs made by hand take their functions out of whatever the engine said about them. */
export function withManual(d: DiffDocument, manual: FunctionMatch[]) {
  if (!manual.length) return { matches: d.matches, onlyA: d.unmatched_a, onlyB: d.unmatched_b };
  const a = new Set(manual.map((m) => m.a_addr)), b = new Set(manual.map((m) => m.b_addr));
  const broken = d.matches.filter((m) => a.has(m.a_addr) || b.has(m.b_addr));
  return {
    matches: [...manual, ...d.matches.filter((m) => !a.has(m.a_addr) && !b.has(m.b_addr))],
    // The old partner of a function paired by hand now has none.
    onlyA: [...d.unmatched_a.filter((f) => !a.has(f.address)), ...broken.filter((m) => !a.has(m.a_addr)).map((m): FunctionRef => ({ address: m.a_addr, name: m.a_name, instructions: m.a_instructions }))],
    onlyB: [...d.unmatched_b.filter((f) => !b.has(f.address)), ...broken.filter((m) => !b.has(m.b_addr)).map((m): FunctionRef => ({ address: m.b_addr, name: m.b_name, instructions: m.b_instructions }))],
  };
}

/** A pair the reader made: there is no evidence behind it beyond their judgement. */
export function manualPair(a: FunctionRef, b: FunctionRef): FunctionMatch {
  return {
    a_addr: a.address, b_addr: b.address, a_name: a.name, b_name: b.name, method: "manual", confidence: 1, similarity: 0, changed: true, reasons: [],
    a_instructions: a.instructions, b_instructions: b.instructions,
    evidence: { same_instructions: false, same_cfg: false, blocks: [0, 0], edges: [0, 0] },
  };
}

/** What to show for a function of one file: its pair if it has one. */
export function opener(d: DiffDocument, side: Side, at: number, manual: FunctionMatch[] = []): Target | null {
  const all = withManual(d, manual);
  const m = all.matches.find((x) => (side === "a" ? x.a_addr : x.b_addr) === at);
  if (m) return { kind: "match", m };
  const f = (side === "a" ? all.onlyA : all.onlyB).find((x) => x.address === at);
  return f ? { kind: side, f } : null;
}

/** Every function of one file, whether it was matched or not. */
export function functionsOf(d: DiffDocument, side: Side): FunctionRef[] {
  const matched = d.matches.map((m): FunctionRef => (side === "a"
    ? { address: m.a_addr, name: m.a_name, instructions: m.a_instructions }
    : { address: m.b_addr, name: m.b_name, instructions: m.b_instructions }));
  return [...matched, ...(side === "a" ? d.unmatched_a : d.unmatched_b)].sort((x, y) => x.address - y.address);
}

/** For the function list of one file: what happened to each function. */
export function marksOf(d: DiffDocument, side: Side, manual: FunctionMatch[] = []): Map<number, Mark> {
  const all = withManual(d, manual), out = new Map<number, Mark>();
  for (const m of all.matches) out.set(side === "a" ? m.a_addr : m.b_addr, m.changed ? "changed" : "same");
  for (const f of side === "a" ? all.onlyA : all.onlyB) out.set(f.address, side === "a" ? "removed" : "added");
  return out;
}

const plural = (n: number, one: string, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const list = (names: string[], most = 2) => names.slice(0, most).join(", ") + (names.length > most ? ` and ${names.length - most} more` : "");
const shortString = (s: string) => (s.length > 34 ? `${s.slice(0, 20)}…${s.slice(-10)}` : s);

function strings(only: string[] = [], other: string[] = [], word: string) {
  if (only.length === 1 && other.length === 1) return null; // said once, as a replacement
  return only.length ? `${word} ${only.length === 1 ? `"${shortString(only[0])}"` : `${only.length} strings`}` : null;
}

/** A pair's change in plain words, the most telling first, and how much it deserves attention. */
function matchChange(m: FunctionMatch, newB: Set<number>): { reason: string; score: number } {
  const e = m.evidence, parts: string[] = [];
  let score = 0;
  if (e.rules_only_b?.length) { parts.push(`Gained: ${list(e.rules_only_b)}`); score += 100; }
  if (e.rules_only_a?.length) { parts.push(`Lost: ${list(e.rules_only_a)}`); score += 90; }
  if (e.imports_only_b?.length) { parts.push(`Now calls ${list(e.imports_only_b)}`); score += 40; }
  if (e.imports_only_a?.length) { parts.push(`No longer calls ${list(e.imports_only_a)}`); score += 30; }
  if (e.callees_only_b?.length) {
    const fresh = e.callees_only_b.filter((f) => newB.has(f.address)).length;
    parts.push(fresh ? `Now calls ${plural(fresh, "new function")}` : `Now calls ${plural(e.callees_only_b.length, "other function")}`);
    score += fresh ? 25 : 12;
  }
  if (e.callees_only_a?.length) { parts.push(`No longer calls ${plural(e.callees_only_a.length, "function")}`); score += 10; }
  const [sa, sb] = [e.strings_only_a ?? [], e.strings_only_b ?? []];
  if (sa.length === 1 && sb.length === 1) parts.push(`String "${shortString(sa[0])}" is now "${shortString(sb[0])}"`);
  else {
    const added = strings(sb, sa, "New string"), gone = strings(sa, sb, "Drops");
    if (added) parts.push(added);
    if (gone) parts.push(gone);
  }
  if (sa.length || sb.length) score += 15;
  if (e.constants_only_a?.length || e.constants_only_b?.length) { parts.push("Constants differ"); score += 5; }
  if (!parts.length) parts.push(!e.same_cfg ? `Control flow changed, ${m.a_instructions} → ${m.b_instructions} instructions` : `Instructions differ, ${m.a_instructions} → ${m.b_instructions}`);
  return { reason: parts.slice(0, 2).join(". "), score };
}

function oneSideChange(f: FunctionRef): { reason: string; score: number } {
  const parts: string[] = [];
  let score = 10;
  if (f.rules?.length) { parts.push(list(f.rules)); score += 100; }
  if (f.imports?.length) { parts.push(`Calls ${list(f.imports)}`); score += 40; }
  if (f.strings?.length) { parts.push(f.strings.length === 1 ? `Uses "${shortString(f.strings[0])}"` : `Uses ${f.strings.length} strings`); score += 15; }
  if (!parts.length) parts.push(plural(f.instructions, "instruction"));
  return { reason: parts.slice(0, 2).join(". "), score };
}

/** Everything that differs, what most deserves a look first. Size breaks ties, then address, so the order is stable. */
export function changesOf(d: DiffDocument, manual: FunctionMatch[] = []): Change[] {
  const all = withManual(d, manual), newB = new Set(all.onlyB.map((f) => f.address));
  const out: Change[] = [];
  for (const m of all.matches) {
    if (!m.changed) continue;
    const target: Target = { kind: "match", m };
    if (m.method === "manual") out.push({ key: keyOf(target), target, status: "changed", reason: "Paired by hand", score: 1000, size: m.b_instructions });
    else out.push({ key: keyOf(target), target, status: "changed", size: Math.max(m.a_instructions, m.b_instructions), ...matchChange(m, newB) });
  }
  for (const [side, status, fns] of [["b", "added", all.onlyB], ["a", "removed", all.onlyA]] as const) {
    for (const f of fns) {
      const target: Target = { kind: side, f };
      out.push({ key: keyOf(target), target, status, size: f.instructions, ...oneSideChange(f) });
    }
  }
  const at = (c: Change) => addressOf(c.target, "b") ?? addressOf(c.target, "a") ?? 0;
  return out.sort((x, y) => y.score - x.score || y.size - x.size || at(x) - at(y));
}

/** The comparison in a few sentences: what a reader would otherwise have to piece together. */
export function summaryOf(d: DiffDocument): { headline: string; details: string[] } {
  if (d.verdict === "identical") return { headline: "The two files are byte for byte the same.", details: [] };
  if (d.verdict === "equivalent") return { headline: "The bytes differ, but nothing compared here does.", details: ["Functions, capabilities and file contents all line up."] };
  const cap = d.capability_delta, changed = d.matches.filter((m) => m.changed).length;
  const adds = [cap?.added.length ? plural(cap.added.length, "capability", "capabilities") : "", d.unmatched_b.length ? plural(d.unmatched_b.length, "function") : ""].filter(Boolean);
  const loses = [cap?.removed.length ? plural(cap.removed.length, "capability", "capabilities") : "", d.unmatched_a.length ? plural(d.unmatched_a.length, "function") : ""].filter(Boolean);
  const said = [adds.length ? `adds ${adds.join(" and ")}` : "", loses.length ? `loses ${loses.join(" and ")}` : "", changed ? `changes ${plural(changed, "function")}` : ""].filter(Boolean);
  const headline = !d.functions_compared ? "These files are for different architectures, so their functions were not compared."
    : said.length ? `B ${said.slice(0, -1).join(", ")}${said.length > 1 ? " and " : ""}${said[said.length - 1]}.`
    : "The functions line up. Only the file's contents differ.";
  const details: string[] = [];
  const imports = d.file_delta.imports;
  if (imports.added.length || imports.removed.length) {
    const short = (n: string) => n.split("!").pop() ?? n;
    details.push(`Imports: ${[...imports.added.slice(0, 3).map((n) => "+" + short(n)), ...imports.removed.slice(0, 3).map((n) => "−" + short(n))].join(", ")}${imports.added.length + imports.removed.length > 6 ? ` and ${imports.added.length + imports.removed.length - 6} more` : ""}`);
  }
  // A rule that also matches elsewhere counts as unchanged, yet new code that does it is news.
  const known = new Set(cap?.added.map((r) => r.name));
  const rules = [...new Set(d.unmatched_b.flatMap((f) => f.rules ?? []))].filter((r) => !known.has(r));
  if (rules.length) details.push(`New code also matches: ${list(rules, 3)}`);
  const lost = new Set(cap?.removed.map((r) => r.name));
  const gone = [...new Set(d.unmatched_a.flatMap((f) => f.rules ?? []))].filter((r) => !lost.has(r));
  if (gone.length) details.push(`Code only in A also matched: ${list(gone, 3)}`);
  return { headline, details };
}

/** The strings code refers to, read from a side's fingerprint lines: what the strings score was made from. */
export function referencedStrings(facts: string): Set<string> {
  const out = new Set<string>();
  for (const line of facts.split("\n")) {
    if (!line.includes('"refs"')) continue;
    try {
      for (const r of (JSON.parse(line) as { refs?: { k: string; v: unknown }[] }).refs ?? []) if (r.k === "str") out.add(String(r.v));
    } catch { /* not a function line */ }
  }
  return out;
}

export function stringsDelta(a: Set<string>, b: Set<string>) {
  return { removed: [...a].filter((s) => !b.has(s)).sort(), added: [...b].filter((s) => !a.has(s)).sort(), same: [...a].filter((s) => b.has(s)).length };
}

/** Which of a target's two addresses to go to, when a place in one file should show in the other. */
export function counterpart(d: DiffDocument, side: Side, at: number, manual: FunctionMatch[] = []): number | null {
  const t = opener(d, side, at, manual);
  return t ? addressOf(t, side === "a" ? "b" : "a") : null;
}
