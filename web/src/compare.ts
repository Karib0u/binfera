// Compares two binaries in the browser. Each side's facts come from its own worker, so no worker
// holds both samples; a further short-lived worker compares the facts. The engine decides what
// matches and what changed, and this file only moves its output around.
import { loadAssets, loadEngine } from "./engine/assets";
import { EngineError, runEngine, TOO_LARGE } from "./engine/run";

export type Verdict = "identical" | "equivalent" | "changed";
export type Method = "exact" | "shape" | "name" | "propagated" | "fuzzy" | "duplicate" | "manual";
export type Reason = "code" | "string" | "import" | "callee";
export type Status = "same" | "changed" | "added" | "removed";

export interface InfoSummary { name: string; size: number; sha256: string; format: string; arch: string; image_base: number; entry: number | null; functions: number; instructions: number; packed: boolean; source: string }
export interface Signal { name: string; value: number; weight: number }
export interface Evidence {
  same_instructions: boolean; same_cfg: boolean; blocks: [number, number]; edges: [number, number]; signals?: Signal[];
  strings_only_a?: string[]; strings_only_b?: string[]; imports_only_a?: string[]; imports_only_b?: string[];
  constants_only_a?: number[]; constants_only_b?: number[]; callees_only_a?: FunctionRef[]; callees_only_b?: FunctionRef[];
  rules_only_a?: string[]; rules_only_b?: string[]; rules_both?: string[];
}
export interface FunctionMatch { evidence: Evidence; a_addr: number; b_addr: number; a_name: string | null; b_name: string | null; method: Method; confidence: number; similarity: number; changed: boolean; reasons: Reason[]; a_instructions: number; b_instructions: number }
export interface FunctionRef { address: number; name: string | null; instructions: number; rules?: string[]; strings?: string[]; imports?: string[] }
export interface ChangedItem { name: string; changes: string[] }
export interface ListDelta { added: string[]; removed: string[]; changed: ChangedItem[] }
export interface FileDelta { sections: ListDelta; imports: ListDelta; exports: ListDelta; resources: ListDelta; overlay: string[]; imphash: [string | null, string | null] | null }
export interface RuleSummary { name: string; namespace: string | null; scope: string; attack: string[]; mbc: string[]; addresses: number[]; functions: number[] }
export interface RetargetedRule { name: string; namespace: string | null; lost: number[]; gained: number[] }
export interface CapabilityDelta { added: RuleSummary[]; removed: RuleSummary[]; retargeted: RetargetedRule[]; unchanged: number; unmapped: number; attack_added: string[]; attack_removed: string[]; similarity: number | null }
export interface Similarity { overall: number; code: number | null; imports: number | null; strings: number | null; capabilities: number | null }
export interface DiffDocument {
  verdict: Verdict; inputs: [InfoSummary, InfoSummary]; warnings: string[]; functions_compared: boolean;
  file_delta: FileDelta; matches: FunctionMatch[]; unmatched_a: FunctionRef[]; unmatched_b: FunctionRef[];
  capability_delta: CapabilityDelta | null; similarity: Similarity;
}

export interface Instruction { address: number; bytes: string; text: string; norm: string; note?: string; call?: number }
export interface InstructionRow { status: Status; a: Instruction | null; b: Instruction | null }
export interface BlockRow { status: Status; a: number | null; b: number | null; similarity: number; rows: InstructionRow[] }
export interface GraphEdge { from: number; to: number; kind: string }
export interface PairDiff { a: number; b: number; a_name: string | null; b_name: string | null; blocks: BlockRow[]; a_edges: GraphEdge[]; b_edges: GraphEdge[]; similarity: number }

interface Side {
  file: File;
  /** The fingerprint without listings: the header line, then one line per function. */
  facts: string;
  header: string;
  /** Each function's listing line, kept here so a pair can be diffed without recovering again. */
  details: Map<number, string>;
  capa: string | null;
}

export interface Comparison {
  document: DiffDocument; sides: [Side, Side];
  /** C a full analysis of that side has already produced, so nothing is decompiled twice. */
  known?: (side: "a" | "b", address: number) => string | undefined;
}

export interface FunctionListing { address: number; name: string | null; blocks: { address: number; instructions: Instruction[]; successors: { target: number; kind: string }[] }[] }

/** One function's listing, as its fingerprint holds it. */
export function functionListing(c: Comparison, side: "a" | "b", address: number): FunctionListing | null {
  const line = c.sides[side === "a" ? 0 : 1].details.get(address);
  return line === undefined ? null : JSON.parse(line) as FunctionListing;
}
export interface Stage { label: string; fraction: number | null }

const DETAIL = '{"record":"detail"';
const SERIAL_ABOVE = 16 << 20;

/** The engine's message for a file it cannot read, in terms of the file the user chose. */
function refusal(file: File, e: unknown) {
  const text = String((e as Error)?.message ?? e).replace(/^error: /, "");
  if (e instanceof EngineError && e.code === TOO_LARGE) return `${file.name} is too large to compare in the browser. ${text}`;
  return /unsupported input format|unknown|invalid/i.test(text) ? `binfera can't read ${file.name} as an executable: ${text}` : `${file.name}: ${text}`;
}

async function fingerprintSide(file: File, module: WebAssembly.Module, signal: AbortSignal): Promise<Side> {
  const sample = await file.arrayBuffer();
  const facts: string[] = [];
  const details = new Map<number, string>();
  let header = "";
  await runEngine({ kind: "fingerprint", module, sample, data: {} }, (line) => {
    if (!line) return;
    if (line.startsWith(DETAIL)) {
      const at = /"address":(\d+)/.exec(line);
      if (at) details.set(Number(at[1]), line);
    } else {
      if (!header) header = line;
      facts.push(line);
    }
  }, signal).catch((e) => { if (signal.aborted) throw e; throw new Error(refusal(file, e)); });
  return { file, facts: facts.join("\n") + "\n", header, details, capa: null };
}

export async function compareFiles(a: File, b: File, onStage: (s: Stage) => void, signal: AbortSignal): Promise<Comparison> {
  onStage({ label: "Loading the analysis engine", fraction: null });
  const module = await loadEngine((p) => { if (p) onStage(p); });
  const serial = a.size > SERIAL_ABOVE || b.size > SERIAL_ABOVE;
  onStage({ label: "Reading functions", fraction: null });
  let left: Side, right: Side;
  if (serial) {
    left = await fingerprintSide(a, module, signal);
    right = await fingerprintSide(b, module, signal);
  } else {
    [left, right] = await Promise.all([fingerprintSide(a, module, signal), fingerprintSide(b, module, signal)]);
  }

  const assets = await loadAssets(null, (p) => { if (p) onStage(p); });
  onStage({ label: "Matching capabilities", fraction: null });
  const notes: string[] = [];
  const matchRules = async (side: Side) => {
    let json = "";
    const sample = await side.file.arrayBuffer();
    try {
      await runEngine({ kind: "capa", module: assets.module, sample, data: assets.data("capa"), rules: assets.rules }, (l) => { json += l; }, signal);
      side.capa = json;
    } catch (e) {
      if (signal.aborted) throw e;
      // Functions and file structure still compare.
      notes.push(`capabilities were not compared: ${side.file.name}: ${String((e as Error)?.message ?? e).replace(/^error: /, "")}`);
    }
  };
  if (serial) {
    await matchRules(left);
    await matchRules(right);
  } else {
    await Promise.all([matchRules(left), matchRules(right)]);
  }

  onStage({ label: "Comparing", fraction: null });
  const files: Record<string, string> = { "a.idx": left.facts, "b.idx": right.facts };
  const args = ["/a.idx", "/b.idx", "--json"];
  if (left.capa && right.capa) {
    files["a.json"] = left.capa;
    files["b.json"] = right.capa;
    args.push("--capa-a", "/a.json", "--capa-b", "/b.json");
  } else {
    args.push("--no-capabilities");
  }
  let out = "";
  await runEngine({ kind: "diff", module, sample: new ArrayBuffer(0), data: {}, files, args }, (l) => { out += l; }, signal);
  const document = JSON.parse(out) as DiffDocument;
  document.warnings.push(...notes);
  // The workers only ever see `/sample.bin`.
  document.inputs[0].name = a.name;
  document.inputs[1].name = b.name;
  return { document, sides: [left, right] };
}

/** One matched pair down to its instructions, from the listings already held. */
export async function pairDiff(c: Comparison, a: number, b: number, module: WebAssembly.Module, signal: AbortSignal): Promise<PairDiff> {
  const [left, right] = c.sides;
  const listing = (side: Side, at: number) => {
    const line = side.details.get(at);
    if (line === undefined) throw new Error(`no listing for function 0x${at.toString(16)}`);
    return `${side.header}\n${line}\n`;
  };
  let out = "";
  await runEngine({
    kind: "diff", module, sample: new ArrayBuffer(0), data: {},
    files: {
      "a.idx": listing(left, a), "b.idx": listing(right, b),
      "map.json": JSON.stringify(c.document.matches.map((m) => [m.a_addr, m.b_addr])),
    },
    args: ["/a.idx", "/b.idx", "--pair", `0x${a.toString(16)}:0x${b.toString(16)}`, "--function-map", "/map.json", "--json"],
  }, (l) => { out += l; }, signal);
  return JSON.parse(out) as PairDiff;
}

/** The decompiled C of one function of one side, with the data files that file's decompiler reads. */
export async function decompileOne(c: Comparison, side: "a" | "b", address: number, signal: AbortSignal): Promise<string> {
  const index = side === "a" ? 0 : 1;
  const { arch, format } = c.document.inputs[index];
  const assets = await loadAssets(arch === "x64" || arch === "x86" ? arch : null, () => {}, format === "pe");
  const sample = await c.sides[index].file.arrayBuffer();
  let out = "";
  await runEngine({ kind: "decompileOne", module: assets.module, sample, data: assets.data("decompile"), address }, (l) => { out += l + "\n"; }, signal);
  const parsed = JSON.parse(out) as { text?: string; c?: string; functions?: { text?: string; c?: string }[] };
  const first = parsed.functions?.[0] ?? parsed;
  return first.text ?? first.c ?? out;
}

export const engineModule = () => loadEngine(() => {});
