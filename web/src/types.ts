import type { DemoSample } from "./demos";
import type { ImageInfo } from "./engine/image";
import type { RawCodeOptions } from "./engine/engine.worker";
import type { ShellcodeEncoding } from "./engine/shellcode";

export type Arch = "x86" | "x64" | "aarch64" | "arm" | "mips" | "mipsel" | "cil" | null;
export type AsmRow = [number, string, string];

export interface DecompiledFunction {
  address: number;
  name?: string | null;
  text?: string;
  /** Gaps only; each one makes the output incomplete. */
  warnings?: string[];
  /** Informational (modeled effects, inferred types); not shown in the banner. */
  notes?: string[];
  incomplete?: boolean;
  unknown_callees?: boolean;
  error?: string;
  retry_pending?: boolean;
  /** Instruction listing: [address, hex bytes, text]. */
  asm?: [number, string, string][];
  /** Recovery graph and references, independent of printed code and architecture syntax. */
  cfg?: FunctionGraph;
  calls?: number[];
  data_refs?: { from: number; to: number }[];
  /** Exception funclets that belong to this function's body. */
  labels?: Record<string, string>;
  /** Per line of `text`: instruction addresses of the operations printed on it. Empty when unknown. */
  lines?: number[][];
  /** Stack symbols by offset, from the decompiler. */
  frame?: StackSlot[];
  /** The named parameters of each call, and where the caller puts each argument. */
  call_args?: CallArgument[];
  /** x86 calls with a known stack effect: the call and the bytes its callee pops besides the return address. */
  call_pops?: [number, number][];
  /** The data symbols the text names, with the type class the decompiler gave each. */
  globals?: GlobalSymbol[];
}

export interface CallArgument {
  /** The call instruction. */
  call: number;
  index: number;
  name: string;
  type: string;
  /** The register holding the argument, as the decompiler names it (`RCX`, `R8D`, `x0`). */
  register?: string;
  /** From the stack pointer at the call instruction, for an argument on the stack. */
  stack?: number;
}

export interface GlobalSymbol {
  name: string;
  address: number;
  size: number;
  kind: "float" | "signed" | "unsigned" | "bool" | "pointer" | "unknown";
}

export interface StackSlot {
  name: string;
  /** The register holding a parameter passed in one; `offset` means nothing then. */
  register?: string;
  /** From the stack pointer at entry. */
  offset: number;
  size: number;
  type: string;
  parameter: boolean;
  /** Instruction addresses. */
  reads: number[];
  writes: number[];
  references: number[];
}

export interface FunctionGraph {
  blocks: { address: number; instructions: number[] }[];
  edges: { from: number; to: number; kind: "true" | "false" | "jump" }[];
}

export interface Packing {
  /** The packer, when its own marks name it. */
  packer: string | null;
  evidence: string[];
}

export interface CapaRule {
  name: string;
  namespace: string | null;
  scope: string;
  lib: boolean;
  attack: { id: string; tactic: string; technique: string; subtechnique: string }[];
  mbc: { id: string; objective: string; behavior: string; method: string }[];
  description: string;
  count: number;
  addresses: number[];
  /** Addresses of matched features, keyed by the rule match address. */
  evidence: ReadonlyMap<number, readonly number[]>;
}

export interface CapaResult {
  sample: { md5: string; sha256: string };
  format: string;
  arch: string;
  os: string;
  baseAddress: number | null;
  rules: CapaRule[];
}

export interface StringEntry {
  a: number;
  s: string;
  /** UTF-16 rather than ASCII. */
  w: boolean;
}

export interface Analysis {
  shellcode?: RawCodeOptions & { guessed: boolean; ambiguous: boolean; evidence: string[]; osDetected: boolean; encoding: ShellcodeEncoding; inputSize: number };
  fileWarnings?: string[];
  strings: StringEntry[];
  /** Number found before the address-ordered display limit. */
  stringsTotal: number;
  /** Raw bytes, sections, imports and exports; null until the file is read. */
  image: ImageInfo | null;
  /** Program entry point, when known. */
  entry: number | null;
  fileName: string;
  /** The packed demo this file is, shown by name instead of its SHA-256 file name. */
  demo?: DemoSample;
  size: number;
  /** Signs the file is packed, from the decompiler's first record; null when there are none. */
  packed: Packing | null;
  /** Named by the decompiler's first record; the listing's syntax depends on it. */
  arch: Arch;
  /** Sorted function entry points, known once recovery finishes. */
  order: number[];
  functions: Map<number, DecompiledFunction>;
  names: Map<number, string>;
  /** Retry one browser function with longer limits, retaining its listing and references. */
  retryFunction?: (address: number) => Promise<void>;
  capa: CapaResult | null;
  capaError: string | null;
  decompileError: string | null;
  /** Set when the decompiler refused the file as too large for the browser's memory: nothing is shown. */
  tooLarge: string | null;
  /** Set when only the capability analysis refused it (its limit is lower); functions still show. */
  capaTooLarge: string | null;
  /** Set while the engine, signatures and rules are downloading; null otherwise. */
  loading: { label: string; fraction: number | null } | null;
  settled: boolean;
  done: boolean;
}
