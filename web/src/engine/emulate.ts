// Isolated p-code emulation (binfera/src/emulate.rs) for the Emulate tab: request building, the
// engine's 64-bit JSON, and decoding what a run wrote. Imports are stubs; no host API ever runs.

/** A machine word as the engine printed it: a number when exact in JavaScript, else its decimal digits. */
export type Word = number | string;

export interface MemoryOutput { address: Word; size: Word; data: number[]; truncated: boolean }
export interface ImportCall { name: string; slot: Word; return_address: Word; args: Word[]; signature_known: boolean; return_value: Word }
export interface EmulationResult {
  address: Word;
  stop: { kind: string; address: Word; detail: string };
  steps: number;
  return_value: Word;
  registers: Record<string, Word>;
  calls: ImportCall[];
  writes: MemoryOutput[];
  memory: MemoryOutput[];
  warnings: string[];
}
export interface CallSiteResult { caller: Word; site: Word; reached: boolean; call_writes?: MemoryOutput[]; result: EmulationResult }
export interface CallSitesResult { address: Word; total_sites: number; truncated: boolean; sites: CallSiteResult[] }

/** Defaults below the engine's caps (10M steps, 60 s, 1 MiB written). */
export const LIMITS = { max_steps: 2_000_000, timeout_ms: 5_000, max_calls: 256, max_write_bytes: 65_536 } as const;
/** Call-site batches share one timeout, so they get a longer one. */
export const SITE_LIMITS = { ...LIMITS, timeout_ms: 15_000 } as const;
export const MAX_SITES = 64;
/** Input buffers: the engine maps at most 1 MiB of initial memory per request. */
export const MAX_BUFFER = 64 * 1024;
const MAX_INPUT = 1 << 20;

/** The engine's arguments for an emulation run, shared by the browser worker and the desktop build. */
export function emulateArgs(sample: string, address: number, callSites?: number): string[] {
  const args = [sample, "--emulate", `0x${address.toString(16)}`, "--emulate-request"];
  if (callSites) args.push("--emulate-call-sites", "--emulate-max-sites", String(Math.max(1, Math.min(128, Math.floor(callSites)))));
  return args;
}

export type ArgKind = "auto" | "int" | "hex" | "utf8" | "utf16";
export interface ArgInput {
  kind: ArgKind; text: string;
  /** Buffer capacity in bytes; blank means the input plus 256. */ size?: string;
  /** The parameter is a pointer, so an empty value is an empty buffer rather than 0. */ pointer?: boolean;
  /** The parameter as the prototype declares it. */ decl?: string;
}

export class InputError extends Error {}

/** Parses an integer argument: decimal, 0x hex, or negative (two's complement at the pointer width). */
export function parseWord(text: string, ptrSize: number): bigint {
  const t = text.trim().replace(/_/g, "");
  if (!t) return 0n;
  const negative = t.startsWith("-");
  const body = negative ? t.slice(1) : t;
  if (!/^(0x[0-9a-f]+|\d+)$/i.test(body)) throw new InputError(`"${text}" is not a number`);
  let v = BigInt(body);
  const bits = BigInt(ptrSize * 8), max = (1n << bits) - 1n;
  if (negative) v = ((1n << bits) - v) & max;
  if (v > max) throw new InputError(`${text} does not fit in ${ptrSize * 8} bits`);
  return v;
}

/** The bytes a buffer argument starts with. */
export function bufferBytes(kind: Exclude<ArgKind, "int" | "auto">, text: string): Uint8Array {
  if (kind === "hex") {
    const h = text.replace(/0x/gi, "").replace(/[\s,]/g, "");
    if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new InputError("Bytes need pairs of hex digits");
    return Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
  }
  // Escapes let a string carry the bytes an encrypted blob needs.
  const s = text.replace(/\\x([0-9a-f]{2})|\\u([0-9a-f]{4})|\\n|\\r|\\t|\\0|\\\\/gi, (m, x, u) =>
    x ? String.fromCharCode(parseInt(x, 16)) : u ? String.fromCharCode(parseInt(u, 16)) : ({ "\\n": "\n", "\\r": "\r", "\\t": "\t", "\\0": "\0", "\\\\": "\\" } as Record<string, string>)[m]);
  if (kind === "utf16") {
    const out = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); out[2 * i] = c & 0xff; out[2 * i + 1] = c >> 8; }
    return out;
  }
  // \xNN escapes are raw bytes in UTF-8 input too, so encode code points above 0xff only.
  return /[^\0-\xff]/.test(s) ? new TextEncoder().encode(s) : Uint8Array.from(s, (c) => c.charCodeAt(0));
}

/** What an "auto" argument's text means: 0x10 or -1 a number, "text" or L"wide" a string, 32 3f bytes,
 * anything else plain text. An empty pointer argument is an empty buffer. */
export function resolveArg(arg: ArgInput): { kind: Exclude<ArgKind, "auto">; text: string } {
  if (arg.kind !== "auto") return { kind: arg.kind, text: arg.text };
  const t = arg.text.trim();
  if (!t) return arg.pointer ? { kind: "hex", text: "" } : { kind: "int", text: "0" };
  let m = /^L"([\s\S]*)"$/.exec(t);
  if (m) return { kind: "utf16", text: m[1] };
  m = /^"([\s\S]*)"$/.exec(t) ?? /^'([\s\S]*)'$/.exec(t);
  if (m) return { kind: "utf8", text: m[1] };
  if (/^-?(0x[0-9a-f_]+|[\d_]+)$/i.test(t)) return { kind: "int", text: t };
  if (/^(0x)?[0-9a-f]{2}([\s,]*(0x)?[0-9a-f]{2})*$/i.test(t)) return { kind: "hex", text: t };
  return { kind: "utf8", text: arg.text };
}

/** A short note on how an argument will be passed, or why it cannot be. */
export function describeArg(arg: ArgInput, ptrSize: number): { text: string; error?: boolean } {
  const { kind, text } = resolveArg(arg);
  try {
    if (kind === "int") { parseWord(text, ptrSize); return { text: "Number" }; }
    const n = bufferBytes(kind, text).length;
    if (!n) return { text: "Empty buffer" };
    const bytes = `${n} byte${n === 1 ? "" : "s"}`;
    return { text: kind === "hex" ? bytes : kind === "utf16" ? `UTF-16 text, ${bytes}` : `Text, ${bytes}` };
  } catch (e) {
    return { text: (e as Error).message, error: true };
  }
}

/** Where input buffers go: clear of every section, at addresses that fit 32-bit pointers. */
export function bufferBase(sections: { va: number; vsize: number; size: number }[], need: number): number {
  for (let base = 0x2000_0000; base > 0x10_0000; base -= 0x100_0000) {
    if (sections.every((s) => base + need <= s.va || s.va + Math.max(s.vsize, s.size) <= base)) return base;
  }
  throw new InputError("No free address range for the input buffers");
}

export interface BuiltRequest {
  /** JSON for `--emulate-request`, with exact 64-bit integers. */
  json: string;
  /** Each buffer argument's address and capacity, by argument index. */
  buffers: Map<number, { address: number; size: number }>;
}

/** The emulation request for `address` with these arguments and the default limits. */
export function buildRequest(address: number, args: ArgInput[], ptrSize: number, sections: { va: number; vsize: number; size: number }[], limits: Record<string, number> = LIMITS): BuiltRequest {
  const slots: bigint[] = [];
  const buffers = new Map<number, { address: number; size: number }>();
  const memory: { address: number; data: Uint8Array }[] = [];
  const pending: { i: number; data: Uint8Array; size: number }[] = [];
  args.forEach((input, i) => {
    const arg = { ...input, ...resolveArg(input) };
    if (arg.kind === "int") { slots.push(parseWord(arg.text, ptrSize)); return; }
    const data = bufferBytes(arg.kind, arg.text);
    const size = arg.size?.trim() ? Number(parseWord(arg.size, 4)) : data.length + 256;
    if (size < Math.max(1, data.length)) throw new InputError(`Buffer ${i + 1} is smaller than its input`);
    if (size > MAX_BUFFER) throw new InputError(`Buffers are limited to ${MAX_BUFFER / 1024} KiB`);
    pending.push({ i, data, size });
    slots.push(0n);
  });
  const stride = 0x1_0000 + MAX_BUFFER;
  if (pending.reduce((n, p) => n + p.size, 0) > MAX_INPUT) throw new InputError("Input buffers are limited to 1 MiB in total");
  if (pending.length) {
    const base = bufferBase(sections, stride * pending.length);
    pending.forEach((p, k) => {
      const at = base + k * stride;
      const data = new Uint8Array(p.size);
      data.set(p.data);
      memory.push({ address: at, data });
      buffers.set(p.i, { address: at, size: p.size });
      slots[p.i] = BigInt(at);
    });
  }
  const json = `{"address":${address},"args":[${slots.join(",")}],"memory":[${memory.map((m) => `{"address":${m.address},"data":[${m.data.join(",")}]}`).join(",")}],`
    + `"capture":[${[...buffers.values()].map((b) => `{"address":${b.address},"size":${b.size}}`).join(",")}],`
    + Object.entries(limits).map(([k, v]) => `"${k}":${v}`).join(",") + "}";
  return { json, buffers };
}

/** JSON.parse that keeps integers beyond 2^53 exact, as decimal strings. */
export function parseExact<T>(text: string): T {
  let out = "", i = 0, inString = false;
  while (i < text.length) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === "\\") { out += text[i + 1] ?? ""; i += 2; continue; }
      if (c === '"') inString = false;
      i++;
    } else if (c === '"') { inString = true; out += c; i++; }
    else if (c >= "0" && c <= "9") {
      let j = i;
      while (j < text.length && /[0-9.eE+-]/.test(text[j])) j++;
      const token = text.slice(i, j);
      out += /^\d{16,}$/.test(token) && !Number.isSafeInteger(Number(token)) ? `"${token}"` : token;
      i = j;
    } else { out += c; i++; }
  }
  return JSON.parse(out) as T;
}

export const big = (w: Word): bigint => BigInt(w);
export const hexWord = (w: Word) => "0x" + big(w).toString(16);
/** A word as an address the UI can navigate to, when it is exact. */
export const addressOf = (w: Word): number | null => { const n = Number(w); return Number.isSafeInteger(n) ? n : null; };

export interface DecodedText { encoding: "ASCII" | "UTF-8" | "UTF-16LE"; text: string }

const printable = (c: number) => c === 9 || c === 10 || c === 13 || (c >= 0x20 && c < 0x7f);

/** Readable text in written bytes, up to the first terminator, or null when it does not look like text. */
export function decodeText(data: number[]): DecodedText | null {
  if (!data.length) return null;
  // UTF-16LE: mostly zero high bytes at odd offsets.
  if (data.length >= 4) {
    let end = data.length - (data.length % 2);
    for (let i = 0; i + 1 < end; i += 2) if (data[i] === 0 && data[i + 1] === 0) { end = i; break; }
    let ok = 0, units = end / 2;
    for (let i = 0; i < end; i += 2) if (data[i + 1] === 0 && printable(data[i])) ok++;
    if (units >= 2 && ok / units >= 0.9) {
      const text = String.fromCharCode(...Array.from({ length: units }, (_, k) => data[2 * k] | (data[2 * k + 1] << 8)));
      return { encoding: "UTF-16LE", text };
    }
  }
  let end = data.indexOf(0);
  if (end < 0) end = data.length;
  if (end < 2) return null;
  const bytes = Uint8Array.from(data.slice(0, end));
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { return null; }
  const chars = [...text];
  const good = chars.filter((ch) => { const c = ch.codePointAt(0)!; return printable(c) || c >= 0xa0; }).length;
  if (good / chars.length < 0.9) return null;
  return { encoding: bytes.some((b) => b >= 0x80) ? "UTF-8" : "ASCII", text };
}

export interface Output { address: Word; data: number[]; size: Word; truncated: boolean; stack: boolean; text: DecodedText | null; label?: string }

const STACK_WINDOW = 1n << 20n;

/** Written ranges, with the synthetic stack's (return addresses, spills) marked as such. */
export function outputs(writes: MemoryOutput[], sp: Word | undefined): Output[] {
  const at = sp === undefined ? null : big(sp);
  return writes.map((w) => {
    const d = at === null ? STACK_WINDOW : big(w.address) - at;
    return { ...w, stack: (d < 0n ? -d : d) < STACK_WINDOW, text: decodeText(w.data) };
  });
}

/** The stack pointer register of a result, whatever the architecture names it. */
export function stackPointer(result: EmulationResult): Word | undefined {
  const r = result.registers;
  return r.RSP ?? r.ESP ?? r.sp ?? r.SP;
}

/** A plain-language stop reason. */
export function stopText(kind: string): string {
  switch (kind) {
    case "returned": return "Finished";
    case "caller_returned": return "Caller finished first";
    case "step_limit": return "Ran too long";
    case "timeout": return "Timed out";
    case "call_limit": return "Too many API calls";
    case "read_fault": return "Read unmapped memory";
    case "write_fault": return "Wrote to unmapped memory";
    case "fetch": return "Jumped to unmapped code";
    case "trap": return "Hit a trap or system call";
    case "unknown_import_abi": return "Called an API it could not model";
    case "unsupported": return "Hit an unsupported instruction";
    default: return kind ? kind.replace(/_/g, " ") : "Stopped";
  }
}

/** Arguments from the decompiled prototype, blank: pointers read as empty buffers, the rest as 0. */
export function argsFromPrototype(text: string | undefined): ArgInput[] {
  const head = (text ?? "").replace(/^\s+/, "").split("{")[0];
  const open = head.indexOf("("), close = head.lastIndexOf(")");
  if (open < 0 || close < open) return [];
  const list = head.slice(open + 1, close).trim();
  if (!list || list === "void") return [];
  return list.split(",").map((p) => p.trim()).filter((p) => p && p !== "...").slice(0, 8)
    .map((decl) => ({ kind: "auto" as const, text: "", decl, ...(decl.includes("*") || decl.includes("[") ? { pointer: true } : {}) }));
}

/** The text a call site produced: its own writes off the stack, best first. */
export function siteOutput(site: CallSiteResult): Output | undefined {
  const sp = stackPointer(site.result);
  const own = outputs(site.call_writes ?? site.result.writes, sp).filter((w) => !w.stack);
  return own.find((w) => w.text) ?? own[0];
}

export const bytesHex = (data: number[]) => data.map((b) => b.toString(16).padStart(2, "0")).join(" ");
