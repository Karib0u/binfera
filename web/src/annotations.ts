import { rowFlow } from "./graph";
import type { ImageInfo } from "./engine/image";
import type { Arch, AsmRow, DecompiledFunction, StackSlot } from "./types";

// IDA-style annotations of an instruction listing: the parameter each argument-setting
// instruction fills (`mov rcx,rbx ; hFile`), and the stack symbols each instruction uses.

const X86_FAMILIES = [
  ["rax", "eax", "ax", "al", "ah"], ["rcx", "ecx", "cx", "cl", "ch"], ["rdx", "edx", "dx", "dl", "dh"],
  ["rbx", "ebx", "bx", "bl", "bh"], ["rsi", "esi", "si", "sil"], ["rdi", "edi", "di", "dil"],
  ["rbp", "ebp", "bp", "bpl"], ["rsp", "esp", "sp", "spl"],
  ...Array.from({ length: 8 }, (_, i) => [`r${i + 8}`, `r${i + 8}d`, `r${i + 8}w`, `r${i + 8}b`]),
];
const X86_FAMILY = new Map(X86_FAMILIES.flatMap((names) => names.map((n) => [n, names[0]] as const)));

/** One name for a register and its narrower views: `ecx` and `cl` are `rcx`, `w0` is `x0`. */
export function registerFamily(name: string, arch: Arch): string {
  const r = name.toLowerCase().replace(/^\$/, "");
  if (arch === "x86" || arch === "x64") return X86_FAMILY.get(r) ?? r.replace(/^[xy]mm/, "xmm");
  if (arch === "aarch64") {
    const m = /^[xw](\d+)$/.exec(r);
    if (m) return "x" + m[1];
    const v = /^[qdsbh](\d+)$/.exec(r);
    return v ? "v" + v[1] : r;
  }
  return r;
}

/** Instructions whose first operand is read, not written. */
const NO_DESTINATION = /^(cmp|cmn|test|tst|teq|push|call|bl|blr|blx|b|bx|br|ret|retn|nop|bt|cb\w*|tb\w*|j\w*|b\.\w+|st\w*|s[bhwd]|s[wd]c1|sw[lr])$/;

const number = (text: string) => {
  const t = text.trim();
  if (/^-?0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  if (/^-?[0-9][0-9a-f]*h$/i.test(t)) return parseInt(t.slice(0, -1), 16);
  if (/^-?\d+$/.test(t)) return parseInt(t, 10);
  return undefined;
};

function split(text: string): [string, string[]] {
  const sp = text.indexOf(" ");
  if (sp < 0) return [text.toLowerCase(), []];
  const ops: string[] = [];
  let depth = 0, start = sp + 1;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (c === "[" || c === "(" || c === "{") depth++;
    else if (c === "]" || c === ")" || c === "}") depth--;
    else if (c === "," && depth === 0) { ops.push(text.slice(start, i).trim()); start = i + 1; }
  }
  ops.push(text.slice(start).trim());
  return [text.slice(0, sp).toLowerCase(), ops];
}

/** The stack-pointer offset a memory operand names (`dword ptr [esp+10h]` → 16), if it names one. */
function stackOperand(op: string, arch: Arch): number | undefined {
  const m = /\[\s*(esp|rsp|sp)\s*(?:([+-])\s*([0-9a-fx]+h?))?\s*\]$/i.exec(op)
    ?? (arch === "aarch64" || arch === "arm" ? /\[\s*(sp)\s*(?:,\s*#()(-?[0-9a-fx]+))?\s*\]$/i.exec(op) : null);
  if (!m) return undefined;
  if (!m[3]) return 0;
  const value = number(m[3]);
  if (value === undefined) return undefined;
  return m[2] === "-" ? -value : value;
}

/** How far back from a call to look for the instructions that set its arguments up. */
const LOOKBACK = 40;

/**
 * The instructions that set up each named call argument, found by walking back from the call
 * within its block: the nearest write of the argument's register, or the push or store that
 * fills its stack slot. An argument set up elsewhere, or by a path this does not model, is left out.
 */
export function argumentSites(f: Pick<DecompiledFunction, "asm" | "call_args" | "cfg" | "call_pops">, arch: Arch): Map<number, string[]> {
  const out = new Map<number, string[]>();
  const rows = f.asm;
  if (!rows?.length || !f.call_args?.length) return out;
  const index = new Map(rows.map((r, i) => [r[0], i]));
  const blockStarts = new Set(f.cfg?.blocks.map((b) => b.address) ?? []);
  const byCall = new Map<number, typeof f.call_args>();
  for (const arg of f.call_args) {
    const list = byCall.get(arg.call);
    if (list) list.push(arg);
    else byCall.set(arg.call, [arg]);
  }
  const add = (at: number, name: string) => {
    const list = out.get(at);
    if (!list) out.set(at, [name]);
    else if (!list.includes(name)) list.push(name);
  };
  const push = arch === "x64" ? 8 : 4;
  const pops = new Map(f.call_pops ?? []);
  for (const [call, args] of byCall) {
    const at = index.get(call);
    if (at === undefined) continue;
    const registers = new Map<string, string>();
    const stack = new Map<number, string>();
    for (const arg of args) {
      if (arg.register) registers.set(registerFamily(arg.register, arch), arg.name);
      else if (arg.stack !== undefined) stack.set(arg.stack, arg.name);
    }
    let depth = 0;
    const visit = (row: AsmRow) => {
      const [mnemonic, ops] = split(row[2]);
      if (mnemonic === "push" && (arch === "x86" || arch === "x64")) {
        const name = stack.get(depth);
        if (name) { add(row[0], name); stack.delete(depth); }
        depth += push;
        return;
      }
      if (mnemonic === "pop" && (arch === "x86" || arch === "x64")) { depth -= push; return; }
      if ((mnemonic === "sub" || mnemonic === "add") && /^[re]?sp$/i.test(ops[0] ?? "")) {
        const n = number(ops[1] ?? "");
        if (n !== undefined) depth += mnemonic === "sub" ? n : -n;
        return;
      }
      if (NO_DESTINATION.test(mnemonic) || !ops.length) {
        // A store's destination is its last operand on the RISC architectures.
        if ((arch === "aarch64" || arch === "arm") && /^st/.test(mnemonic) && ops.length >= 2) {
          const offset = stackOperand(ops[ops.length - 1], arch);
          const name = offset === undefined ? undefined : stack.get(offset + depth);
          if (name) { add(row[0], name); stack.delete(offset! + depth); }
        }
        return;
      }
      const destination = ops[0];
      const offset = stackOperand(destination, arch);
      if (offset !== undefined) {
        const name = stack.get(offset + depth);
        if (name) { add(row[0], name); stack.delete(offset + depth); }
        return;
      }
      const family = registerFamily(destination.replace(/^\$/, ""), arch);
      const name = registers.get(family);
      if (name) { add(row[0], name); registers.delete(family); }
    };
    // A MIPS call's delay slot runs before the callee.
    if ((arch === "mips" || arch === "mipsel") && rows[at + 1]) visit(rows[at + 1]);
    for (let i = at - 1; i >= 0 && i >= at - LOOKBACK && (registers.size || stack.size); i--) {
      const row = rows[i];
      const kind = rowFlow(row, arch).kind;
      if (kind === "ret" || kind === "jump") break;
      if (kind === "call") {
        // An x86 argument can be pushed before another call (`push x; call GetProcessHeap; push eax`).
        // Step back over a call whose stack effect is known; registers do not survive one.
        const popped = arch === "x86" ? pops.get(row[0]) : undefined;
        if (popped === undefined) break;
        registers.clear();
        depth -= popped;
        if (blockStarts.has(row[0])) break;
        continue;
      }
      visit(row);
      if (blockStarts.has(row[0])) break;
    }
  }
  return out;
}

/** The stack symbols each instruction reads, writes or takes the address of. Calls are left out:
 * the decompiler counts every register argument as read there. */
export function frameUses(f: Pick<DecompiledFunction, "asm" | "frame">, arch: Arch): Map<number, string[]> {
  const out = new Map<number, string[]>();
  if (!f.frame?.length) return out;
  const calls = new Set((f.asm ?? []).filter((r) => rowFlow(r, arch).kind === "call").map((r) => r[0]));
  for (const slot of f.frame) {
    for (const at of [...slot.writes, ...slot.reads, ...slot.references]) {
      if (calls.has(at)) continue;
      const list = out.get(at);
      if (!list) out.set(at, [slot.name]);
      else if (!list.includes(slot.name)) list.push(slot.name);
    }
  }
  return out;
}

type Noted = Pick<DecompiledFunction, "asm" | "call_args" | "call_pops" | "cfg" | "frame">;
const notesCache = new WeakMap<Noted, Map<number, string>>();

/** The comment to show beside each instruction of \p f: the arguments it sets up, then the stack symbols it uses. */
export function instructionNotes(f: Noted | undefined, arch: Arch): Map<number, string> | undefined {
  if (!f || (!f.call_args?.length && !f.frame?.length)) return undefined;
  const cached = notesCache.get(f);
  if (cached) return cached;
  const notes = new Map<number, string>();
  const args = argumentSites(f, arch), uses = frameUses(f, arch);
  for (const at of new Set([...args.keys(), ...uses.keys()])) {
    const names = [...(args.get(at) ?? [])];
    for (const n of uses.get(at) ?? []) if (!names.includes(n)) names.push(n);
    notes.set(at, names.join(", "));
  }
  notesCache.set(f, notes);
  return notes;
}

/** Where a stack symbol lives, as an analyst reads it: its register, or its offset from the stack pointer at entry. */
export function slotLocation(slot: StackSlot, arch: Arch): string {
  if (slot.register) return slot.register.toLowerCase();
  const sp = arch === "x64" ? "rsp" : arch === "x86" ? "esp" : "sp";
  const off = Math.abs(slot.offset).toString(16).toUpperCase();
  return `[${sp}${slot.offset < 0 ? "-" : "+"}${/^[A-F]/.test(off) ? "0" : ""}${off}h]`;
}

/** The function's parameters, then its locals, for a header like IDA's stack variable list. */
export function frameHeader(frame: StackSlot[] | undefined): StackSlot[] {
  if (!frame?.length) return [];
  return [...frame.filter((s) => s.parameter), ...frame.filter((s) => !s.parameter)];
}

/** Lines of a function's frame header in the listing; a huge frame is cut short. */
export const MAX_FRAME_LINES = 48;

/**
 * The import an x86 stub jumps through: `jmp dword ptr [slot]` (FF 25 abs32) on x86, or
 * `jmp qword ptr [rip+rel32]` (FF 25 rel32) on x64. Stubs are not listed as functions, so a call to
 * one would otherwise show only its address.
 */
export function importThunk<T>(image: Pick<ImageInfo, "arch" | "bytes" | "vaToOff">, va: number, slots: ReadonlyMap<number, T>): T | undefined {
  if (image.arch !== "x86" && image.arch !== "x64") return undefined;
  const off = image.vaToOff(va);
  if (off === null || off + 6 > image.bytes.length || image.bytes[off] !== 0xff || image.bytes[off + 1] !== 0x25) return undefined;
  const b = image.bytes;
  const imm = (b[off + 2] | (b[off + 3] << 8) | (b[off + 4] << 16) | (b[off + 5] << 24)) >>> 0;
  const target = image.arch === "x64" ? va + 6 + (imm | 0) : imm;
  return slots.get(target);
}
