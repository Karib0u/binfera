import { createRoot } from "react-dom/client";
import { createImage } from "../../src/engine/image";
import Workspace from "../../src/workspace/Workspace";
import { locOf } from "../../src/workspace/location";
import type { Analysis, CapaRule, DecompiledFunction } from "../../src/types";
import { runEngine } from "../../src/engine/run";
import "../../src/styles.css";

const noop = () => undefined;
const root = createRoot(document.getElementById("root")!);
let run = 0;
const base = 0x401000;

/** One function whose C names every kind of local the decompiler prints. */
const text = [
  "int work(int param_1)",
  "",
  "{",
  "  int iVar3;",
  "  int unaff_EBX;",
  "  undefined4 auStack_28;",
  "  int count;",
  "",
  "  iVar3 = param_1 + unaff_EBX;",
  "  auStack_28 = iVar3;",
  "  count = auStack_28 + 1;",
  "  return count;",
  "}",
].join("\n");

const fn: DecompiledFunction = {
  address: base, name: "work", text,
  asm: [[base, "90", "nop"], [base + 1, "c3", "ret"]],
  lines: text.split("\n").map(() => []),
  frame: [{ name: "count", offset: -4, size: 4, type: "int", parameter: false, reads: [], writes: [], references: [] }],
};

const image = createImage(new Uint8Array(0x2000), {
  format: "pe", arch: "x86", fidArch: "x86", entry: base, ptrSize: 4, littleEndian: true, warnings: [],
  sections: [
    { name: ".text", va: base, off: 0, size: 0x1000, vsize: 0x1000, perms: "r-x", entropy: 5 },
    { name: ".data", va: base + 0x1000, off: 0x1000, size: 0x1000, vsize: 0x1000, perms: "rw-", entropy: 1 },
  ],
  regions: [{ va: base, off: 0, size: 0x2000 }],
  imports: [], exports: [],
  details: { structures: [], facts: [], anomalies: [], resources: [], versionInfo: [], signatures: [] },
});

/** Capability matches inside the one function, for the header's capability trigger. */
const rule = (name: string): CapaRule => ({ name, namespace: "test", scope: "function", lib: false, attack: [], mbc: [], description: "", count: 1, addresses: [base], evidence: new Map() });
const capa = (n: number) => ({ sample: { md5: "", sha256: "0".repeat(64) }, format: "pe", arch: "i386", os: "windows", baseAddress: base,
  rules: ["Encrypt data using RC4", "Create a process", "Read a file"].slice(0, n).map(rule) }) as Analysis["capa"];

Object.assign(window, { mountWorkbench: (sel: number | "capa" | "strings" | "file", layout = "c", caps = 0) => {
  const a: Analysis = {
    image, functions: new Map([[base, fn]]), order: [base], names: new Map(), strings: [],
    entry: base, fileName: "a".repeat(64) + ".exe", size: image.bytes.length, arch: "x86", packed: null, stringsTotal: 0,
    capa: caps ? capa(caps) : null, capaError: null, family: null, familyError: null, pickFamilyPack: async () => undefined, decompileError: null, tooLarge: null, capaTooLarge: null, loading: null, settled: true, done: true,
  };
  const key = ++run;
  history.replaceState({ binfera: true, run: key, i: 0, ...locOf(sel), at: null }, "");
  root.render(<Workspace key={key} a={a} onNew={noop} onFile={noop} onCompare={noop} run={key} active initial={{ sel, at: null, layout }} />);
} });

/**
 * x64 shellcode whose main decrypts two XOR-0x5a strings in place through decrypt(buffer, length)
 * at 0x2f (the bytes of binfera/tests/emulate.rs XOR_STRINGS). Emulation runs the real engine:
 * engine.worker.ts with the wasm build, as the page does.
 */
const XOR = Uint8Array.from([
  0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d, 0x39, 0, 0, 0, 0xba, 5, 0, 0, 0, 0xe8, 0x1a, 0, 0, 0,
  0x48, 0x8d, 0x0d, 0x2e, 0, 0, 0, 0xba, 7, 0, 0, 0, 0xe8, 9, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28,
  0x31, 0xc0, 0xc3, 0xcc, 0xcc, 0x48, 0x89, 0xc8, 0x85, 0xd2, 0x74, 0x0a, 0x80, 0x31, 0x5a, 0x48,
  0xff, 0xc1, 0xff, 0xca, 0x75, 0xf6, 0xc3, 0xcc, 0xcc, 0xcc, 0x32, 0x3f, 0x36, 0x36, 0x35, 0,
  0x3f, 0x22, 0x3b, 0x37, 0x2a, 0x36, 0x3f, 0,
]);
const row = (at: number, end: number, text: string): [number, string, string] =>
  [at, [...XOR.slice(at, end)].map((b) => b.toString(16).padStart(2, "0")).join(""), text];
const mainText = "int main(void)\n\n{\n  decrypt(&DAT_00000044,5);\n  decrypt(&DAT_0000004a,7);\n  return 0;\n}";
const decryptText = "char * decrypt(char *param_1,int param_2)\n\n{\n  for (; param_2 != 0; param_2 = param_2 + -1) {\n    *param_1 = *param_1 ^ 0x5a;\n    param_1 = param_1 + 1;\n  }\n  return param_1;\n}";
const xorFns: DecompiledFunction[] = [
  { address: 0, name: "main", text: mainText, calls: [0x2f], lines: mainText.split("\n").map((_, i) => (i === 3 ? [0x4, 0xb, 0x10] : i === 4 ? [0x15, 0x1c, 0x21] : [])),
    asm: [row(0, 4, "sub rsp,0x28"), row(4, 0xb, "lea rcx,[0x44]"), row(0xb, 0x10, "mov edx,5"), row(0x10, 0x15, "call decrypt"), row(0x15, 0x1c, "lea rcx,[0x4a]"),
      row(0x1c, 0x21, "mov edx,7"), row(0x21, 0x26, "call decrypt"), row(0x26, 0x2a, "add rsp,0x28"), row(0x2a, 0x2c, "xor eax,eax"), row(0x2c, 0x2d, "ret")] },
  { address: 0x2f, name: "decrypt", text: decryptText, lines: decryptText.split("\n").map(() => []),
    asm: [row(0x2f, 0x32, "mov rax,rcx"), row(0x32, 0x34, "test edx,edx"), row(0x34, 0x36, "je 0x40"), row(0x36, 0x39, "xor byte ptr [rcx],0x5a"),
      row(0x39, 0x3c, "inc rcx"), row(0x3c, 0x3e, "dec edx"), row(0x3e, 0x40, "jne 0x36"), row(0x40, 0x41, "ret")] },
];
const xorImage = createImage(XOR, {
  format: "sc64", arch: "x64", fidArch: "x64", entry: 0, ptrSize: 8, littleEndian: true, warnings: [],
  sections: [{ name: "code", va: 0, off: 0, size: XOR.length, vsize: XOR.length, perms: "rwx", entropy: 4 }],
  regions: [{ va: 0, off: 0, size: XOR.length }], imports: [], exports: [],
  details: { structures: [], facts: [], anomalies: [], resources: [], versionInfo: [], signatures: [] },
});
let engine: Promise<WebAssembly.Module> | null = null;

Object.assign(window, { mountEmulate: (sel: number) => {
  const a: Analysis = {
    image: xorImage, functions: new Map(xorFns.map((f) => [f.address, f])), order: xorFns.map((f) => f.address), names: new Map(), strings: [],
    entry: 0, fileName: "xor-strings.bin", size: XOR.length, arch: "x64", packed: null, stringsTotal: 0,
    shellcode: { format: "sc64", os: "windows", guessed: false, ambiguous: false, evidence: [], osDetected: false, encoding: "binary", inputSize: XOR.length },
    capa: null, capaError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: null, settled: true, done: true,
    emulate: async (address, request, callSites, signal) => {
      engine ??= WebAssembly.compileStreaming(fetch("/binfera.wasm"));
      let out = "";
      await runEngine({ kind: "emulate", module: await engine, sample: XOR.slice().buffer, data: {}, address, request, callSites, raw: { format: "sc64", os: "windows" } },
        (line) => { out += line; }, signal);
      return out;
    },
  };
  const key = ++run;
  history.replaceState({ binfera: true, run: key, i: 0, ...locOf(sel), at: null }, "");
  root.render(<Workspace key={key} a={a} onNew={noop} onFile={noop} onCompare={noop} run={key} active initial={{ sel, at: null, layout: "c+asm" }} />);
} });
