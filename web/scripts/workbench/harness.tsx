import { createRoot } from "react-dom/client";
import { createImage } from "../../src/engine/image";
import Workspace from "../../src/workspace/Workspace";
import { locOf } from "../../src/workspace/location";
import type { Analysis, CapaRule, DecompiledFunction } from "../../src/types";
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
