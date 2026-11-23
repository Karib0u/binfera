import { createRoot } from "react-dom/client";
import { createImage } from "../../src/engine/image";
import Workspace from "../../src/workspace/Workspace";
import { locOf } from "../../src/workspace/location";
import type { Analysis, DecompiledFunction } from "../../src/types";
import "../../src/styles.css";
import "../../src/mobile.css";

const noop = () => undefined;
const root = createRoot(document.getElementById("root")!);
let run = 0;
const [A, B, C] = [0x401000, 0x401100, 0x401200];
const text = (name: string, body: string[]) => [`int ${name}(void)`, "", "{", "  int iVar1;", "", ...body, "  return iVar1;", "}"].join("\n");
const make = (address: number, name: string, calls: number[], body: string[]): DecompiledFunction => {
  const t = text(name, body);
  return { address, name, text: t, calls, asm: [[address, "90", "nop"], [address + 1, "c3", "ret"]], lines: t.split("\n").map(() => []) };
};
const functions = new Map([
  [A, make(A, "alpha", [B], ["  iVar1 = FUN_00401100();"])],
  [B, make(B, "beta", [C], ["  iVar1 = FUN_00401200();"])],
  [C, make(C, "gamma", [], ["  iVar1 = 3;"])],
]);
const bytes = Uint8Array.from({ length: 0x1000 }, (_, i) => (i * 5) & 0xff);
const image = createImage(bytes, {
  format: "pe", arch: "x86", fidArch: "x86", entry: A, ptrSize: 4, littleEndian: true, warnings: [],
  sections: [{ name: ".text", va: A, off: 0, size: 0x1000, vsize: 0x1000, perms: "r-x", entropy: 5 }],
  regions: [{ va: A, off: 0, size: 0x1000 }], imports: [], exports: [],
  details: { structures: [], facts: [], anomalies: [], resources: [], versionInfo: [], signatures: [] },
});

Object.assign(window, { mountTouch: () => {
  const a: Analysis = {
    image, functions, order: [A, B, C], names: new Map(), strings: [],
    entry: A, fileName: "touch.bin", size: bytes.length, arch: "x86", packed: null, stringsTotal: 0,
    capa: null, capaError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: null, settled: true, done: true,
  };
  const key = ++run;
  history.replaceState({ binfera: true, run: key, i: 0, ...locOf(A), at: A }, "");
  root.render(<Workspace key={key} a={a} onNew={noop} onFile={noop} run={key} active initial={{ sel: A, at: A }} />);
} });
