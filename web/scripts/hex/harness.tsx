import { createRoot } from "react-dom/client";
import { createImage } from "../../src/engine/image";
import Workspace from "../../src/workspace/Workspace";
import { locOf } from "../../src/workspace/location";
import type { Analysis, DecompiledFunction } from "../../src/types";
import "../../src/styles.css";

const noop = () => undefined;
const root = createRoot(document.getElementById("root")!);
let run = 0;
const base = 0x401000;
const text = "int work(void)\n\n{\n  return 1;\n}";
const fn: DecompiledFunction = { address: base, name: "work", text, asm: [[base, "90", "nop"], [base + 1, "c3", "ret"]], lines: text.split("\n").map(() => []) };
const bytes = Uint8Array.from({ length: 0x2000 }, (_, i) => (i * 7 + 0x41) & 0xff);
const image = createImage(bytes, {
  format: "pe", arch: "x86", fidArch: "x86", entry: base, ptrSize: 4, littleEndian: true, warnings: [],
  sections: [{ name: ".text", va: base, off: 0, size: 0x2000, vsize: 0x2000, perms: "r-x", entropy: 5 }],
  regions: [{ va: base, off: 0, size: 0x2000 }], imports: [], exports: [],
  details: { structures: [], facts: [], anomalies: [], resources: [], versionInfo: [], signatures: [] },
});

Object.assign(window, { bytes, mountHex: (layout = "c+hex") => {
  const a: Analysis = {
    image, functions: new Map([[base, fn]]), order: [base], names: new Map(), strings: [],
    entry: base, fileName: "hex.bin", size: bytes.length, arch: "x86", packed: null, stringsTotal: 0,
    capa: null, capaError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: null, settled: true, done: true,
  };
  const key = ++run;
  history.replaceState({ binfera: true, run: key, i: 0, ...locOf(base), at: base }, "");
  root.render(<Workspace key={key} a={a} onNew={noop} onFile={noop} run={key} active initial={{ sel: base, at: base, layout }} />);
} });
