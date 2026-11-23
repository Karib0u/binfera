import { createRoot } from "react-dom/client";
import { createImage } from "../../src/engine/image";
import Workspace from "../../src/workspace/Workspace";
import { locOf } from "../../src/workspace/location";
import type { Analysis } from "../../src/types";
import "../../src/styles.css";

const root = createRoot(document.getElementById("root")!);
let run = 0;
const base = 0x401000;
const bytes = Uint8Array.from({ length: 0x3000 }, (_, i) => (i * 3 + 1) & 0xff);
const image = createImage(bytes, {
  format: "pe", arch: "x86", fidArch: "x86", entry: base, ptrSize: 4, littleEndian: true, warnings: [],
  sections: [{ name: ".rsrc", va: base, off: 0, size: 0x3000, vsize: 0x3000, perms: "r--", entropy: 5 }],
  regions: [{ va: base, off: 0, size: 0x3000 }], imports: [], exports: [],
  details: {
    structures: [], facts: [], anomalies: [], signatures: [], versionInfo: [],
    resources: [
      { type: "RCDATA", name: "XIA", lang: "0", va: base + 0x100, off: 0x100, size: 0x400, entropy: 7.9, detected: "PE" },
      { type: "ICON", name: "1", lang: "0", va: base + 0x600, off: 0x600, size: 0x80, detected: "PNG" },
    ],
    overlay: { off: 0x2000, size: 0x800, entropy: 7.8, kind: "ZIP" },
  },
});

Object.assign(window, { bytes, received: [] as { name: string; size: number; head: number[] }[], compareAsked: 0, mountStages: () => {
  const a: Analysis = {
    image, functions: new Map(), order: [], names: new Map(), strings: [],
    entry: base, fileName: "dropper.exe", size: bytes.length, arch: "x86", packed: null, stringsTotal: 0,
    capa: null, capaError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: null, settled: true, done: true,
  };
  const key = ++run;
  history.replaceState({ binfera: true, run: key, i: 0, ...locOf("file"), at: null }, "");
  root.render(<Workspace key={key} a={a} onNew={() => undefined} run={key} active initial={{ sel: "file", at: null }}
    onFile={(f) => { f.arrayBuffer().then((b) => (window as unknown as { received: unknown[] }).received.push({ name: f.name, size: f.size, head: [...new Uint8Array(b).slice(0, 4)] })); }}
    onCompare={() => { (window as unknown as { compareAsked: number }).compareAsked++; }} />);
} });
