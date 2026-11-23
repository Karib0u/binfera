import { createRoot } from "react-dom/client";
import Workspace from "../../src/workspace/Workspace";
import { locOf } from "../../src/workspace/location";
import type { Analysis, DecompiledFunction } from "../../src/types";
import "../../src/styles.css";
import "../../src/mobile.css";

const noop = () => undefined;
const root = createRoot(document.getElementById("root")!);
let run = 0;
const base = 0x401000;
const count = 3500;

Object.assign(window, { mountMobile: () => {
  const functions = new Map<number, DecompiledFunction>();
  for (let i = 0; i < count; i++) {
    const address = base + i * 16;
    const text = `void f${i}(void)\n\n{\n  return;\n}`;
    functions.set(address, { address, text, asm: [[address, "c3", "ret"]], lines: text.split("\n").map(() => []) });
  }
  const a: Analysis = {
    image: null, functions, order: [...functions.keys()], names: new Map(), strings: [],
    entry: base, fileName: "big.bin", size: 0, arch: "x86", packed: null, stringsTotal: 0,
    capa: null, capaError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: null, settled: true, done: true,
  };
  const key = ++run;
  history.replaceState({ binfera: true, run: key, i: 0, ...locOf("capa"), at: null }, "");
  root.render(<Workspace key={key} a={a} onNew={noop} onFile={noop} run={key} active initial={{ sel: "capa", at: null }} />);
} });
