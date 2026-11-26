import { createRoot } from "react-dom/client";
import Workspace from "../../src/workspace/Workspace";
import { locOf } from "../../src/workspace/location";
import type { Analysis, DecompiledFunction, FamilyReport, StringEntry } from "../../src/types";
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
    const text = i === 0 ? `void f0(void)\n\n{\n  puts("WanaCrypt0r");\n  return;\n}` : `void f${i}(void)\n\n{\n  return;\n}`;
    functions.set(address, { address, text, asm: [[address, "c3", "ret"]], lines: text.split("\n").map(() => []), refs: i === 0 ? [0x40e034] : [] });
  }
  const strings: StringEntry[] = [
    { a: 0x40e034, s: "WanaCrypt0r", w: true },
    { a: 0x40e04c, s: "Software\\", w: true },
    { a: 0x40e080, s: "https://example.invalid/c2", w: false },
  ];
  for (let i = 3; i < 5996; i++) strings.push({ a: 0x40e100 + i * 16, s: `sample_str_${i}`, w: false });
  const family: FamilyReport = {
    total_functions: count, eligible_functions: 100, trusted_functions: 10, shared_malware_functions: 0,
    family_matched_functions: 31, unique_functions: 59,
    breakdown: { trusted_pct: 10, malware_pct: 31, shared_pct: 0, unique_pct: 59 },
    families: [], trusted_sources: [], shared_addresses: [], unique_addresses: [],
    strings: {
      total_strings: 5996, trusted_strings: 1, malware_strings: 1, shared_strings: 0, unique_strings: 5994,
      breakdown: { trusted_pct: 0, malware_pct: 0, shared_pct: 0, unique_pct: 100 },
      families: [{ family: "win.wannacryptor", exclusive_strings: 1, shared_strings: 0, corroborates_code: true }],
      entries: [
        { hash: "1", value: "WanaCrypt0r", kind: "malware", families: ["win.wannacryptor"], encoding: "utf16le", offset: 0x40e034 },
        { hash: "2", value: "Software\\", kind: "trusted", encoding: "utf16le", offset: 0x40e04c },
      ],
      entries_truncated: false,
    },
  };
  const a: Analysis = {
    image: null, functions, order: [...functions.keys()], names: new Map(), strings,
    entry: base, fileName: "WannaCry", size: 3514368, arch: "x86", packed: null, stringsTotal: strings.length,
    capa: null, capaError: null, family, familyError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: null, settled: true, done: true,
  };
  const key = ++run;
  history.replaceState({ binfera: true, run: key, i: 0, ...locOf("capa"), at: null }, "");
  root.render(<Workspace key={key} a={a} onNew={noop} onFile={noop} run={key} active initial={{ sel: "capa", at: null }} />);
} });
