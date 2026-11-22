import { useState } from "react";
import { createRoot } from "react-dom/client";
import Listing from "../../src/Listing";
import { createImage } from "../../src/engine/image";
import { FunctionView, type FnViewProps } from "../../src/views/FunctionView";
import type { Analysis, DecompiledFunction } from "../../src/types";
import "../../src/styles.css";

const noop = () => undefined;
const root = createRoot(document.getElementById("root")!);
let run = 0;

function Harness({ f, mode }: { f: DecompiledFunction; mode: "asm" | "graph" | "sync" | "mobile" }) {
  const [cursor, setCursor] = useState<number | null>(null);
  Object.assign(window, { navigate: setCursor, currentCursor: cursor });
  const props = {
    a: { functions: new Map([[f.address, f]]), names: new Map(), strings: [], arch: "x86",
      image: { imports: ["CreateFileA", "CreateFileW", "ReadFile"].map((name) => ({ dll: "kernel32.dll", name })) } },
    address: f.address, rules: [],
    resolve: noop, onGoto: noop, xrefsReady: true, strings: [], onString: noop, strAt: noop, textAt: noop,
    cursor, onCursor: setCursor, isData: () => false, onData: noop, slot: noop, onImport: noop,
    starred: false, onStar: noop, onRename: noop, onRenameAt: noop, onXrefs: noop, xrefReq: 0, renameReq: 0,
    onCode: noop, capsOf: () => [], layout: mode === "sync" || mode === "mobile" ? "c+asm" : mode, setLayout: noop,
    listing: () => null, callGraph: () => null, listingReq: 0, strip: null, menuItems: [], onSearch: noop,
  } as unknown as FnViewProps;
  return <div style={{ display: "flex", height: 650, width: 1000 }}>
    {mode === "mobile" ? <FunctionView {...props} mobile /> : (mode === "sync" ? ["c", "asm"] as const : [mode]).map((view) => <FunctionView key={view} {...props} paneView={view} />)}
  </div>;
}

Object.assign(window, { mount: (f: DecompiledFunction, mode: "asm" | "graph" | "sync" | "mobile") => root.render(<Harness key={++run} f={f} mode={mode} />) });

const base = 0x400000;
const span = 64 * 4;
const functionCount = 10_000;
const dataStart = base + functionCount * span;

function listingFixture(): Analysis {
  const functions = new Map<number, DecompiledFunction>();
  for (let i = 0; i < functionCount; i++) {
    const address = base + i * span;
    const asm: DecompiledFunction["asm"] = Array.from({ length: 64 }, (_, j) => [
      address + j * 4, "8b44240c",
      j === 0 ? "jnz " + (address + 63 * 4).toString(16).toUpperCase() + "h" : "mov eax, dword ptr [esp+0Ch]",
    ]);
    functions.set(address, { address, asm, labels: i === 0 ? { [address]: "entry_label" } : undefined });
  }
  const image = createImage(new Uint8Array(functionCount * span + 128), {
    format: "pe", arch: "x86", fidArch: "x86", entry: base, ptrSize: 4, littleEndian: true, warnings: [],
    sections: [
      { name: ".text", va: base, off: 0, size: functionCount * span, vsize: functionCount * span, perms: "r-x", entropy: 0 },
      { name: ".data", va: dataStart, off: functionCount * span, size: 128, vsize: 128, perms: "rw-", entropy: 0 },
    ],
    regions: [{ va: base, off: 0, size: functionCount * span + 128 }],
    imports: [{ va: dataStart + 4, name: "test_import", dll: "test.dll" }],
    exports: [],
    details: { structures: [{ name: "test header", off: functionCount * span, size: 4, va: dataStart, fields: [
      { name: "magic", off: functionCount * span, size: 4, value: "1234", target: base },
    ] }], facts: [], anomalies: [], resources: [], versionInfo: [], signatures: [] },
  });
  return {
    image, functions, order: [...functions.keys()], strings: [{ a: dataStart + 8, s: "listing string", w: false }],
    names: new Map(), entry: base, fileName: "large.bin", size: image.bytes.length, arch: "x86", packed: null,
    stringsTotal: 1, capa: null, capaError: null, decompileError: null, tooLarge: null, capaTooLarge: null,
    loading: null, settled: false, done: false,
  };
}

function ListingHarness({ all }: { all: Analysis }) {
  const [a, setAnalysis] = useState(() => ({ ...all, functions: new Map([...all.functions].slice(-128)) }));
  const [cursor, setCursor] = useState<number | null>(null);
  const [panes, setPanes] = useState(true);
  Object.assign(window, {
    navigateListing: setCursor,
    showListingPanes: setPanes,
    receiveListings: () => setAnalysis(all),
    settleListings: () => setAnalysis((previous) => ({ ...previous, settled: true, done: true, functions: new Map(previous.functions) })),
  });
  const listing = (arrows: boolean) => <Listing a={a} arrows={arrows} cursor={cursor} tick={0} onCursor={setCursor}
    label={(va) => "FUN_" + va.toString(16)} resolve={noop} strAt={noop} textAt={noop} isData={() => false}
    onData={setCursor} onOpenFn={setCursor} onString={noop} onImport={noop} onXrefs={noop} xrefCount={() => 0}
    exportName={noop} slot={noop} fnInfo={() => ""} />;
  return panes && <div style={{ display: "flex", height: 530 }}>
    <div style={{ flex: 1, minWidth: 0 }}>{listing(true)}</div>
    <div style={{ flex: 1, minWidth: 0 }}>{listing(false)}</div>
  </div>;
}

let fixture: Analysis;
Object.assign(window, {
  prepareListing: () => { fixture = listingFixture(); },
  mountListing: () => root.render(<ListingHarness key={++run} all={fixture} />),
});
