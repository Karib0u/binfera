import { useState } from "react";
import { createRoot } from "react-dom/client";
import { FunctionView, type FnViewProps } from "../../src/views/FunctionView";
import type { DecompiledFunction } from "../../src/types";
import "../../src/styles.css";

const noop = () => undefined;
const root = createRoot(document.getElementById("root")!);
let run = 0;

function Harness({ f, mode }: { f: DecompiledFunction; mode: "asm" | "graph" | "sync" | "mobile" }) {
  const [cursor, setCursor] = useState<number | null>(null);
  Object.assign(window, { navigate: setCursor, currentCursor: cursor });
  const props = {
    a: { functions: new Map([[f.address, f]]), names: new Map(), strings: [], arch: "x86" }, address: f.address, rules: [],
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
