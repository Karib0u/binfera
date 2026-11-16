import { useState } from "react";
import type { Analysis } from "../types";
import type { Indicator } from "../indicators";
import ImportsView from "../ImportsView";
import { StringsView } from "./StringsView";

/** Each data pane keeps its own filters while following its linked address. */
export default function PaneData({ view, a, cursor, strRefs, importRefs, label, indicators, navigate, onBytes, siteOf }: {
  view: "strings" | "imports"; a: Analysis; cursor: number | null;
  strRefs: Map<number, number[]>; importRefs: Map<string, number[]>; label: (ad: number) => string;
  indicators: Indicator[]; navigate: (va: number) => void; onBytes?: (va: number, len: number) => void; siteOf: (fn: number, target: number | string) => number;
}) {
  const [query, setQuery] = useState("");
  const [onlyRef, setOnlyRef] = useState(false);
  const [onlyIndicators, setOnlyIndicators] = useState(false);
  const open = (fn: number, target?: number | string) => {
    const at = target === undefined ? -1 : siteOf(fn, target);
    navigate(at >= 0 ? at : fn);
  };
  return <div className="pane-data">
    {view === "strings" ? <StringsView a={a} cursor={cursor} indicators={indicators} onlyIndicators={onlyIndicators} setOnlyIndicators={setOnlyIndicators}
      refs={strRefs} onGoto={open} query={query} setQuery={setQuery} onHex={navigate} onBytes={onBytes} onlyRefPref={onlyRef} setOnlyRef={setOnlyRef} autoFocus={false} />
      : <ImportsView a={a} cursor={cursor} refs={importRefs} label={label} onFn={open} onAddr={navigate} onBytes={onBytes ? (va) => onBytes(va, 0) : undefined} query={query} setQuery={setQuery} />}
  </div>;
}
