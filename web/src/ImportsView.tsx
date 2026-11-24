import { useEffect, useMemo, useRef, useState } from "react";
import type { Analysis } from "./types";
import { revealIn } from "./workspace/panels";
import { FunctionReferences } from "./views/FunctionReferences";

const hex = (n: number) => "0x" + n.toString(16);
const PAGE = 300;

export default function ImportsView({ a, refs, label, onFn, onAddr, onBytes, onSymbol, query, setQuery, mobile, cursor }: {
  /** Open an export or a library variable by address; defaults to onAddr. */
  onSymbol?: (va: number) => void;
  cursor?: number | null;
  /** Phone: compact rows whose callers open on tap. */
  mobile?: boolean;
  a: Analysis; refs: Map<string, number[]>; label: (ad: number) => string;
  onFn: (ad: number, target?: string) => void; onAddr: (va: number) => void; onBytes?: (va: number) => void; query: string; setQuery: (q: string) => void;
}) {
  const [limit, setLimit] = useState(PAGE);
  const [open, setOpen] = useState<string | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const image = a.image;
  const needle = query.trim().toLowerCase();
  const groups = useMemo(() => {
    const g = new Map<string, { name: string; va: number; data?: boolean }[]>();
    for (const i of image?.imports ?? []) {
      if (needle && !i.name.toLowerCase().includes(needle) && !i.dll.toLowerCase().includes(needle)) continue;
      const k = i.dll || "dynamic symbols";
      g.set(k, [...(g.get(k) ?? []), i]);
    }
    return [...g].sort(([x], [y]) => x.localeCompare(y));
  }, [image, needle]);
  const exports = useMemo(() => (image?.exports ?? []).filter((e) => !needle || e.name.toLowerCase().includes(needle)), [image, needle]);
  useEffect(() => {
    const i = groups.flatMap(([, rows]) => rows).findIndex((i) => cursor != null && i.va > 0 && cursor >= i.va && cursor < i.va + (image?.ptrSize ?? 1));
    const e = exports.findIndex((e) => e.va === cursor);
    if (i >= 0 || e >= 0) setLimit((n) => Math.max(n, i + PAGE, e + PAGE));
  }, [cursor, groups, exports, image]);
  useEffect(() => { revealIn(box.current?.closest<HTMLElement>(".pane-data"), "[data-current]"); }, [cursor, limit]);
  let shown = 0;

  return (
    <div ref={box} className={"view" + (mobile ? " mimports" : "")}>
      {!mobile && <h1>Imports and exports</h1>}
      {!mobile && <p className="fine" style={{ marginTop: 4 }}>
        {image?.imports.length ?? 0} imports · {image?.exports.length ?? 0} exports{a.done ? "" : " · callers appear once decompilation finishes"}
      </p>}
      <div className="tools flat">
        <input placeholder="Search imports and exports" value={query} onChange={(e) => { setQuery(e.target.value); setLimit(PAGE); }} />
      </div>
      {exports.length > 0 && (
        <section>
          <h2>Exports <small>{exports.length}</small></h2>
          {exports.slice(0, limit).map((e) => mobile ? (
            // Phone: the same row as an import, the whole row a target.
            <button className="imp m" key={e.name + e.va} disabled={!!e.forward} onClick={() => (onSymbol ?? onAddr)(e.va)}>
              <span className="imp-name">{e.name}</span>
              <small>{e.forward ? `→ ${e.forward}` : hex(e.va)}</small>
            </button>
          ) : (
            <div className={"imp" + (cursor === e.va ? " selected" : "")} data-current={cursor === e.va || undefined} key={e.name + e.va}>
              {e.forward ? <span className="imp-name">{e.name}</span> : <button className="imp-name" onClick={() => (onSymbol ?? onAddr)(e.va)}>{e.name}</button>}
              {e.forward ? <code>forwarded to {e.forward}</code> : <code>{hex(e.va)}</code>}
            </div>
          ))}
        </section>
      )}
      {groups.map(([dll, items]) => (
        <section key={dll}>
          <h2>{dll} <small>{items.length}</small></h2>
          {items.map((i) => {
            if (shown++ >= limit) return null;
            const r = refs.get(i.name);
            const selected = cursor != null && i.va > 0 && cursor >= i.va && cursor < i.va + (image?.ptrSize ?? 1);
            // A library variable is read, not called; its copy in .bss has no bytes to show, so it opens its references.
            const users = (n: number) => i.data ? `read by ${n} function${n === 1 ? "" : "s"}` : `${n} caller${n === 1 ? "" : "s"}`;
            const none = i.data ? "not read" : "no callers";
            const tag = i.data && <span className="imp-tag" title="A library variable: this file holds a copy of it (an ELF copy relocation)">variable</span>;
            if (mobile) {
              const key = dll + i.name + i.va, isOpen = open === key;
              return (
                <div className={"imp m" + (isOpen ? " open" : "")} key={key} onClick={() => setOpen(isOpen ? null : key)}>
                  <span className="imp-name">{i.name}{tag}</span>
                  <small>{r ? users(r.length) : a.done ? none : ""}</small>
                  {isOpen && (
                    <div className="str-actions" onClick={(e) => e.stopPropagation()}>
                      {r && <FunctionReferences addresses={r} limit={8} label={label} onSelect={(ad) => onFn(ad, i.name)} />}
                      {i.va > 0 && (i.data
                        ? <button className="primary" onClick={() => (onSymbol ?? onAddr)(i.va)}>Every reference</button>
                        : <button className="primary" onClick={() => (onBytes ?? onAddr)(i.va)}>View slot</button>)}
                    </div>
                  )}
                </div>
              );
            }
            return (
              <div className={"imp" + (selected ? " selected" : "")} data-current={selected || undefined} key={dll + i.name + i.va}>
                <span className="imp-name">{i.name}{tag}</span>
                {i.va > 0 && (i.data
                  ? <button className="imp-slot" onClick={(e) => { e.stopPropagation(); (onSymbol ?? onAddr)(i.va); }} title="Show every instruction that reads this variable">{hex(i.va)}</button>
                  : <button className="imp-slot" onClick={(e) => { e.stopPropagation(); (onBytes ?? onAddr)(i.va); }} title="Show the import slot in the hex view">{hex(i.va)}</button>)}
                <span className="addrs used">
                  {r ? <FunctionReferences addresses={r} limit={6} label={label} onSelect={(ad) => onFn(ad, i.name)} />
                    : <small>{a.done ? (i.data ? "not read" : "no callers found") : ""}</small>}
                </span>
              </div>
            );
          })}
        </section>
      ))}
      {shown >= limit && <button className="ghost more" onClick={() => setLimit(limit + PAGE * 3)}>Show more</button>}
      {!groups.length && !exports.length && <p className="empty">{image?.imports.length || image?.exports.length ? "No matches." : "No import or export table in this file."}</p>}
    </div>
  );
}
