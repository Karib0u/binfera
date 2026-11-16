import { useMemo, useState } from "react";
import type { Indicator } from "../indicators";
import type { StringEntry } from "../types";
import { hex } from "../workspace/labels";

const byteLength = (x: StringEntry) => (x.w ? x.s.length * 2 : x.s.length);

/** The Strings view's indicators, by kind, each with the functions that use it. */
export function IndicatorGroups({ items, query, refs, label, onFn, onHex, ready }: {
  items: Indicator[]; query: string; refs: Map<number, number[]>; label: (ad: number) => string;
  onFn: (ad: number, target?: number) => void; onHex: (va: number, len: number) => void;
  /** False until decompilation finishes and references are known. */
  ready: boolean;
}) {
  const [copied, setCopied] = useState<string | null>(null);
  const groups = useMemo(() => {
    const n = query.trim().toLowerCase(), g = new Map<string, Indicator[]>();
    for (const it of items) if (!n || it.value.toLowerCase().includes(n)) g.set(it.kind, [...(g.get(it.kind) ?? []), it]);
    return [...g];
  }, [items, query]);
  const copy = (kind: string, values: Indicator[]) => navigator.clipboard.writeText(values.map((v) => v.value).join("\n")).then(() => { setCopied(kind); setTimeout(() => setCopied(null), 1200); });

  return (
    <>
      {groups.map(([kind, values]) => (
        <section key={kind}>
          <h2 className="ioc-head">{kind} <small>{values.length}</small><button className="hexlink" onClick={() => copy(kind, values)}>{copied === kind ? "Copied" : "Copy all"}</button></h2>
          {values.map((it) => {
            const fns = [...new Set(it.strings.flatMap((x) => refs.get(x.a) ?? []))], first = it.strings[0];
            return (
              <div className="ioc" key={it.value}>
                <button className="ioc-value" title={`${hex(first.a)} · show these bytes`} onClick={() => onHex(first.a, byteLength(first))}>{it.value}</button>
                <div className="addrs used">
                  {fns.length ? <>{fns.slice(0, 6).map((ad) => <button key={ad} onClick={() => onFn(ad, it.strings.find((x) => refs.get(x.a)?.includes(ad))?.a)}>{label(ad)}</button>)}{fns.length > 6 && <small>+{fns.length - 6}</small>}</>
                    : <small>{ready ? "No function references found" : "Looking for references…"}</small>}
                </div>
              </div>
            );
          })}
        </section>
      ))}
      {!items.length && <p className="empty">No indicators found in this file's strings.</p>}
      {items.length > 0 && !groups.length && <p className="empty">No indicators match.</p>}
    </>
  );
}
