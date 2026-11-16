import type { Indicator } from "../indicators";
import type { Analysis } from "../types";
import { useNotes } from "../names";
import { hex } from "../workspace/labels";
import { useState, useEffect, useMemo, useRef } from "react";
import { IndicatorGroups } from "./IndicatorGroups";
import { revealIn } from "../workspace/panels";

const PAGE = 300;

export function StringsView({ a, indicators, onlyIndicators, setOnlyIndicators, refs, onGoto, query, setQuery, onHex, onBytes, onlyRefPref, setOnlyRef, mobile, onPeek, cursor, autoFocus = true }: {
  cursor?: number | null; autoFocus?: boolean;
  /** The strings that look like URLs, addresses, keys and so on; the toggle shows only these, by kind. */
  indicators: Indicator[]; onlyIndicators: boolean; setOnlyIndicators: (v: boolean) => void;
  onlyRefPref: boolean; setOnlyRef: (v: boolean) => void;
  /** Phone: compact rows that open on tap, with "View bytes" taking the place of the side-by-side hex. */
  mobile?: boolean; onPeek?: (va: number, len: number) => void;
  a: Analysis; refs: Map<number, number[]>; onGoto: (ad: number, target?: number) => void; query: string; setQuery: (q: string) => void;
  /** Open the string's bytes in the hex view: address, byte length. */
  onHex: (va: number, len: number) => void;
  /** Where the explicit "hex" actions go, when that differs from where a row click goes (a pane). */
  onBytes?: (va: number, len: number) => void;
}) {
  const [limit, setLimit] = useState(PAGE);
  const [open, setOpen] = useState<string | null>(null);
  const box = useRef<HTMLDivElement>(null);
  // A sample whose code never names a string (Conti hides its text behind hashes and stack strings)
  // would show an empty list under the default filter, so it only applies when references exist.
  const onlyRef = onlyRefPref && refs.size > 0;
  useEffect(() => setLimit(PAGE), [query, onlyRef]);
  const rows = useMemo(() => {
    const n = query.toLowerCase();
    return a.strings.filter((x) => (!onlyRef || refs.has(x.a)) && (!n || x.s.toLowerCase().includes(n) || hex(x.a).includes(n)));
  }, [a.strings, query, onlyRef, refs]);
  useEffect(() => {
    const i = rows.findIndex((x) => cursor != null && cursor >= x.a && cursor < x.a + Math.max(1, x.s.length * (x.w ? 2 : 1)));
    if (i >= 0) setLimit((n) => Math.max(n, i + PAGE));
  }, [cursor, rows]);
  useEffect(() => { revealIn(box.current?.closest<HTMLElement>(".pane-data"), "[data-current]"); }, [cursor, limit]);
  const notes = useNotes();
  const fnName = (ad: number) => notes.label(ad, a.functions.get(ad)?.name);

  return (
    <div ref={box} className={"view" + (mobile ? " mstrings" : "")}>
      {!mobile && <h1>Strings</h1>}
      {!mobile && <p className="fine" style={{ marginTop: 4 }}>
        {onlyIndicators ? "Pattern matches in the strings, to check before relying on them. Values encoded or built at run time don't appear."
          : <>{a.strings.length} ASCII and UTF-16 strings{a.done ? "" : " · references appear once decompilation finishes"}</>}
      </p>}
      {a.stringsTotal > a.strings.length && <p className="fine">Showing the first {a.strings.length.toLocaleString("en-US")} of {a.stringsTotal.toLocaleString("en-US")} strings, by address</p>}
      <div className="tools flat">
        <div className="tool-row">
          <input placeholder="Search strings" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus={autoFocus && !mobile && matchMedia("(pointer: fine)").matches} />
        </div>
        <div className="chips" role="group" aria-label="Show strings">
          <button aria-pressed={!onlyIndicators && !onlyRef} onClick={() => { setOnlyIndicators(false); setOnlyRef(false); }}>All <em>{a.strings.length}</em></button>
          <button aria-pressed={!onlyIndicators && onlyRef} disabled={refs.size === 0} title={refs.size === 0 ? "References appear once decompilation finishes" : "Only strings the code uses"} onClick={() => { setOnlyIndicators(false); setOnlyRef(true); }}>{mobile ? "Used" : "Referenced"} <em>{refs.size}</em></button>
          <button aria-pressed={onlyIndicators} title="URLs, IP addresses, domains, commands, registry keys, paths and similar" onClick={() => setOnlyIndicators(true)}>Indicators <em>{indicators.length}</em></button>
        </div>
      </div>
      {onlyIndicators && <IndicatorGroups items={indicators} query={query} refs={refs} label={fnName} onFn={onGoto} ready={a.done} onHex={(va, len) => (mobile ? onPeek : onBytes ?? onHex)?.(va, len)} />}
      {!onlyIndicators && rows.slice(0, limit).map((x) => {
        const r = refs.get(x.a);
        const selected = cursor != null && cursor >= x.a && cursor < x.a + Math.max(1, x.s.length * (x.w ? 2 : 1));
        if (mobile) {
          const key = x.a + (x.w ? "w" : "a"), isOpen = open === key, sec = a.image?.sectionAt(x.a);
          return (
            <div className={"str m" + (isOpen ? " open" : "")} key={key} onClick={() => setOpen(isOpen ? null : key)}>
              <div className="str-text">{x.s}</div>
              <div className="str-meta">
                <code>{hex(x.a)}</code>{sec && <span>{sec.name}</span>}{x.w && <span>utf-16</span>}
                {r && <span className="str-in">in {fnName(r[0])}{r.length > 1 ? ` +${r.length - 1}` : ""}</span>}
              </div>
              {isOpen && (
                <div className="str-actions" onClick={(e) => e.stopPropagation()}>
                  {r?.slice(0, 6).map((ad) => <button key={ad} onClick={() => onGoto(ad, x.a)}>{fnName(ad)}</button>)}
                  <button className="primary" onClick={() => onPeek?.(x.a, x.w ? x.s.length * 2 : x.s.length)}>View bytes</button>
                </div>
              )}
            </div>
          );
        }
        return (
          <div className={"str" + (selected ? " selected" : "")} data-ctx-str={x.a} data-ctx-len={x.w ? x.s.length * 2 : x.s.length} data-ctx-text={x.s} data-current={selected || undefined} key={x.a + (x.w ? "w" : "a")} onClick={() => onHex(x.a, x.w ? x.s.length * 2 : x.s.length)}>
            <div className="str-head">
              <code>{hex(x.a)}</code>
              {a.image?.sectionAt(x.a) && <span className="tag">{a.image.sectionAt(x.a)!.name}</span>}
              {x.w && <span className="tag">utf-16</span>}
              <button className="hexlink" onClick={(e) => { e.stopPropagation(); (onBytes ?? onHex)(x.a, x.w ? x.s.length * 2 : x.s.length); }} title="Show these bytes in the hex view">hex</button>
            </div>
            <div className="str-text">{x.s}</div>
            <div className="addrs used">
              {r ? <><small>Used in</small>{r.slice(0, 12).map((ad) => <button key={ad} onClick={(e) => { e.stopPropagation(); onGoto(ad, x.a); }}>{fnName(ad)}</button>)}{r.length > 12 && <small>+{r.length - 12}</small>}</>
                : <small>{a.done ? "No function references found" : "Looking for references…"}</small>}
            </div>
          </div>
        );
      })}
      {!onlyIndicators && rows.length > limit && <button className="ghost more" onClick={() => setLimit(limit + PAGE * 3)}>Show more ({rows.length - limit})</button>}
      {!onlyIndicators && !rows.length && <p className="empty">No strings match.</p>}
    </div>
  );
}
