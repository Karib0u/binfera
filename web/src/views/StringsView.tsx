import type { Indicator } from "../indicators";
import type { Analysis, StringMatch, StringOriginKind } from "../types";
import { buildStringOriginIndex, stringOriginBadge, stringOriginKey } from "../familyOrigin";
import { useNotes } from "../names";
import { hex } from "../workspace/labels";
import { useState, useEffect, useMemo, useRef } from "react";
import { IndicatorGroups } from "./IndicatorGroups";
import { FunctionReferences } from "./FunctionReferences";
import { revealIn } from "../workspace/panels";

const PAGE = 300;
/** A string row's identity: address plus encoding, as the list keys rows. */
type StringEntryKey = string;

/** String Reuse filter state; the Workspace holds it so the Code origin card can set it. */
export interface StringOriginFilter {
  kind: StringOriginKind | null; setKind: (k: StringOriginKind | null) => void;
  hideTrusted: boolean; setHideTrusted: (v: boolean) => void;
}

const ORIGIN_CHIPS: { kind: StringOriginKind; label: string; title: string }[] = [
  { kind: "malware", label: "Malware", title: "Strings found in one malware family's samples only" },
  { kind: "shared", label: "Shared", title: "Strings seen in two or three malware families" },
  { kind: "unique", label: "Unique", title: "Strings no loaded pack knows" },
  { kind: "trusted", label: "Trusted", title: "Strings common in benign software, from the packs' Trusted string filters" },
];

export function StringsView({ a, indicators, onlyIndicators, setOnlyIndicators, refs, onGoto, query, setQuery, onHex, onBytes, onlyRefPref, setOnlyRef, mobile, onPeek, cursor, autoFocus = true, origin: originProp }: {
  cursor?: number | null; autoFocus?: boolean;
  /** Controlled String Reuse filter; the view keeps its own when absent. */
  origin?: StringOriginFilter;
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
  const [ownKind, setOwnKind] = useState<StringOriginKind | null>(null);
  const [ownHide, setOwnHide] = useState(false);
  const origin: StringOriginFilter = originProp ?? { kind: ownKind, setKind: setOwnKind, hideTrusted: ownHide, setHideTrusted: setOwnHide };
  // String Reuse classes, when the pack match carries string data (BXFAM003); null hides all of it.
  const originIndex = useMemo(() => buildStringOriginIndex(a.family), [a.family]);
  const originOf = useMemo(() => {
    const m = new Map<StringEntryKey, StringMatch | null>();
    if (!originIndex) return m;
    for (const x of a.strings) m.set(x.a + (x.w ? "w" : "a"), originIndex.get(stringOriginKey(x.s)) ?? null);
    return m;
  }, [originIndex, a.strings]);
  const kindOf = (key: StringEntryKey): StringOriginKind => originOf.get(key)?.kind ?? "unique";
  const kindFilter = originIndex ? origin.kind : null;
  const hideTrusted = !!originIndex && origin.hideTrusted && kindFilter !== "trusted";
  // A sample whose code never names a string (Conti hides its text behind hashes and stack strings)
  // would show an empty list under the default filter, so it only applies when references exist.
  const onlyRef = onlyRefPref && refs.size > 0;
  useEffect(() => setLimit(PAGE), [query, onlyRef, kindFilter, hideTrusted]);
  const rows = useMemo(() => {
    const n = query.toLowerCase();
    return a.strings.filter((x) => {
      if (onlyRef && !refs.has(x.a)) return false;
      const key = x.a + (x.w ? "w" : "a");
      if (kindFilter && kindOf(key) !== kindFilter) return false;
      if (hideTrusted && kindOf(key) === "trusted") return false;
      return !n || x.s.toLowerCase().includes(n) || hex(x.a).includes(n) || !!originOf.get(key)?.families?.some((f) => f.toLowerCase().includes(n));
    });
  }, [a.strings, query, onlyRef, refs, kindFilter, hideTrusted, originOf]);
  const originCounts = useMemo(() => {
    const c: Record<StringOriginKind, number> = { malware: 0, shared: 0, unique: 0, trusted: 0 };
    if (originIndex) for (const x of a.strings) c[kindOf(x.a + (x.w ? "w" : "a"))]++;
    return c;
  }, [originIndex, originOf, a.strings]);
  const badge = (key: StringEntryKey) => {
    const m = originOf.get(key);
    if (!m) return null;
    const b = stringOriginBadge(m);
    return <span className={"tag str-origin str-origin-" + m.kind} title={b.title}>{b.text}</span>;
  };
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
        {originIndex && !onlyIndicators && (
          <div className="chips" role="group" aria-label="Show strings by origin" title="String Reuse from the loaded packs: supporting evidence, never the code verdict">
            <button aria-pressed={!kindFilter} onClick={() => origin.setKind(null)}>All</button>
            {ORIGIN_CHIPS.map((c) => (
              <button key={c.kind} aria-pressed={kindFilter === c.kind} disabled={!originCounts[c.kind] && kindFilter !== c.kind} title={c.title}
                onClick={() => { origin.setKind(kindFilter === c.kind ? null : c.kind); if (c.kind === "trusted") origin.setHideTrusted(false); }}>
                <span className={"co-dot co-" + c.kind} aria-hidden />{c.label} <em>{originCounts[c.kind]}</em>
              </button>
            ))}
            <button aria-pressed={hideTrusted} disabled={!originCounts.trusted && !hideTrusted} title="Hide strings common in benign software"
              onClick={() => { if (kindFilter === "trusted") origin.setKind(null); origin.setHideTrusted(!origin.hideTrusted); }}>Hide trusted <em>{originCounts.trusted}</em></button>
          </div>
        )}
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
                <code>{hex(x.a)}</code>{sec && <span>{sec.name}</span>}{x.w && <span>utf-16</span>}{badge(key)}
                {r && <span className="str-in">in {fnName(r[0])}{r.length > 1 ? ` +${r.length - 1}` : ""}</span>}
              </div>
              {isOpen && (
                <div className="str-actions" onClick={(e) => e.stopPropagation()}>
                  {r && <FunctionReferences addresses={r} limit={6} label={fnName} onSelect={(ad) => onGoto(ad, x.a)} />}
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
              {badge(x.a + (x.w ? "w" : "a"))}
              <button className="hexlink" onClick={(e) => { e.stopPropagation(); (onBytes ?? onHex)(x.a, x.w ? x.s.length * 2 : x.s.length); }} title="Show these bytes in the hex view">hex</button>
            </div>
            <div className="str-text">{x.s}</div>
            <div className="addrs used">
              {r ? <><small>Used in</small><FunctionReferences addresses={r} limit={12} label={fnName} onSelect={(ad) => onGoto(ad, x.a)} /></>
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
