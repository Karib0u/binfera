import { useEffect, useMemo, useRef, useState } from "react";
import { decompileOne, engineModule, functionListing, pairDiff, type Comparison, type FunctionMatch, type FunctionRef, type GraphEdge, type Instruction, type PairDiff, type Status } from "../compare";
import { opener, withManual, type Side, type Target } from "../compareModel";
import { layoutCfg, type Cfg, type CfgEdge } from "../graph";
import { useMedia } from "../workspace/panels";
import { cKey, diffLines, diffWords, folded, localNames, withLocals, type LineRow, type Piece } from "../textdiff";

export const hex = (n: number) => "0x" + n.toString(16);
export const pct = (n: number | null | undefined) => (n === null || n === undefined ? "n/a" : `${(n * 100).toFixed(1)}%`);

/** Which file a fact is about, the same everywhere on the page. */
export const Tag = ({ side }: { side: Side }) => <span className={"cmp-tag cmp-tag-" + side} aria-label={`file ${side.toUpperCase()}`}>{side.toUpperCase()}</span>;

/** What only one file has. Always both columns, so an empty side reads as a finding. */
export function SideColumn({ side, children, empty }: { side: Side; children: React.ReactNode; empty: boolean }) {
  return (
    <div className="cmp-column">
      <h4><Tag side={side} /> Only in {side.toUpperCase()}</h4>
      {empty ? <p className="fine">Nothing</p> : children}
    </div>
  );
}

/** What the text of a diff can do: follow a call to its own difference, and name what it calls. */
export interface DiffLinks {
  /** Whether a function of this file is known, and so can be followed. */
  known: (side: Side, at: number) => boolean;
  follow: (side: Side, at: number) => void;
  /** The name the reader gave a function, or the file's own, if any. */
  name: (side: Side, at: number) => string;
}

const METHOD: Record<FunctionMatch["method"], string> = {
  exact: "Exact: the same instructions, strings and imports, and no other function in either file has them.",
  shape: "Same instructions: no other function in either file has these instructions, but what they refer to differs.",
  name: "Name: both files give this function the same symbol, and the code supports it.",
  propagated: "Call graph: it sits next to functions already paired, and was the clear best among their neighbours.",
  fuzzy: "Score: each function was the other's clear best on the signals below.",
  duplicate: "Position: identical functions exist more than once, so these were paired in address order. Swapping them would change nothing.",
  manual: "By hand: you paired these two. The engine did not, so nothing below is evidence for it.",
};

/** One line of a diff, whichever kind of text it came from. */
interface Row { status: Status; aNo?: string; bNo?: string; a?: string; b?: string; aNote?: string; bNote?: string; head?: string; aCall?: number; bCall?: number; aBlock?: number; bBlock?: number }

const FUNCTION_LINK = /\b(?:thunk_)?FUN_([0-9a-f]+)\b/g;

/** Text with each function it names made something to follow. */
function Linked({ text, side, links }: { text: string; side: Side; links: DiffLinks }) {
  const out: React.ReactNode[] = [];
  let from = 0;
  for (const m of text.matchAll(FUNCTION_LINK)) {
    const at = parseInt(m[1], 16);
    if (!links.known(side, at)) continue;
    out.push(text.slice(from, m.index));
    out.push(<button key={m.index} type="button" className="cmp-call" title={`Show ${hex(at)}`} onClick={() => links.follow(side, at)}>{links.name(side, at)}</button>);
    from = m.index + m[0].length;
  }
  out.push(text.slice(from));
  return <>{out}</>;
}

function Words({ pieces, side, links }: { pieces: Piece[]; side: Side; links: DiffLinks }) {
  return <>{pieces.map((p, i) => (p.changed ? <mark key={i}><Linked text={p.text} side={side} links={links} /></mark> : <span key={i}><Linked text={p.text} side={side} links={links} /></span>))}</>;
}

/** The text of one side, with what changed on the line marked when the two differ. */
function Cell({ row, side, links, wordKeys }: { row: Row; side: Side; links: DiffLinks; wordKeys?: WordKeys }) {
  const text = side === "a" ? row.a : row.b, note = side === "a" ? row.aNote : row.bNote, call = side === "a" ? row.aCall : row.bCall;
  const pieces = useMemo(() => {
    if (row.status !== "changed" || row.a === undefined || row.b === undefined) return null;
    const full = (t: string, n?: string) => (n ? `${t}  ; ${n}` : t);
    return diffWords(full(row.a, row.aNote), full(row.b, row.bNote), wordKeys?.[0], wordKeys?.[1])[side === "a" ? 0 : 1];
  }, [row, side, wordKeys]);
  if (text === undefined) return null;
  const body = pieces ? <Words pieces={pieces} side={side} links={links} /> : <><Linked text={text} side={side} links={links} />{note && <span className="cmp-note">  ; {note}</span>}</>;
  // An instruction that calls a known function goes to it.
  if (call !== undefined && links.known(side, call)) return <button type="button" className="cmp-call cmp-call-line" title={`Show ${hex(call)}`} onClick={() => links.follow(side, call)}>{body}</button>;
  return body;
}

type WordKeys = [(t: string) => string, (t: string) => string];

/** The change last stepped to: a short diff has nothing to scroll, so position alone cannot say. */
let atHunk: HTMLElement | null = null;
const forgetHunk = () => { atHunk?.classList.remove("cmp-flash"); atHunk = null; };

/** Goes to the next or previous change in the diff shown; false when there is no other. */
export function stepHunk(root: Element | null, dir: 1 | -1) {
  if (!root) return false;
  const top = root.getBoundingClientRect().top;
  const hunks = [...root.querySelectorAll<HTMLElement>("[data-hunk]")];
  const from = atHunk ? hunks.indexOf(atHunk) : -1;
  const next = from >= 0
    ? hunks[from + dir]
    : dir > 0 ? hunks.find((h) => h.getBoundingClientRect().top >= top - 4) : [...hunks].reverse().find((h) => h.getBoundingClientRect().top < top - 4);
  if (!next) { forgetHunk(); return false; }
  forgetHunk();
  next.scrollIntoView({ block: "nearest" });
  void next.offsetWidth;
  next.classList.add("cmp-flash");
  atHunk = next;
  return true;
}

/** The difference as `git diff` shows it: both sides next to each other, or interleaved. */
function DiffTable({ rows, mode, links, wordKeys }: { rows: Row[]; mode: "split" | "unified"; links: DiffLinks; wordKeys?: WordKeys }) {
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [showAll, setShowAll] = useState(false);
  useEffect(() => { setOpen(new Set()); setShowAll(false); }, [rows]);
  const items = useMemo(() => folded(rows, (r) => r.status === "same" && !r.head, showAll ? new Set(rows.map((_, i) => i)) : open), [rows, open, showAll]);
  const unchanged = rows.filter((r) => r.status === "same" && !r.head).length;
  const line = (r: Row, k: string, side?: Side, hunk?: boolean) => {
    const sign = r.status === "same" ? " " : side === "a" ? "−" : side === "b" ? "+" : " ";
    const kind = r.status === "same" ? "same" : side === "a" ? "removed" : "added";
    return (
      <div key={k} className={"cmp-u st-" + kind} data-hunk={hunk ? "" : undefined}>
        <code className="cmp-no">{side !== "b" ? r.aNo : ""}</code>
        <code className="cmp-no">{side !== "a" ? r.bNo : ""}</code>
        <code className="cmp-sign">{sign}</code>
        <code className="cmp-text"><Cell row={r} side={side ?? (r.a !== undefined ? "a" : "b")} links={links} wordKeys={wordKeys} /></code>
      </div>
    );
  };
  return (
    <div className={"cmp-diff cmp-diff-" + mode}>
      {items.map((item, i) => {
        if ("fold" in item) {
          return <button key={"f" + item.from} type="button" className="cmp-fold" onClick={() => setOpen(new Set(open).add(item.from))}>Show {item.fold} unchanged {item.fold === 1 ? "line" : "lines"}</button>;
        }
        const r = item.row;
        if (r.head) return <div key={i} className="cmp-hunk" data-block-a={r.aBlock} data-block-b={r.bBlock}><code>{r.head}</code></div>;
        // The first line of a run of changes is where "next change" stops.
        const before = items[i - 1], hunk = r.status !== "same" && !(before && "row" in before && !before.row.head && before.row.status !== "same");
        if (mode === "unified") {
          if (r.status === "same") return line(r, "s" + i);
          return <div key={i} data-hunk={hunk ? "" : undefined}>{r.a !== undefined && line(r, "a" + i, "a")}{r.b !== undefined && line(r, "b" + i, "b")}</div>;
        }
        return (
          <div key={i} className={"cmp-s st-" + r.status} data-hunk={hunk ? "" : undefined}>
            <code className="cmp-no">{r.aNo}</code>
            <code className="cmp-text">{r.a !== undefined && <Cell row={r} side="a" links={links} wordKeys={wordKeys} />}</code>
            <code className="cmp-no">{r.bNo}</code>
            <code className="cmp-text">{r.b !== undefined && <Cell row={r} side="b" links={links} wordKeys={wordKeys} />}</code>
          </div>
        );
      })}
      {unchanged > 8 && !showAll && items.some((x) => "fold" in x) && <button type="button" className="cmp-fold" onClick={() => setShowAll(true)}>Show all lines</button>}
    </div>
  );
}

const lineRows = (rows: LineRow[]): Row[] => rows.map((r) => ({ status: r.status, a: r.a, b: r.b, aNo: r.aLine?.toString(), bNo: r.bLine?.toString() }));
const addr = (i: Instruction | null | undefined) => i?.address.toString(16);

function asmRows(pair: PairDiff): Row[] {
  return pair.blocks.flatMap((b) => [
    { status: "same" as Status, aBlock: b.a ?? undefined, bBlock: b.b ?? undefined, head: `@@ block ${b.a !== null ? `A ${hex(b.a)}` : "only in B"}${b.a !== null && b.b !== null ? " · " : ""}${b.b !== null ? (b.a !== null ? `B ${hex(b.b)}` : hex(b.b)) : " only"} @@` },
    ...b.rows.map((r): Row => ({ status: r.status, a: r.a?.text, b: r.b?.text, aNote: r.a?.note, bNote: r.b?.note, aNo: addr(r.a), bNo: addr(r.b), aCall: r.a?.call, bCall: r.b?.call })),
  ]);
}

const STATUS_FILL: Record<Status, string> = { same: "var(--soft)", changed: "color-mix(in srgb, var(--warn) 24%, var(--panel))", added: "color-mix(in srgb, var(--c-str) 24%, var(--panel))", removed: "color-mix(in srgb, var(--err) 22%, var(--panel))" };

interface GraphBlock { address: number; status: Status }

/** One side's graph, blocks coloured by what happened to them. Layout comes from the Graph view's. */
function DiffGraph({ blocks, edges, side, onBlock }: { blocks: GraphBlock[]; edges: GraphEdge[]; side: Side; onBlock: (side: Side, at: number) => void }) {
  const { layout } = useMemo(() => {
    const ids = new Map(blocks.map((b, id) => [b.address, id]));
    const cfg: Cfg = {
      blocks: blocks.map((b, id) => ({ id, addr: b.address, rows: [] })),
      edges: edges.flatMap((e): CfgEdge[] => {
        const from = ids.get(e.from), to = ids.get(e.to);
        return from === undefined || to === undefined ? [] : [{ from, to, kind: e.kind === "branch" ? "true" : e.kind === "fallthrough" ? "false" : "jump" }];
      }),
    };
    return { layout: layoutCfg(cfg, () => ({ w: 62, h: 24 })) };
  }, [blocks, edges]);
  return (
    <figure className="cmp-graph">
      <figcaption><Tag side={side} /> {blocks.length} {blocks.length === 1 ? "block" : "blocks"}</figcaption>
      <svg style={{ maxWidth: Math.max(layout.width, 60) * 1.6 }} viewBox={`0 0 ${Math.max(layout.width, 60)} ${Math.max(layout.height, 24)}`} role="img" aria-label={`File ${side.toUpperCase()} control flow graph`}>
        {layout.routes.map((r, i) => <polyline key={i} points={r.pts.map((p) => p.join(",")).join(" ")} fill="none" stroke="var(--muted)" strokeWidth="1" strokeDasharray={r.back ? "3 2" : undefined} />)}
        {layout.nodes.map((n) => {
          const b = blocks[n.id];
          return (
            <g key={n.id} className="cmp-graph-block" role="button" tabIndex={0} aria-label={`Show block ${hex(b.address)}`} onClick={() => onBlock(side, b.address)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onBlock(side, b.address); } }}>
              <title>{`${hex(b.address)} · ${b.status}. Click to read it.`}</title>
              <rect x={n.x} y={n.y} width={n.w} height={n.h} rx="4" fill={STATUS_FILL[b.status]} stroke="var(--line)" />
              <text x={n.x + n.w / 2} y={n.y + n.h / 2 + 3.5} textAnchor="middle" fontSize="9" fill="var(--text)" fontFamily="var(--mono)">{b.address.toString(16).slice(-6)}</text>
            </g>
          );
        })}
      </svg>
    </figure>
  );
}

function Legend() {
  return <p className="cmp-legend fine"><i className="k-same" />same <i className="k-changed" />changed <i className="k-removed" />only in A <i className="k-added" />only in B · click a block to read it</p>;
}

function Check({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return <li className={ok ? "ok" : "no"}><i aria-label={ok ? "same" : "different"}>{ok ? "=" : "≠"}</i>{children}</li>;
}

function Differences<T>({ title, a, b, show }: { title: string; a?: T[]; b?: T[]; show: (x: T) => React.ReactNode }) {
  if (!a?.length && !b?.length) return null;
  const list = (items?: T[]) => <ul>{items?.map((x, i) => <li key={i}>{show(x)}</li>)}</ul>;
  return (
    <section className="cmp-delta">
      <h3>{title}</h3>
      <div className="cmp-two">
        <SideColumn side="a" empty={!a?.length}>{list(a)}</SideColumn>
        <SideColumn side="b" empty={!b?.length}>{list(b)}</SideColumn>
      </div>
    </section>
  );
}

/** Why the pair was made and what differs in it: everything the numbers were made from. */
function Why({ c, m, manual, onOpen }: { c: Comparison; m: FunctionMatch; manual: FunctionMatch[]; onOpen: (t: Target) => void }) {
  const e = m.evidence;
  if (m.method === "manual") return <div className="cmp-why"><section><h3>Why these two are paired</h3><p>{METHOD.manual}</p></section></div>;
  const same = (a?: unknown[], b?: unknown[]) => !a?.length && !b?.length;
  const callee = (side: Side) => (f: FunctionRef) => {
    const target = opener(c.document, side, f.address, manual);
    const label = <>{f.name && <>{f.name} </>}<code>{hex(f.address)}</code></>;
    return target ? <button type="button" className="cmp-link" onClick={() => onOpen(target)}>{label}</button> : label;
  };
  const total = e.signals?.reduce((sum, s) => sum + s.weight, 0) ?? 0;
  return (
    <div className="cmp-why">
      <section>
        <h3>Why these two are paired</h3>
        <p>{METHOD[m.method]}</p>
        <p className="fine">{pct(m.confidence)} sure of the pairing, which is separate from how alike the functions are ({pct(m.similarity)}).</p>
      </section>
      <section>
        <h3>What was compared</h3>
        <ul className="cmp-checks">
          <Check ok={e.same_instructions}>Instructions, with addresses masked <small>{m.a_instructions} in A, {m.b_instructions} in B</small></Check>
          <Check ok={same(e.strings_only_a, e.strings_only_b)}>Strings it refers to</Check>
          <Check ok={same(e.imports_only_a, e.imports_only_b)}>Imports it calls</Check>
          <Check ok={!m.reasons.includes("callee")}>Functions it calls, through the function match</Check>
          <Check ok={same(e.constants_only_a, e.constants_only_b)}>Constants</Check>
          <Check ok={e.same_cfg}>Control flow <small>{e.blocks[0]} blocks and {e.edges[0]} edges in A, {e.blocks[1]} and {e.edges[1]} in B</small></Check>
        </ul>
        {m.reasons.includes("callee") && same(e.callees_only_a, e.callees_only_b) && <p className="fine">It calls the same functions, in a different order.</p>}
      </section>
      <Differences title="Strings" a={e.strings_only_a} b={e.strings_only_b} show={(x: string) => <code>{JSON.stringify(x)}</code>} />
      <Differences title="Imports" a={e.imports_only_a} b={e.imports_only_b} show={(x: string) => <code>{x}</code>} />
      <Differences title="Constants" a={e.constants_only_a} b={e.constants_only_b} show={(x: number) => <code>{hex(x)}</code>} />
      {(e.callees_only_a?.length || e.callees_only_b?.length) ? (
        <section className="cmp-delta">
          <h3>Functions it calls</h3>
          <div className="cmp-two">
            <SideColumn side="a" empty={!e.callees_only_a?.length}><ul>{e.callees_only_a?.map((f) => <li key={f.address}>{callee("a")(f)}</li>)}</ul></SideColumn>
            <SideColumn side="b" empty={!e.callees_only_b?.length}><ul>{e.callees_only_b?.map((f) => <li key={f.address}>{callee("b")(f)}</li>)}</ul></SideColumn>
          </div>
        </section>
      ) : null}
      <Differences title="Capabilities in this function" a={e.rules_only_a} b={e.rules_only_b} show={(x: string) => x} />
      {e.rules_both?.length ? <p className="fine">Both match: {e.rules_both.join(", ")}.</p> : null}
      {e.signals?.length ? (
        <section>
          <h3>What the score weighed</h3>
          <table className="cmp-signals">
            <tbody>
              {e.signals.map((s) => (
                <tr key={s.name}>
                  <th scope="row">{s.name}</th>
                  <td><span className="cmp-meter"><span style={{ width: `${s.value * 100}%` }} /></span></td>
                  <td>{pct(s.value)}</td>
                  <td className="fine">{Math.round((s.weight / total) * 100)}% of score</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="fine">Each signal is shared items over all items. What neither function has is left out rather than counted against it.</p>
        </section>
      ) : <p className="fine">Nothing needed weighing: the hashes are equal and unique in both files.</p>}
    </div>
  );
}

function OneSideWhy({ side, f }: { side: Side; f: FunctionRef }) {
  const other = side === "a" ? "B" : "A";
  return (
    <div className="cmp-why">
      <section>
        <h3>Why it has no counterpart</h3>
        <p>No function in {other} has the same code or name, or is a clear enough match on its imports, strings, constants, instruction patterns, control flow and position in the call graph. It may be new code, or code that changed too much to be recognized.</p>
      </section>
      {f.rules?.length ? <section><h3>Capabilities in this function</h3><ul className="cmp-plain">{f.rules.map((x) => <li key={x}>{x}</li>)}</ul></section> : null}
      {f.imports?.length ? <section><h3>Imports it calls</h3><ul className="cmp-plain">{f.imports.map((x) => <li key={x}><code>{x}</code></li>)}</ul></section> : null}
      {f.strings?.length ? <section><h3>Strings it refers to</h3><ul className="cmp-plain">{f.strings.map((x) => <li key={x}><code>{JSON.stringify(x)}</code></li>)}</ul></section> : null}
    </div>
  );
}

type View = "c" | "asm" | "graph" | "why";

/** Decompiling recovers the whole file, so what was read once is kept for the page's life. */
const decompiled = new WeakMap<Comparison, Map<string, Promise<string>>>();
/** Each run recovers a whole file, so a page of diffs takes its turn rather than starting them all. */
let decompiling = 0;
const waiting: (() => void)[] = [];
async function inTurn<T>(job: () => Promise<T>) {
  if (decompiling >= 2) await new Promise<void>((go) => waiting.push(go));
  decompiling++;
  try { return await job(); } finally { decompiling--; waiting.shift()?.(); }
}
function decompile(c: Comparison, side: Side, at: number) {
  const ready = c.known?.(side, at);
  if (ready !== undefined) return Promise.resolve(ready);
  let known = decompiled.get(c);
  if (!known) decompiled.set(c, (known = new Map()));
  const key = `${side}:${at}`;
  let hit = known.get(key);
  if (!hit) {
    hit = inTurn(() => decompileOne(c, side, at, new AbortController().signal));
    hit.catch(() => known.delete(key));
    known.set(key, hit);
  }
  return hit;
}

function toLines(text: string) {
  const lines = text.split("\n");
  while (lines.length && !lines[0].trim()) lines.shift();
  while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
  return lines;
}

/** Everything one function's difference is made from, as it becomes available. `enabled` holds it back until it is on screen. */
function usePairData(c: Comparison, target: Target, view: View, manual: FunctionMatch[], enabled = true) {
  const m = target.kind === "match" ? target.m : null;
  const [pair, setPair] = useState<PairDiff | null>(null);
  const [pairError, setPairError] = useState<string | null>(null);
  const [code, setCode] = useState<[string | null, string | null] | null>(null);
  const [codeError, setCodeError] = useState<string | null>(null);
  const forward = useMemo(() => new Map(withManual(c.document, manual).matches.map((x) => [x.a_addr, x.b_addr])), [c, manual]);

  useEffect(() => {
    setPair(null); setPairError(null);
    if (!m || !enabled) return;
    const ctl = new AbortController();
    engineModule()
      .then((module) => pairDiff(c, m.a_addr, m.b_addr, module, ctl.signal))
      .then(setPair)
      .catch((e) => { if (!ctl.signal.aborted) setPairError(String(e.message ?? e)); });
    return () => ctl.abort();
  }, [c, m, enabled]);

  useEffect(() => {
    setCode(null); setCodeError(null);
    if (view !== "c" || !enabled) return;
    let live = true;
    const left = target.kind === "match" ? target.m.a_addr : target.kind === "a" ? target.f.address : null;
    const right = target.kind === "match" ? target.m.b_addr : target.kind === "b" ? target.f.address : null;
    Promise.all([left === null ? null : decompile(c, "a", left), right === null ? null : decompile(c, "b", right)])
      .then((texts) => { if (live) setCode(texts); })
      .catch((e) => { if (live) setCodeError(String(e.message ?? e).replace(/^error: /, "")); });
    return () => { live = false; };
  }, [c, target, view, enabled]);

  const listing = useMemo(() => (target.kind === "match" ? null : functionListing(c, target.kind, target.f.address)), [c, target]);

  const { codeRows, wordKeys } = useMemo<{ codeRows: Row[] | null; wordKeys?: WordKeys }>(() => {
    if (!code) return { codeRows: null };
    const [left, right] = [toLines(code[0] ?? ""), toLines(code[1] ?? "")];
    // A variable's number is the decompiler's bookkeeping: set it aside like an address.
    const namesA = localNames(left), namesB = localNames(right);
    const rows = lineRows(diffLines(left, right, (l) => cKey(withLocals(l, namesA), "a", forward), (l) => cKey(withLocals(l, namesB), "b", forward)));
    return { codeRows: rows, wordKeys: [(t) => namesA.get(t) ?? cKey(t, "a", forward), (t) => namesB.get(t) ?? cKey(t, "b", forward)] };
  }, [code, forward]);

  const asm = useMemo<Row[] | null>(() => {
    if (pair) return asmRows(pair);
    if (!listing || target.kind === "match") return null;
    const side = target.kind;
    return listing.blocks.flatMap((b) => [
      { status: "same" as Status, head: `@@ block ${hex(b.address)} @@`, aBlock: side === "a" ? b.address : undefined, bBlock: side === "b" ? b.address : undefined },
      ...b.instructions.map((i): Row => side === "a"
        ? { status: "removed", a: i.text, aNote: i.note, aNo: addr(i), aCall: i.call }
        : { status: "added", b: i.text, bNote: i.note, bNo: addr(i), bCall: i.call }),
    ]);
  }, [pair, listing, target]);

  const counts = useMemo(() => {
    const rows = view === "c" ? codeRows : view === "asm" ? asm : null;
    if (!rows) return null;
    const of = (s: Status) => rows.filter((r) => r.status === s && !r.head).length;
    return { changed: of("changed"), removed: of("removed"), added: of("added") };
  }, [view, codeRows, asm]);

  return { m, pair, pairError, listing, codeRows, wordKeys, codeError, asm, counts };
}
type PairData = ReturnType<typeof usePairData>;

const Counts = ({ counts }: { counts: PairData["counts"] }) => (counts ? (
  <span className="cmp-counts fine"><b className="c-removed">−{counts.removed + counts.changed}</b> <b className="c-added">+{counts.added + counts.changed}</b></span>
) : null);

function PairBody({ data, target, view, mode, links, onBlock, onOpen, c, manual }: {
  data: PairData; target: Target; view: View; mode: "split" | "unified"; links: DiffLinks; onBlock: (side: Side, at: number) => void; onOpen: (t: Target) => void; c: Comparison; manual: FunctionMatch[];
}) {
  const { m, pair, pairError, listing, codeRows, wordKeys, codeError, asm } = data;
  const shape = target.kind === "match" ? mode : "unified";
  const graphs = (() => {
    if (pair) {
      const a = pair.blocks.flatMap((b) => (b.a === null ? [] : [{ address: b.a, status: b.status }]));
      const b = pair.blocks.flatMap((x) => (x.b === null ? [] : [{ address: x.b, status: x.status }]));
      return <div className="cmp-graphs"><DiffGraph blocks={a} edges={pair.a_edges} side="a" onBlock={onBlock} /><DiffGraph blocks={b} edges={pair.b_edges} side="b" onBlock={onBlock} /></div>;
    }
    if (listing && target.kind !== "match") {
      const blocks = listing.blocks.map((b) => ({ address: b.address, status: (target.kind === "a" ? "removed" : "added") as Status }));
      const edges = listing.blocks.flatMap((b) => b.successors.map((e) => ({ from: b.address, to: e.target, kind: e.kind })));
      return <div className="cmp-graphs cmp-graphs-one"><DiffGraph blocks={blocks} edges={edges} side={target.kind} onBlock={onBlock} /></div>;
    }
    return null;
  })();
  return (
    <>
      {view === "c" && (codeError
        ? <p className="error cmp-pad" role="alert">Decompiling failed: {codeError}. The assembly is still available.</p>
        : codeRows
          ? (codeRows.some((r) => r.status !== "same") || target.kind !== "match"
            ? <DiffTable rows={codeRows} mode={shape} links={links} wordKeys={wordKeys} />
            : <><p className="fine cmp-pad">The decompiled C is the same once addresses and variable numbers are set aside{m?.changed ? `, though the function differs in ${m.reasons.join(", ")}: see Why and Assembly` : ""}.</p><DiffTable rows={codeRows} mode={mode} links={links} wordKeys={wordKeys} /></>)
          : <p className="fine cmp-pad">Decompiling… The assembly is available right away.</p>)}
      {view === "asm" && (pairError
        ? <p className="error cmp-pad" role="alert">{pairError}</p>
        : asm ? <DiffTable rows={asm} mode={shape} links={links} /> : <p className="fine cmp-pad">Aligning blocks…</p>)}
      {view === "graph" && (graphs ? <><Legend />{graphs}</> : <p className="fine cmp-pad">{pairError ?? "Aligning blocks…"}</p>)}
      {view === "why" && (m ? <Why c={c} m={m} manual={manual} onOpen={onOpen} /> : target.kind !== "match" && <OneSideWhy side={target.kind} f={target.f} />)}
    </>
  );
}

const TABS: [View, string][] = [["c", "C"], ["asm", "Assembly"], ["graph", "Graph"], ["why", "Why"]];
const startMode = () => (window.innerWidth < 900 ? "unified" : "split") as "split" | "unified";

function Layout({ mode, setMode }: { mode: "split" | "unified"; setMode: (m: "split" | "unified") => void }) {
  return (
    <div role="group" aria-label="Layout" className="cmp-tabs cmp-layout">
      <button type="button" aria-pressed={mode === "split"} className={mode === "split" ? "on" : ""} onClick={() => setMode("split")}>Split</button>
      <button type="button" aria-pressed={mode === "unified"} className={mode === "unified" ? "on" : ""} onClick={() => setMode("unified")}>Unified</button>
    </div>
  );
}

/** What to do with the difference shown, shared by the single diff and the list of them. */
export interface DiffActions {
  links: DiffLinks;
  onOpen: (t: Target) => void;
  /** Shows the function in that file's own workspace. */
  onFile: (side: Side, at: number) => void;
  /** Chooses another function to compare this one with. */
  onPairWith: (side: Side, at: number) => void;
  onUnpair: (m: FunctionMatch) => void;
}

/** A function's title and addresses, in whichever names the reader has given it. */
function Title({ target, links }: { target: Target; links: DiffLinks }) {
  if (target.kind !== "match") return <>{links.name(target.kind, target.f.address)}</>;
  const a = links.name("a", target.m.a_addr), b = links.name("b", target.m.b_addr);
  return <>{a === b ? b : `${a} → ${b}`}</>;
}

export default function FunctionDiff({ c, target, manual, reason, viewed, onViewed, actions, onClose, onPrevious, onNext }: {
  c: Comparison; target: Target; manual: FunctionMatch[]; reason?: string; viewed: boolean; onViewed: () => void; actions: DiffActions;
  /** A phone shows the list or the diff; a wider window keeps both, and needs no way back. */
  onClose: () => void; onPrevious?: () => void; onNext?: () => void;
}) {
  const [view, setView] = useState<View>("c");
  const [chosenMode, setMode] = useState<"split" | "unified">(startMode);
  // Two columns do not fit a phone, whatever was chosen on a wider window.
  const mode = useMedia("(max-width: 760px)") ? "unified" : chosenMode;
  const data = usePairData(c, target, view, manual);
  const { m } = data;
  const body = useRef<HTMLDivElement>(null);
  const [block, setBlock] = useState<{ side: Side; at: number } | null>(null);
  const toBlock = (side: Side, at: number) => { setBlock({ side, at }); setView("asm"); };
  useEffect(() => {
    if (!block || view !== "asm" || !data.asm) return;
    body.current?.querySelector(`[data-block-${block.side}="${block.at}"]`)?.scrollIntoView({ block: "start" });
    setBlock(null);
  }, [block, view, data.asm]);
  useEffect(() => { forgetHunk(); body.current?.scrollTo({ top: 0 }); }, [target, view]);

  return (
    <section className="cmp-pair" aria-label="Function difference">
      <header>
        <div className="cmp-pair-title">
          <h2><Title target={target} links={actions.links} /></h2>
          {reason && <p className="cmp-reason">{reason}</p>}
          {m ? (
            <p className="fine"><Tag side="a" /> <code>{hex(m.a_addr)}</code> <Tag side="b" /> <code>{hex(m.b_addr)}</code>{m.method === "manual" ? " · paired by hand" : ` · ${m.changed ? `${pct(m.similarity)} alike` : "no differences"}`}</p>
          ) : target.kind !== "match" && <p className="fine"><Tag side={target.kind} /> <code>{hex(target.f.address)}</code> · only in {target.kind.toUpperCase()}</p>}
        </div>
        <div className="cmp-actions">
          <button type="button" className="cmp-btn cmp-back" onClick={onClose}>Back to list</button>
          <button type="button" className="cmp-btn" onClick={onPrevious} disabled={!onPrevious} aria-label="Previous function" title="Previous function (k)">↑</button>
          <button type="button" className="cmp-btn" onClick={onNext} disabled={!onNext} aria-label="Next function" title="Next function (j)">↓</button>
          <label className="cmp-btn cmp-viewed" title="Mark as read (v)"><input type="checkbox" checked={viewed} onChange={onViewed} /> Viewed</label>
          {(target.kind === "match" || target.kind === "a") && <button type="button" className="cmp-btn" title="Open in A (a)" onClick={() => actions.onFile("a", target.kind === "match" ? target.m.a_addr : (target as { f: FunctionRef }).f.address)}>Open in <Tag side="a" /></button>}
          {(target.kind === "match" || target.kind === "b") && <button type="button" className="cmp-btn" title="Open in B (b)" onClick={() => actions.onFile("b", target.kind === "match" ? target.m.b_addr : (target as { f: FunctionRef }).f.address)}>Open in <Tag side="b" /></button>}
          {target.kind !== "match" && <button type="button" className="cmp-btn" title={`Choose a function in ${target.kind === "a" ? "B" : "A"} to compare this one with`} onClick={() => actions.onPairWith(target.kind as Side, (target as { f: FunctionRef }).f.address)}>Diff against…</button>}
          {m?.method === "manual" && <button type="button" className="cmp-btn" onClick={() => actions.onUnpair(m)}>Unpair</button>}
        </div>
      </header>
      <div className="cmp-pair-bar">
        <div role="tablist" aria-label="View of this function" className="cmp-tabs">
          {TABS.map(([k, label]) => <button key={k} type="button" role="tab" aria-selected={view === k} className={view === k ? "on" : ""} onClick={() => setView(k)}>{label}</button>)}
        </div>
        <Counts counts={data.counts} />
        {(view === "c" || view === "asm") && target.kind === "match" && <Layout mode={mode} setMode={setMode} />}
      </div>
      <div className="cmp-pair-body" ref={body}>
        <PairBody data={data} target={target} view={view} mode={mode} links={actions.links} onBlock={toBlock} onOpen={actions.onOpen} c={c} manual={manual} />
      </div>
    </section>
  );
}

export interface StackItem { key: string; target: Target; reason?: string }

/** One function in the page of all changes. Nothing is computed for it until it comes near the screen. */
function StackCard({ c, item, manual, view, mode, viewed, onViewed, actions, onSingle }: {
  c: Comparison; item: StackItem; manual: FunctionMatch[]; view: "c" | "asm"; mode: "split" | "unified"; viewed: boolean; onViewed: () => void; actions: DiffActions; onSingle: () => void;
}) {
  const card = useRef<HTMLElement>(null);
  const [near, setNear] = useState(false);
  useEffect(() => {
    if (!card.current) return;
    const io = new IntersectionObserver((seen) => { if (seen.some((s) => s.isIntersecting)) { setNear(true); io.disconnect(); } }, { rootMargin: "300px" });
    io.observe(card.current);
    return () => io.disconnect();
  }, []);
  const open = near && !viewed;
  const data = usePairData(c, item.target, view, manual, open);
  const toAsm = (side: Side, at: number) => actions.onFile(side, at);
  return (
    <article className={"cmp-card" + (viewed ? " is-viewed" : "")} ref={card} data-key={item.key}>
      <header>
        <div className="cmp-pair-title">
          <h3><button type="button" className="cmp-link" onClick={onSingle}><Title target={item.target} links={actions.links} /></button></h3>
          {item.reason && <p className="cmp-reason">{item.reason}</p>}
        </div>
        <Counts counts={data.counts} />
        <label className="cmp-btn cmp-viewed"><input type="checkbox" checked={viewed} onChange={onViewed} /> Viewed</label>
      </header>
      {!viewed && (near
        ? <PairBody data={data} target={item.target} view={view} mode={mode} links={actions.links} onBlock={toAsm} onOpen={actions.onOpen} c={c} manual={manual} />
        : <p className="fine cmp-pad">Loads when it comes into view.</p>)}
    </article>
  );
}

/** Every change on one scrolling page, as a pull request shows its files. */
export function StackedDiffs({ c, items, manual, isViewed, onViewed, actions, onSingle, more, onMore }: {
  c: Comparison; items: StackItem[]; manual: FunctionMatch[]; isViewed: (key: string) => boolean; onViewed: (key: string) => void; actions: DiffActions;
  onSingle: (t: Target) => void; more: number; onMore: () => void;
}) {
  const [view, setView] = useState<"c" | "asm">("c");
  const [chosenMode, setMode] = useState<"split" | "unified">(startMode);
  const mode = useMedia("(max-width: 760px)") ? "unified" : chosenMode;
  return (
    <section className="cmp-stack-wrap" aria-label="All changes">
      <div className="cmp-pair-bar">
        <div role="tablist" aria-label="View of every function" className="cmp-tabs">
          <button type="button" role="tab" aria-selected={view === "c"} className={view === "c" ? "on" : ""} onClick={() => setView("c")}>C</button>
          <button type="button" role="tab" aria-selected={view === "asm"} className={view === "asm" ? "on" : ""} onClick={() => setView("asm")}>Assembly</button>
        </div>
        <span className="fine">{items.length} functions{more > 0 ? ` of ${items.length + more}` : ""}</span>
        <Layout mode={mode} setMode={setMode} />
      </div>
      <div className="cmp-pair-body cmp-stack">
        {items.map((it) => <StackCard key={it.key} c={c} item={it} manual={manual} view={view} mode={mode} viewed={isViewed(it.key)} onViewed={() => onViewed(it.key)} actions={actions} onSingle={() => onSingle(it.target)} />)}
        {more > 0 && <button type="button" className="cmp-btn cmp-more" onClick={onMore}>Show more ({more} left)</button>}
      </div>
    </section>
  );
}
