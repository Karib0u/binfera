import { useEffect, useMemo, useRef, useState } from "react";
import { analyze } from "../analyze";
import type { Comparison, FunctionMatch, FunctionRef } from "../compare";
import { addressOf, changesOf, counterpart, functionsOf, keyOf, manualPair, marksOf, opener, summaryOf, withManual, type Change, type Mark, type Side, type Target } from "../compareModel";
import { Notes } from "../names";
import Palette, { type PaletteItem } from "../Palette";
import Shortcuts, { searchKey } from "../Shortcuts";
import type { Analysis } from "../types";
import Wordmark from "../Wordmark";
import { Splitter, useStored } from "../workspace/panels";
import { useMobile } from "../workspace/useMobile";
import Workspace, { type Embedding } from "../workspace/Workspace";
import BuildVersion from "../BuildVersion";
import ReportMenu from "../ReportMenu";
import ThemeToggle from "../ThemeToggle";
import { download } from "../report";
import { compareFileStem, compareHtml, compareJson, compareMarkdown } from "../compareReport";
import { loadPairs, savePairs } from "../comparePairs";
import CompareDetails from "./CompareDetails";
import FunctionDiff, { hex, stepHunk, StackedDiffs, Tag, type DiffActions } from "./FunctionDiff";

type View = "changes" | Side | "split";
type Main = "diff" | "all" | "details";
type Filter = "changes" | "changed" | "added" | "removed" | "unchanged";
interface Place { view: View; main: Main; target: string | null }
interface Row { key: string; target: Target; status: Mark; reason: string; score: number }

const PAGE = 200;
/** Above this size the two files are analyzed one after the other, as the comparison itself reads them. */
const SERIAL_ABOVE = 16 << 20;
const index = (side: Side) => (side === "a" ? 0 : 1);
const other = (side: Side): Side => (side === "a" ? "b" : "a");
const STATUS: Record<Mark, string> = { changed: "Changed", added: "Only in B", removed: "Only in A", same: "No differences" };

const KEYS: [string, string][] = [
  ["d", "Show the difference for the function open here"],
  ["a  b", "Show this function in file A or file B"],
  ["n  p", "Next or previous change in the difference"],
  ["j  k", "Next or previous function in the list of changes"],
  ["v", "Mark a function as viewed and go to the next"],
];
const CHANGES_KEYS: [string, string][] = [
  ["/  " + searchKey, "Search both files"],
  ["g", "Go to an address"],
  ["?", "This list"],
];

const blank = (file: File): Analysis => ({ fileName: file.name, size: file.size, order: [], strings: [], stringsTotal: 0, image: null, entry: null, arch: null, packed: null, functions: new Map(), names: new Map(), settled: false, capa: null, capaError: null, family: null, familyError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: { label: "Getting ready", fraction: null }, done: false });

/** Two files in one place: what changed between them, and each file to explore on its own. */
export default function CompareWorkspace({ c, onReset }: { c: Comparison; onReset: () => void }) {
  const d = c.document;
  const mobile = useMobile();
  const [a, b] = d.inputs;
  const refs = useMemo<[Map<number, FunctionRef>, Map<number, FunctionRef>]>(() => [new Map(functionsOf(d, "a").map((f) => [f.address, f])), new Map(functionsOf(d, "b").map((f) => [f.address, f]))], [d]);
  // Pairs made by hand last across reloads, for these two files; a pair whose function is gone is dropped.
  const [manual, setManual] = useState<FunctionMatch[]>(() => loadPairs(a.sha256, b.sha256).flatMap(([x, y]) => {
    const [fa, fb] = [refs[0].get(x), refs[1].get(y)];
    return fa && fb ? [manualPair(fa, fb)] : [];
  }));
  useEffect(() => { savePairs(a.sha256, b.sha256, manual.map((m) => [m.a_addr, m.b_addr])); }, [manual, a.sha256, b.sha256]);
  const all = useMemo(() => withManual(d, manual), [d, manual]);
  const changes = useMemo(() => changesOf(d, manual), [d, manual]);
  const changeBy = useMemo(() => new Map(changes.map((x) => [x.key, x])), [changes]);
  const summary = useMemo(() => summaryOf(d), [d]);
  const notes = useMemo<[Notes, Notes]>(() => {
    const pair: [Notes, Notes] = [new Notes(), new Notes()];
    pair[0].load(a.sha256); pair[1].load(b.sha256);
    return pair;
  }, [a.sha256, b.sha256]);
  const [namesTick, setNamesTick] = useState(0);

  const first = changes[0]?.target ?? null;
  const [view, setViewState] = useState<View>("changes");
  const [main, setMainState] = useState<Main>(first && d.functions_compared ? "diff" : "details");
  const [target, setTargetState] = useState<Target | null>(first);
  // A phone shows the list or what was picked from it.
  const [picked, setPicked] = useState(false);
  const fromKey = (key: string | null): Target | null => {
    if (!key) return null;
    const [kind, x, y] = key.split(":");
    if (kind === "m") return opener(d, "a", Number(x), manual) ?? opener(d, "b", Number(y), manual);
    return opener(d, kind as Side, Number(x), manual);
  };

  // Browser Back retraces what was opened here; each file keeps its own Back within its pane.
  const here = useRef<Place>({ view, main, target: target && keyOf(target) });
  const record = (next: Place, mode: "push" | "replace" = "push") => {
    here.current = next;
    try { history[mode === "push" ? "pushState" : "replaceState"]({ binferaCompare: true, ...next }, "", location.pathname + location.search); } catch { /* Safari's limit on history calls: Back just skips a step */ }
  };
  const go = (next: Partial<Place>) => {
    const place = { ...here.current, ...next };
    if (place.view === here.current.view && place.main === here.current.main && place.target === here.current.target) return;
    setViewState(place.view); setMainState(place.main); setTargetState(fromKey(place.target));
    record(place);
  };
  useEffect(() => {
    record(here.current);
    const onPop = () => {
      const st = history.state as ({ binferaCompare?: unknown } & Partial<Place>) | null;
      if (st?.binferaCompare !== true || !st.view) return;
      const place = { view: st.view, main: st.main ?? "diff", target: st.target ?? null };
      here.current = place;
      setViewState(place.view); setMainState(place.main); setTargetState(fromKeyRef.current(place.target));
      if (place.view === "a" || place.view === "b") start(place.view);
      if (place.view === "split") { start("a"); start("b"); }
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);
  const fromKeyRef = useRef(fromKey);
  fromKeyRef.current = fromKey;
  useEffect(() => { if (mobile && view === "split") go({ view: "a" }); }, [mobile, view]);

  // Each file is analyzed in full only once it is opened: the difference needs none of that.
  const [analyses, setAnalyses] = useState<[Analysis | null, Analysis | null]>([null, null]);
  const analysesRef = useRef(analyses);
  analysesRef.current = analyses;
  const [failures, setFailures] = useState<[string | null, string | null]>([null, null]);
  const runs = useRef<[number, number]>([Date.now(), Date.now() + 1]);
  const stop = useRef(new AbortController());
  const queue = useRef<Promise<unknown>>(Promise.resolve());
  const started = useRef([false, false]);
  useEffect(() => {
    c.known = (side, at) => analysesRef.current[index(side)]?.functions.get(at)?.text ?? undefined;
    // A remount (a hot reload, say) cancelled what was running: start over whatever had not finished.
    const ctl = stop.current = new AbortController();
    (["a", "b"] as const).forEach((side, i) => {
      const an = analysesRef.current[i];
      if (an && !an.done) { started.current[i] = false; start(side); }
    });
    return () => { ctl.abort(); c.known = undefined; };
  }, [c]);
  const start = (side: Side) => {
    const i = index(side);
    if (started.current[i]) return;
    started.current[i] = true;
    const file = c.sides[i].file;
    const put = (next: Analysis | null) => setAnalyses((now) => { const out = [...now] as typeof now; out[i] = next; return out; });
    put(blank(file));
    const run = () => analyze(file, (next) => put(next), stop.current.signal).catch((e) => {
      if (stop.current.signal.aborted) return;
      put(null);
      setFailures((now) => { const out = [...now] as typeof now; out[i] = String((e as Error).message ?? e).replace(/^error: /, ""); return out; });
    });
    if (file.size > SERIAL_ABOVE || c.sides[1 - i].file.size > SERIAL_ABOVE) queue.current = queue.current.then(run);
    else void run();
  };

  // Each pane's place, what it has been asked to show, and which one the keyboard is talking to.
  const [places, setPlaces] = useState<[number | null, number | null]>([null, null]);
  const placesRef = useRef(places);
  placesRef.current = places;
  const [requests, setRequests] = useState<[Embedding["request"], Embedding["request"]]>([null, null]);
  const ticks = useRef(1);
  const ask = (side: Side, at: number) => setRequests((now) => { const out = [...now] as typeof now; out[index(side)] = { at, tick: ++ticks.current }; return out; });
  const [focus, setFocusState] = useState<Side>("a");
  const focusRef = useRef(focus);
  focusRef.current = focus;
  const setFocus = (side: Side) => { focusRef.current = side; setFocusState(side); };
  const [linked, setLinked] = useStored("compare-linked", false);
  const linkedRef = useRef(linked);
  linkedRef.current = linked;
  const viewRef = useRef(view);
  viewRef.current = view;
  const manualRef = useRef(manual);
  manualRef.current = manual;
  const [notice, setNotice] = useState<string | null>(null);
  useEffect(() => { if (!notice) return; const t = setTimeout(() => setNotice(null), 2600); return () => clearTimeout(t); }, [notice]);

  const onPlace = (side: Side, fn: number | null) => {
    setPlaces((now) => { const out = [...now] as typeof now; out[index(side)] = fn; return out; });
    if (!linkedRef.current || viewRef.current !== "split" || focusRef.current !== side || fn === null) return;
    const peer = counterpart(d, side, fn, manualRef.current);
    if (peer !== null) ask(other(side), peer);
  };
  /** Shows a function in its file's own workspace, in whichever view is showing. */
  const openIn = (side: Side, at: number) => {
    start(side);
    ask(side, at);
    setFocus(side);
    if (view !== "split") go({ view: side });
  };
  const showView = (next: View) => {
    if (next === "a" || next === "b") {
      const started_ = started.current[index(next)];
      start(next);
      // A file opened for the first time starts at what is being read, not at its overview.
      if (!started_ && target) { const at = addressOf(target, next); if (at !== null) ask(next, at); }
      setFocus(next);
    } else if (next === "split") {
      for (const side of ["a", "b"] as const) {
        const started_ = started.current[index(side)];
        start(side);
        if (!started_ && target) { const at = addressOf(target, side); if (at !== null) ask(side, at); }
      }
    }
    go({ view: next });
  };
  const openDiff = (t: Target) => { setPicked(true); go({ view: "changes", main: here.current.main === "all" ? "all" : "diff", target: keyOf(t) }); };

  // What the list of changes shows.
  const [filter, setFilter] = useState<Filter>("changes");
  const [query, setQuery] = useState("");
  const [shown, setShown] = useState(PAGE);
  useEffect(() => setShown(PAGE), [filter, query]);
  const unchanged = useMemo(() => all.matches.filter((m) => !m.changed), [all]);
  const counts: Record<Filter, number> = useMemo(() => ({
    changes: changes.length, changed: changes.filter((x) => x.status === "changed").length, added: all.onlyB.length, removed: all.onlyA.length, unchanged: unchanged.length,
  }), [changes, all, unchanged]);
  const title = (t: Target) => {
    if (t.kind !== "match") return notes[index(t.kind)].label(t.f.address, t.f.name);
    const x = notes[0].label(t.m.a_addr, t.m.a_name), y = notes[1].label(t.m.b_addr, t.m.b_name);
    return x === y ? y : `${x} → ${y}`;
  };
  const rows = useMemo<Row[]>(() => {
    const q = query.trim().toLowerCase().replace(/^0x/, "");
    const hit = (r: Row) => !q || title(r.target).toLowerCase().includes(q) || r.reason.toLowerCase().includes(q) || (["a", "b"] as const).some((s) => addressOf(r.target, s)?.toString(16).includes(q));
    const fromChange = (x: Change): Row => ({ key: x.key, target: x.target, status: x.status, reason: x.reason, score: x.score });
    const list = filter === "unchanged"
      ? unchanged.map((m): Row => { const t: Target = { kind: "match", m }; return { key: keyOf(t), target: t, status: "same", reason: "No differences", score: 0 }; })
      : changes.filter((x) => filter === "changes" || x.status === filter).map(fromChange);
    return list.filter(hit);
  }, [changes, unchanged, filter, query, namesTick]);
  const targetKey = target ? keyOf(target) : null;
  const at = targetKey ? rows.findIndex((r) => r.key === targetKey) : -1;

  // What has been read so far stays read, for this pair of files.
  const [viewedList, setViewedList] = useStored<string[]>(`compare-viewed:${a.sha256}:${b.sha256}`, []);
  const viewed = useMemo(() => new Set(viewedList), [viewedList]);
  const toggleViewed = (key: string) => setViewedList(viewed.has(key) ? viewedList.filter((x) => x !== key) : [...viewedList, key]);
  const viewedCount = changes.filter((x) => viewed.has(x.key)).length;

  const stepFunction = (dir: 1 | -1) => {
    const next = rows[at < 0 ? (dir > 0 ? 0 : -1) : at + dir];
    if (!next) { setNotice(dir > 0 ? "That was the last function in the list" : "That was the first function in the list"); return; }
    go({ main: here.current.main === "all" ? "all" : "diff", target: next.key });
  };
  const markViewed = () => {
    if (!targetKey) return;
    const was = viewed.has(targetKey);
    toggleViewed(targetKey);
    if (was) return;
    const later = rows.slice(at + 1).find((r) => !viewed.has(r.key));
    if (later) go({ target: later.key });
  };
  // In the page of all changes, the list scrolls the page rather than replacing it.
  const stage = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (main === "all" && targetKey) stage.current?.querySelector(`.cmp-card[data-key="${targetKey}"]`)?.scrollIntoView({ block: "start" });
  }, [main, targetKey]);

  /** The other half of what is open, in the file asked for. */
  const here_ = (): { side: Side; at: number } | null => {
    if (view === "changes") return null;
    const side = view === "split" ? focus : view;
    const fn = places[index(side)];
    return fn === null ? null : { side, at: fn };
  };
  const toFile = (side: Side) => {
    if (view === "changes") {
      const at_ = target && addressOf(target, side);
      if (at_ === null || at_ === undefined) { setNotice(`This function has no counterpart in ${side.toUpperCase()}`); return; }
      openIn(side, at_);
      return;
    }
    const now = here_();
    if (!now || now.side === side) { showView(view === "split" ? "split" : side); setFocus(side); return; }
    const peer = counterpart(d, now.side, now.at, manual);
    if (peer === null) { setNotice(`This function has no counterpart in ${side.toUpperCase()}`); return; }
    openIn(side, peer);
  };
  const diffHere = () => {
    if (view === "split") {
      const [x, y] = places;
      if (x !== null && y !== null && counterpart(d, "a", x, manual) !== y) { pair("a", x, y); return; }
    }
    const now = here_();
    const t = now && opener(d, now.side, now.at, manual);
    if (t) openDiff(t); else setNotice("Open a function first");
  };

  // Pairs made by hand, for what the matcher missed or got wrong. They last until the page closes.
  const [pairing, setPairing] = useState<{ side: Side; at: number } | null>(null);
  const refOf = (side: Side, at: number): FunctionRef => refs[index(side)].get(at) ?? { address: at, name: null, instructions: 0 };
  const pair = (side: Side, at: number, peer: number) => {
    const [x, y] = side === "a" ? [at, peer] : [peer, at];
    const made = manualPair(refOf("a", x), refOf("b", y));
    const next = [made, ...manual.filter((m) => m.a_addr !== x && m.b_addr !== y)];
    setManual(next); manualRef.current = next;
    // The new pair is not in the old list yet, so its place is written out rather than looked up.
    const key = `m:${x}:${y}`;
    setPicked(true);
    here.current = { view: "changes", main: "diff", target: key };
    setViewState("changes"); setMainState("diff"); setTargetState({ kind: "match", m: made });
    record(here.current);
  };
  const unpair = (m: FunctionMatch) => {
    const next = manual.filter((x) => x !== m);
    setManual(next); manualRef.current = next;
    const t = opener(d, "a", m.a_addr, next);
    setTargetState(t);
    here.current = { ...here.current, target: t && keyOf(t) };
    record(here.current, "replace");
  };
  const pairSearch = (q: string): PaletteItem[] => {
    if (!pairing) return [];
    const side = other(pairing.side), n = q.trim().toLowerCase().replace(/^0x/, "");
    const free = new Set((side === "a" ? all.onlyA : all.onlyB).map((f) => f.address));
    return functionsOf(d, side)
      .filter((f) => !n || notes[index(side)].label(f.address, f.name).toLowerCase().includes(n) || f.address.toString(16).includes(n))
      .sort((x, y) => Number(free.has(y.address)) - Number(free.has(x.address)) || x.address - y.address)
      .slice(0, 60)
      .map((f) => ({ kind: free.has(f.address) ? "unmatched" : "matched", title: notes[index(side)].label(f.address, f.name), detail: `${hex(f.address)} · ${f.instructions} instructions`, run: () => pair(pairing.side, pairing.at, f.address) }));
  };

  // One search for everything: the comparison's own functions, and each file once it has been opened.
  const searches = useRef<[Embedding["searchRef"], Embedding["searchRef"]]>([{ current: null }, { current: null }]);
  const searchAll = (q: string): PaletteItem[] => {
    const scoped = /^([cafsix]):\s*(.*)$/i.exec(q.trim());
    const out: PaletteItem[] = [];
    const n = (scoped ? scoped[2] : q.trim()).toLowerCase().replace(/^0x/, "");
    if (n && (!scoped || scoped[1].toLowerCase() === "f")) {
      let hits = 0;
      for (const list of [changes.map((x) => x.target), all.matches.filter((m) => !m.changed).map((m): Target => ({ kind: "match", m }))]) {
        for (const t of list) {
          if (hits >= 15) break;
          const name = title(t);
          if (!name.toLowerCase().includes(n) && !(["a", "b"] as const).some((s) => addressOf(t, s)?.toString(16).includes(n))) continue;
          hits++;
          out.push({ kind: "difference", title: name, detail: changeBy.get(keyOf(t))?.reason ?? "No differences", run: () => openDiff(t) });
        }
      }
    }
    for (const side of ["a", "b"] as const) {
      const own = searches.current[index(side)].current;
      if (own) {
        for (const item of own(q)) {
          out.push({ ...item, kind: `${side.toUpperCase()} ${item.kind}`, run: () => { if (view === "changes" || (view !== "split" && view !== side)) go({ view: side }); setFocus(side); item.run(); } });
        }
      } else if (n) {
        out.push({ kind: side.toUpperCase(), title: `Open ${d.inputs[index(side)].name} to search its strings, code and imports too`, run: () => showView(side) });
      }
    }
    return out;
  };
  const [palette, setPalette] = useState<string | null>(null);
  const [help, setHelp] = useState(false);

  // The keys of the comparison itself. A file's own workspace handles its keys while it is showing.
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (palette !== null || pairing || help) return;
      const onChanges = view === "changes";
      if (onChanges && (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette(""); return; }
      if ((e.target as HTMLElement).closest?.("input, select, textarea, [contenteditable=true], .palette, .sheet")) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "d") { e.preventDefault(); diffHere(); return; }
      if (e.key === "a" || e.key === "b") { e.preventDefault(); toFile(e.key); return; }
      if (!onChanges) return;
      if (e.key === "/" || e.key === "g") { e.preventDefault(); setPalette(e.key === "g" ? "0x" : ""); return; }
      if (e.key === "?") { e.preventDefault(); setHelp(true); return; }
      if (e.key === "j" || e.key === "k") { e.preventDefault(); stepFunction(e.key === "j" ? 1 : -1); return; }
      if (e.key === "v") { e.preventDefault(); markViewed(); return; }
      if (e.key === "n" || e.key === "p") {
        e.preventDefault();
        const moved = stepHunk(stage.current?.querySelector(".cmp-pair-body") ?? null, e.key === "n" ? 1 : -1);
        if (!moved && main !== "all") stepFunction(e.key === "n" ? 1 : -1);
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  });

  // A diff asks about every function it names, so this has to be a lookup.
  const links = useMemo<DiffActions["links"]>(() => ({
    known: (side, at_) => refs[index(side)].has(at_),
    follow: (side, at_) => { const t = opener(d, side, at_, manualRef.current); if (t) openDiff(t); },
    name: (side, at_) => notes[index(side)].label(at_, refs[index(side)].get(at_)?.name),
  }), [d, refs, namesTick]);
  const actions: DiffActions = { links, onOpen: openDiff, onFile: openIn, onPairWith: (side, at_) => setPairing({ side, at: at_ }), onUnpair: unpair };

  const onRenamed = (side: Side, ad: number, name: string) => {
    // A name given in one file carries to the same function in the other, unless that one already has a name.
    const peer = counterpart(d, side, ad, manual), there = notes[index(other(side))];
    if (name && peer !== null && there.renamed(peer) === undefined) there.rename(peer, name);
    setNamesTick((n) => n + 1);
  };
  const fnNote = (side: Side, fn: number): React.ReactNode => {
    const t = opener(d, side, fn, manual);
    if (!t) return null;
    const peerSide = other(side), Peer = peerSide.toUpperCase(), peer = addressOf(t, peerSide);
    const mark = marks[index(side)].get(fn) ?? "same";
    const reason = changeBy.get(keyOf(t))?.reason;
    return (
      <p className="cmp-fnnote">
        <i className={"cmp-dot d-" + mark} />
        <span>{mark === "same" ? `The same in ${Peer}.` : mark === "changed" ? `Changed in ${Peer}.` : `Only in ${side.toUpperCase()}.`}{reason && mark !== "same" && <small> {reason}</small>}</span>
        <button type="button" className="cmp-note-go" onClick={() => openDiff(t)}>Show the difference <kbd>d</kbd></button>
        {peer !== null && <button type="button" className="cmp-note-go" onClick={() => openIn(peerSide, peer)}>Go to it in {Peer} <kbd>{peerSide}</kbd></button>}
        {peer === null && <button type="button" className="cmp-note-go" onClick={() => setPairing({ side, at: fn })}>Diff against…</button>}
      </p>
    );
  };
  const marks = useMemo<[Map<number, Mark>, Map<number, Mark>]>(() => [marksOf(d, "a", manual), marksOf(d, "b", manual)], [d, manual]);

  const [railWidth, setRailWidth] = useStored("compare-rail", 340);
  const labels: [Filter, string][] = [["changes", "Changes"], ["changed", "Changed"], ["removed", "Only in A"], ["added", "Only in B"], ["unchanged", "Unchanged"]];
  const worthEnd = filter === "changes" ? rows.findIndex((r) => r.score < 15) : -1;
  const row = (r: Row) => (
    <button key={r.key} type="button" aria-current={r.key === targetKey ? "true" : undefined}
      className={"cmp-row-item" + (r.key === targetKey ? " on" : "") + (viewed.has(r.key) ? " is-viewed" : "")}
      onClick={() => { setPicked(true); go({ main: main === "all" ? "all" : "diff", target: r.key }); }}
      ref={(el) => { if (el && r.key === targetKey) el.scrollIntoView({ block: "nearest" }); }}>
      <code><i className={"cmp-dot d-" + r.status} title={STATUS[r.status]} />{title(r.target)}{viewed.has(r.key) && <span className="cmp-seen" aria-label="viewed"> ✓</span>}</code>
      <small>{r.reason}</small>
      {r.status === "changed" && r.score > 0 && <span className="cmp-heat" title={`Change weight ${r.score}`} aria-hidden><i style={{ width: `${Math.max(6, Math.min(100, r.score / 1.5))}%` }} /></span>}
    </button>
  );

  const pane = (side: Side) => {
    const i = index(side), analysis = analyses[i];
    const showing = view === side || view === "split";
    const embedded: Embedding = {
      side, notes: notes[i], compact: view === "split", request: requests[i], onPlace: (fn) => onPlace(side, fn), marks: marks[i],
      note: (fn) => fnNote(side, fn), search: searchAll, searchRef: searches.current[i], onRenamed: (ad, name) => onRenamed(side, ad, name), tick: namesTick, keys: KEYS,
    };
    return (
      <div key={side} className={"cmp-pane cmp-pane-" + side + (view === "split" && focus === side ? " is-focus" : "")} hidden={!showing} onMouseDownCapture={() => setFocus(side)}>
        {view === "split" && <div className="cmp-pane-tag"><Tag side={side} /> <span title={d.inputs[i].name}>{d.inputs[i].name}</span></div>}
        {failures[i] ? <p className="error cmp-pad" role="alert">{d.inputs[i].name} could not be analyzed: {failures[i]}. The differences still work.</p>
          : analysis && <Workspace a={analysis} run={runs.current[i]} active={showing && (view !== "split" || focus === side)} initial={{ sel: requests[i]?.at ?? "capa", at: requests[i]?.at ?? null }} onNew={onReset} onFile={() => {}} embedded={embedded} />}
      </div>
    );
  };

  const tab = (v: View, label: React.ReactNode, tip?: string) => (
    <button type="button" role="tab" aria-selected={view === v} className={view === v ? "on" : ""} title={tip} onClick={() => showView(v)}>{label}</button>
  );
  const fileTab = (side: Side) => {
    const an = analyses[index(side)];
    return <><Tag side={side} /> <span className="cmp-tab-name">{d.inputs[index(side)].name}</span>{an && !an.done && !an.tooLarge && <span className="cmp-busy" title="Analyzing">…</span>}</>;
  };

  return (
    <main className="cmp">
      <header className="cmp-top">
        <button type="button" className="brand sm" onClick={onReset} title="Home" aria-label="binfera home"><Wordmark /></button>
        <div role="tablist" aria-label="View" className="cmp-tabs cmp-views">
          {tab("changes", "Changes", "What differs between the two files")}
          {tab("a", fileTab("a"), `Explore ${a.name} on its own (a)`)}
          {tab("b", fileTab("b"), `Explore ${b.name} on its own (b)`)}
          {!mobile && tab("split", <><Tag side="a" /> | <Tag side="b" /></>, "Both files side by side")}
        </div>
        {notice && <span className="cmp-notice" role="status">{notice}</span>}
        {view === "changes" && <button type="button" className="searchbox cmp-search" onClick={() => setPalette("")} title={`Search both files (${searchKey} or /)`}>
          <svg viewBox="0 0 24 24" aria-hidden><circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" /></svg>
          <span>Search both files…</span><kbd>{searchKey}</kbd>
        </button>}
        {view === "split" && (
          <div className="cmp-link-bar">
            <div role="group" aria-label="How the two panes move" className="cmp-tabs">
              <button type="button" aria-pressed={!linked} className={!linked ? "on" : ""} onClick={() => setLinked(false)} title="Each side keeps its own place">Independent</button>
              <button type="button" aria-pressed={linked} className={linked ? "on" : ""} title="Moving in one side moves the other to the matching function" onClick={() => {
                setLinked(true);
                const fn = places[index(focus)], peer = fn === null ? null : counterpart(d, focus, fn, manual);
                if (peer !== null) ask(other(focus), peer);
              }}>Linked</button>
            </div>
            <button type="button" className="cmp-btn" disabled={places[0] === null && places[1] === null} onClick={diffHere} title="Show the difference between what the two panes have open (d)">Diff these two</button>
          </div>
        )}
        {view === "changes" && <button type="button" className="cmp-btn" onClick={() => setHelp(true)} aria-label="Keyboard shortcuts" title="Keyboard shortcuts (?)">?</button>}
        <ReportMenu groups={[{ title: "Comparison", items: [
          { label: "Report (Markdown)", onClick: () => download(compareFileStem(d) + ".md", compareMarkdown(d, manual), "text/markdown") },
          { label: "Report (web page)", onClick: () => download(compareFileStem(d) + ".html", compareHtml(d, manual), "text/html") },
          { label: "All data (JSON)", note: "the engine's document", onClick: () => download(compareFileStem(d) + ".json", compareJson(d, manual), "application/json") },
        ] }]} />
        <ThemeToggle />
      </header>

      <div className={"cmp-changes" + (picked ? " is-picked" : "")} hidden={view !== "changes"} ref={stage} style={{ gridTemplateColumns: `${railWidth}px minmax(0, 1fr)` }}>
        <aside className="cmp-rail" aria-label="What changed">
          <div className="cmp-summary">
            <p className="cmp-headline-sm">{summary.headline}</p>
            {summary.details.map((x) => <p key={x} className="fine">{x}</p>)}
            <button type="button" className={"cmp-link cmp-details-link" + (main === "details" ? " on" : "")} onClick={() => { setPicked(true); go({ main: "details" }); }}>File details</button>
          </div>
          {d.functions_compared && <>
            <div className="cmp-rail-tools">
              <div role="tablist" aria-label="Which functions" className="cmp-tabs cmp-filters">
                {labels.map(([k, label]) => <button key={k} type="button" role="tab" aria-selected={filter === k} className={filter === k ? "on" : ""} onClick={() => setFilter(k)}>{label} <small>{counts[k]}</small></button>)}
              </div>
              <input type="search" placeholder="Filter by name, address or change" aria-label="Filter functions" value={query} onChange={(e) => setQuery(e.target.value)} />
              <div className="cmp-rail-mode">
                <div role="group" aria-label="How to read" className="cmp-tabs">
                  <button type="button" aria-pressed={main !== "all"} className={main !== "all" ? "on" : ""} onClick={() => go({ main: "diff", target: targetKey ?? rows[0]?.key ?? null })}>One at a time</button>
                  <button type="button" aria-pressed={main === "all"} className={main === "all" ? "on" : ""} disabled={!changes.length} onClick={() => { setPicked(true); go({ main: "all" }); }}>All changes</button>
                </div>
                {changes.length > 0 && <small className="fine">{viewedCount} of {changes.length} viewed</small>}
              </div>
            </div>
            <div className="cmp-rail-list">
              {rows.length === 0 && <p className="fine cmp-empty">{query ? "No functions match." : filter === "changes" ? "No function differs." : "None here."}</p>}
              {rows.slice(0, shown).map((r, i) => <div key={r.key} className="cmp-row-wrap">
                {filter === "changes" && !query && i === 0 && worthEnd !== 0 && <h3 className="cmp-group">Worth a look</h3>}
                {filter === "changes" && !query && i === worthEnd && <h3 className="cmp-group">Other changes</h3>}
                {row(r)}
              </div>)}
              {rows.length > shown && <button type="button" className="cmp-btn cmp-more" onClick={() => setShown(shown + PAGE)}>Show more ({rows.length - shown} left)</button>}
            </div>
          </>}
        </aside>
        {!mobile && <Splitter label="Resize the list of changes" value={railWidth} min={240} max={620} onChange={setRailWidth} style={{ left: railWidth }} />}
        <div className="cmp-main">
          {main === "details" || !d.functions_compared ? (
            <>
              <button type="button" className="cmp-btn cmp-back cmp-back-pad" onClick={() => setPicked(false)}>Back to list</button>
              <CompareDetails c={c} onOpen={(side, at_) => { const t = opener(d, side, at_, manual); if (t) openDiff(t); }} onFunctions={changes.length ? () => go({ main: "all" }) : undefined} />
            </>
          ) : main === "all" ? (
            <>
              <button type="button" className="cmp-btn cmp-back cmp-back-pad" onClick={() => setPicked(false)}>Back to list</button>
              <StackedDiffs c={c} manual={manual} actions={actions} items={changes.slice(0, shown).map((x) => ({ key: x.key, target: x.target, reason: x.reason }))} more={Math.max(0, changes.length - shown)} onMore={() => setShown(shown + PAGE)} isViewed={(k) => viewed.has(k)} onViewed={toggleViewed} onSingle={(t) => go({ main: "diff", target: keyOf(t) })} />
            </>
          ) : target ? (
            <FunctionDiff c={c} target={target} manual={manual} reason={changeBy.get(keyOf(target))?.reason} viewed={viewed.has(keyOf(target))} onViewed={() => toggleViewed(keyOf(target))} actions={actions} onClose={() => setPicked(false)}
              onPrevious={at > 0 ? () => stepFunction(-1) : undefined} onNext={at < rows.length - 1 ? () => stepFunction(1) : undefined} />
          ) : <p className="fine cmp-pad">No function differs. <button type="button" className="cmp-link" onClick={() => go({ main: "details" })}>See the file details</button></p>}
        </div>
      </div>

      <div className={"cmp-panes" + (view === "split" ? " is-split" : "")} hidden={view === "changes"}>
        {pane("a")}
        {pane("b")}
      </div>

      <footer className="statusbar"><BuildVersion /></footer>
      {palette !== null && <Palette initial={palette} search={searchAll} onClose={() => setPalette(null)} />}
      {pairing && <Palette initial="" search={pairSearch} placeholder={`Compare this function with one in ${other(pairing.side).toUpperCase()}: name or address`} onClose={() => setPairing(null)} />}
      {help && <Shortcuts extra={[...KEYS, ...CHANGES_KEYS]} onClose={() => setHelp(false)} />}
    </main>
  );
}
