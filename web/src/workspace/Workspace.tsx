import CommentEditor from "../views/CommentEditor";
import { useEffect, useMemo, useReducer, useRef, useState } from "react";
import type { Analysis } from "../types";
import HexView, { asText, cArray, hexOf, type HexSelection } from "../HexView";
import ImportsView from "../ImportsView";
import Listing from "../Listing";
import CallGraph from "../CallGraph";
import Navigator from "../Navigator";
import MoreMenu, { type MenuItem } from "../MoreMenu";
import Sheet from "../Sheet";
import Palette, { type PaletteItem } from "../Palette";
import Shortcuts, { isMac, searchKey } from "../Shortcuts";
import { Notes, NotesProvider, sha256 } from "../names";
import { project } from "../project/client";
import AgentDock from "../views/AgentDock";
import { agent } from "../agent/client";
import { hex, bytes } from "./labels";
import { useMobile } from "./useMobile";
import { hashOf, locOf, pageUrl, panesOf, parseHash, writeEntry, type CodeView, type Entry, type Loc, type Sel, type Tab } from "./location";
import { Splitter, useMedia, useStored } from "./panels";
import { useContainment, ownersOf, useFunctionRules } from "./ownership";
import { useReferences } from "./references";
import { Glance } from "../views/Glance";
import { LayoutCard, FindingsCard } from "../views/Dashboard";
import ThemeToggle from "../ThemeToggle";
import ReportMenu from "../ReportMenu";
import VirtualList, { type VirtualListHandle } from "./VirtualList";
import ContextMenu, { copyText, type MenuEntry } from "../ContextMenu";
import { toast, ToastHost } from "../Toast";
import type { Reverted } from "../names";
import { csv, download, reportHtml, reportMarkdown, type ReportInput } from "../report";
import { chooseTheme, storedTheme } from "../theme";
import { FeatureMap } from "../views/FeatureMap";
import { FirstLook, guessToolchains } from "../views/FirstLook";
import { FileView } from "../views/FileView";
import { CapabilityView } from "../views/CapabilityView";
import { FunctionView, type FnViewProps, type Layout } from "../views/FunctionView";
import type { PanePlace, PaneRenderer } from "./CodePanes";
import { StringsView } from "../views/StringsView";
import PaneData from "../views/PaneData";
import { extractIndicators } from "../indicators";
import { textAt } from "../engine/strings";
import Wordmark from "../Wordmark";
import BuildVersion from "../BuildVersion";
import { ShellcodeNotice } from "../views/ShellcodeNotice";
import { NATIVE } from "../engine/assets";
import { importThunk } from "../annotations";
import { resolvedSlots } from "../resolved";
import { callDepths, importance, progress as triageProgress, triageFunctions, type FnSort } from "../triage";
import { codeVocabulary, isLocalName } from "../highlight";
import type { RawCodeOptions } from "../engine/engine.worker";

/** The page's own title, from index.html, to restore on leaving a file. */
const HOME_TITLE = document.title;

const SORT_LABELS: Record<FnSort, string> = { address: "Address", importance: "Importance", bottom_up: "Bottom-up", caps: "Capabilities", name: "Name" };
const SORT_HINTS: Record<FnSort, string> = { address: "Order in the file", importance: "Most worth reading first", bottom_up: "Leaf functions before their callers", caps: "Most capability matches first", name: "Alphabetical" };

const MARK_TITLE = { changed: "Differs in the other file", added: "Only in this file", removed: "Only in this file", same: "The same in the other file" } as const;

/** What a comparison gives one of its two files' workspaces, and asks of it. */
export interface Embedding {
  /** Which file this is. */
  side: "a" | "b";
  notes: Notes;
  /** Two panes share the window: less chrome, one code pane and no side panel to start with. */
  compact: boolean;
  /** A function to open, from outside; `tick` makes the same one openable twice. */
  request: { at: number; tick: number } | null;
  onPlace: (fn: number | null) => void;
  /** Whether each function changed, for the list. */
  marks: Map<number, "changed" | "added" | "removed" | "same">;
  /** What the comparison says about the open function. */
  note: (fn: number) => React.ReactNode;
  /** Search reaches both files. */
  search: (q: string) => PaletteItem[];
  /** This workspace's own search, for the other pane and the comparison to call. */
  searchRef: { current: ((q: string) => PaletteItem[]) | null };
  onRenamed: (ad: number, name: string) => void;
  /** Bumped when something outside changed this file's names. */
  tick: number;
  /** Shortcuts the comparison adds. */
  keys: [string, string][];
}

export default function Workspace(props: WorkspaceProps) {
  const notes = useMemo(() => props.embedded?.notes ?? new Notes(), [props.embedded?.notes]);
  return <NotesProvider value={notes}><Inner {...props} notes={notes} /></NotesProvider>;
}

interface WorkspaceProps {
  a: Analysis; onNew: () => void; onFile: (f: File) => void;
  onAnalyzeAgain?: () => void;
  onShellcodeChange?: (raw: RawCodeOptions) => void;
  /** Start a comparison with this file as one side; the other is chosen next. */
  onCompare?: () => void;
  /** Identifies this analysis in browser history entries. */
  run: number;
  /** False while the landing page is over this analysis: it keeps its place but takes no keys and leaves the URL alone. */
  active: boolean;
  /** Where to open: the place a link named, or the overview. */
  initial: { sel: Sel; at: number | null; layout?: string };
  /** Inside a comparison: this file's place is its own, not the browser's. */
  embedded?: Embedding;
}

function Inner({ a, onNew, onFile, onCompare, onShellcodeChange, onAnalyzeAgain, run, active, initial, embedded, notes }: WorkspaceProps & { notes: Notes }) {
  const fnLabel = (ad: number, name?: string | null) => notes.label(ad, name ?? a.functions.get(ad)?.name ?? a.names.get(ad));
  const isStarred = (ad: number) => notes.isStarred(ad);
  const exportOf = (ad: number) => notes.exportOf(ad);
  const compact = !!embedded?.compact;
  const containment = useContainment(a);
  // Exported names stand in for FUN_ labels; set before anything renders a label.
  useMemo(() => notes.setExportNames(new Map((a.image?.exports ?? []).filter((e) => e.va).map((e) => [e.va, e.name]))), [a.image]);
  const { byFn, fileLevel } = useFunctionRules(a, containment);
  const indicators = useMemo(() => extractIndicators(a.strings), [a.strings]);
  // Every place visited is a browser history entry, so the toolbar arrows, browser Back and a phone's back gesture agree.
  const [loc, setLoc] = useState<Loc>(() => locOf(initial.sel));
  const { sel, tab, detail } = loc;
  const [pos, setPos] = useState({ i: 0, max: 0 });
  const posRef = useRef(pos);
  const cursorRef = useRef<number | null>(initial.at);
  const mobile = useMobile();
  const [locateOpen, setLocateOpen] = useState(false), [filtersOpen, setFiltersOpen] = useState(false), [chromeHidden, setChromeHidden] = useState(false);
  const urlOf = (l: Loc, at: number | null) => pageUrl(hashOf(a.demo?.id, l, layout, at));
  // A file in a comparison keeps its own history: two panes cannot share the browser's.
  const ownHistory = useRef<Entry[]>([{ binfera: true, run, i: 0, ...locOf(initial.sel), at: initial.at }]);
  const record = (mode: "push" | "replace", entry: Entry, url: string) => {
    if (!embedded) { writeEntry(mode, entry, url); return; }
    ownHistory.current = [...ownHistory.current.slice(0, entry.i), entry];
  };
  const push = (next: Loc) => {
    const i = posRef.current.i + 1;
    posRef.current = { i, max: i };
    setPos(posRef.current);
    setLoc(next);
    record("push", { binfera: true, run, i, ...next, at: cursorRef.current }, urlOf(next, cursorRef.current));
  };
  const setSel = (s: Sel, keepCursor = false) => {
    // Opening a function from a list puts the cursor at its entry, unless the cursor is already inside it.
    if (typeof s === "number" && !keepCursor && !(cursorRef.current !== null && ownersOf(a, containment, cursorRef.current).includes(s))) setCursor(s);
    // A function opens as its own page on a phone; the back gesture closes it.
    const next: Loc = typeof s === "number" ? { sel: s, tab, detail: true } : locOf(s);
    if (next.sel !== sel || next.tab !== tab || next.detail !== detail) push(next);
  };
  // The one address every view follows: set by clicking an instruction, a hex byte, a string or a capability match.
  const [cursor, setCursorState] = useState<number | null>(initial.at);
  // Counts every placement, so a view scrolls to the cursor even when the same address is picked again.
  const [cursorTick, setCursorTick] = useState(0);
  const setCursor = (ad: number) => {
    cursorRef.current = ad;
    setCursorState(ad);
    setCursorTick((n) => n + 1);
    setHexSel(null);
  };
  const [hexSel, setHexSel] = useState<HexSelection | null>(null);
  // Opened on a function with no cursor yet (a shared link, a restored session): the views start at that function, not the file's top.
  useEffect(() => { if (typeof sel === "number" && cursorRef.current === null) setCursor(sel); }, [sel]);
  const [ctx, setCtx] = useState<{ x: number; y: number; items: MenuEntry[] } | null>(null);
  const [impQuery, setImpQuery] = useState("");
  const [palette, setPalette] = useState<string | null>(null);
  const [tick, bump] = useReducer((n: number) => n + 1, 0);
  // Notes follow the file's contents, whatever it is called. The capa report's hash covers a page without WebCrypto.
  const [hash, setHash] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    if (a.image && crypto.subtle) sha256(a.image.bytes).then((h) => { if (live) setHash(h); }).catch(() => {});
    return () => { live = false; };
  }, [a.image]);
  const noteKey = hash ?? a.capa?.sample.sha256 ?? null;
  useEffect(() => { if (noteKey) { notes.load(noteKey, a.fileName + ":" + a.size); bump(); } }, [noteKey]);
  // Desktop: share the notes with the project database, so an MCP agent's edits arrive live.
  useEffect(() => (noteKey ? notes.attach(noteKey, a.fileName, a.size, bump) : undefined), [noteKey]);
  // The dock reads artifacts and the input path on mount, so register the project first.
  const agentSha = noteKey && notes.isAttached(noteKey) ? noteKey : null;
  const [onlyStars, setOnlyStars] = useState(false);
  const [fnSort, setFnSort] = useState<FnSort>("address");
  const [hideLibrary, setHideLibrary] = useStored("hide-library", false);
  const [listingReq, setListingReq] = useState(0);
  const listingSeen = useRef(0);
  const [wideLayout, setWideLayout] = useState<Layout>(() => { if (initial.layout) return initial.layout; try { const v = localStorage.getItem("layout2"); return v ? panesOf(v).join("+") : "c+listing"; } catch { return "c+listing"; } });
  const [compactLayout, setCompactLayout] = useState<Layout>("c");
  const layout = compact ? compactLayout : wideLayout, setLayout = compact ? setCompactLayout : setWideLayout;
  const [previousLayout, setPreviousLayout] = useStored("pane-layout", "c+asm");
  const toggleSplit = () => {
    const panes = panesOf(layout);
    if (panes.length > 1) { setPreviousLayout(layout); setLayout(panes[0]); return; }
    const restored = panesOf(previousLayout);
    setLayout(restored.length > 1 ? restored.join("+") : panes[0] + "+asm");
  };
  useEffect(() => { try { localStorage.setItem("layout2", wideLayout); } catch {} }, [wideLayout]);
  // Where Code and Data reopen when their header button is pressed.
  const lastFn = useRef<number | null>(null), lastData = useRef<"strings" | "imports" | "hex" | "file">("strings");
  useEffect(() => {
    if (typeof sel === "number") lastFn.current = sel;
    else if (sel !== "capa") lastData.current = sel;
  }, [sel]);
  // Coming back to an entry restores its place and cursor; a hand-edited hash is a new place.
  const restore = (st: Entry) => {
    posRef.current = { i: st.i, max: Math.max(posRef.current.max, st.i) };
    setPos(posRef.current);
    setLoc({ sel: st.sel, tab: st.tab, detail: st.detail });
    if (st.at !== null && st.at !== cursorRef.current) setCursor(st.at);
  };
  useEffect(() => {
    if (embedded) return;
    const onPop = () => {
      const st = history.state as Entry | null;
      if (st?.binfera && st.run === run) restore(st);
      else if (!st) {
        const t = parseHash();
        if (t.sel === undefined) return;
        const next = locOf(t.sel), i = posRef.current.i + 1;
        posRef.current = { i, max: i };
        setPos(posRef.current);
        setLoc(next);
        if (t.layout) setLayout(t.layout as Layout);
        if (t.at !== undefined) setCursor(t.at);
        writeEntry("replace", { binfera: true, run, i, ...next, at: t.at ?? null }, location.href);
      }
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [run]);
  // The address bar follows the place, the view and the cursor; none of those last two add a history entry.
  useEffect(() => {
    if (embedded) {
      const at = posRef.current.i, own = ownHistory.current;
      if (own[at]) ownHistory.current = own.map((e, i) => (i === at ? { ...e, at: cursor } : e));
      return;
    }
    if (!active || history.state?.run !== run) return;
    writeEntry("replace", { ...(history.state as Entry), at: cursor }, urlOf(loc, cursor));
  }, [active, loc, cursor, layout]);
  // Returning from the landing page starts a new branch of history.
  const wasActive = useRef(active);
  useEffect(() => {
    if (active && !wasActive.current) { posRef.current = { ...posRef.current, max: posRef.current.i }; setPos(posRef.current); }
    wasActive.current = active;
  }, [active]);
  // A link from another file can name an address this one does not have.
  useEffect(() => {
    if (!a.done || typeof sel !== "number" || a.functions.has(sel) || a.order.includes(sel)) return;
    // The comparison's function starts can differ from the decompiler's: show the one holding the address.
    const holder = embedded && containment ? ownersOf(a, containment, sel)[0] : undefined;
    if (holder !== undefined) { setCursor(sel); setLoc(locOf(holder)); } else setLoc(locOf("capa"));
  }, [a.done, sel]);
  const toggleRail = () => { if (compact) setCompactRail(!compactRail); else setRailPref(!railOpen); };
  const canBack = pos.i > 0, canForward = pos.i < pos.max;
  const stepOwn = (by: number) => { const st = ownHistory.current[posRef.current.i + by]; if (st) restore(st); };
  const back = () => { if (posRef.current.i > 0) { if (embedded) stepOwn(-1); else history.back(); } };
  const forward = () => { if (posRef.current.i < posRef.current.max) { if (embedded) stepOwn(1); else history.forward(); } };
  const displayName = a.demo?.name ?? a.fileName;
  const [q, setQ] = useState("");
  const [strQuery, setStrQuery] = useState("");
  const [strOnlyRef, setStrOnlyRef] = useState(true);
  const [strIndicators, setStrIndicators] = useState(false);
  const [onlyCaps, setOnlyCaps] = useState(false);
  const [dragging, setDragging] = useState(false);
  useEffect(() => {
    const clear = () => setDragging(false);
    const escape = (e: KeyboardEvent) => { if (e.key === "Escape") clear(); };
    const start = (e: DragEvent) => { if (!e.dataTransfer?.types.includes("Files")) clear(); };
    window.addEventListener("dragstart", start, true);
    window.addEventListener("dragend", clear, true);
    window.addEventListener("drop", clear, true);
    window.addEventListener("blur", clear);
    window.addEventListener("keydown", escape, true);
    return () => {
      window.removeEventListener("dragstart", start, true);
      window.removeEventListener("dragend", clear, true);
      window.removeEventListener("drop", clear, true);
      window.removeEventListener("blur", clear);
      window.removeEventListener("keydown", escape, true);
    };
  }, []);
  const [help, setHelp] = useState(false);
  // Narrow layout only: the agent as a tab. The wide layout docks it beside the code instead.
  const [agentView, setAgentView] = useState(false);
  // The agent panel (desktop only): a chat with the analyst's own Claude Code or Codex beside the code.
  const [agentOpen, setAgentOpen] = useStored("agent-open", false);
  const [agentWidth, setAgentWidth] = useStored("agent-width", 400);
  const [agentBusy, setAgentBusy] = useState(false);
  // A narrow window gets the agent as an overlay on the code; a wide one pushes the code over.
  const overlayDock = useMedia("(max-width: 1300px)");
  // Any other navigation leaves the AI view.
  useEffect(() => { setAgentView(false); }, [sel]);
  const root = useRef<HTMLDivElement>(null);
  const [commentEdit, setCommentEdit] = useState<{ address: number; rect?: DOMRect } | null>(null);
  const editComment = (address: number, target?: Element) => {
    const row = target ?? root.current?.querySelector(`[data-addr="${address}"], [data-ctx-va="${address}"]`);
    setCommentEdit({ address, rect: row?.getBoundingClientRect() });
  };
  /** What an undone or redone edit did, in words. */
  const describeEdit = (verb: "Undid" | "Redid", op: Reverted) => {
    const [at, id] = op.target.split(":"), ad = parseInt(at, 16);
    const [from, to] = verb === "Undid" ? [op.after, op.value] : [op.value, op.after];
    const shown = (v?: string) => (v ? `“${v}”` : "the original");
    if (op.kind === "rename_function") return `${verb} rename: ${shown(from)} → ${shown(to)}`;
    if (op.kind === "rename_variable") return `${verb} rename of ${id}: ${shown(from)} → ${shown(to)}`;
    if (op.kind === "star") return `${verb} ${op.after ? "starring" : "unstarring"} ${fnLabel(ad)}`;
    return `${verb} comment at ${hex(ad)}`;
  };
  const revert = (verb: "Undid" | "Redid") => {
    const op = verb === "Undid" ? notes.undo() : notes.redo();
    if (!op) { toast(verb === "Undid" ? "Nothing to undo" : "Nothing to redo"); return; }
    if (op.kind === "rename_function") embedded?.onRenamed(parseInt(op.target, 16), (verb === "Undid" ? op.value : op.after) ?? "");
    toast(describeEdit(verb, op));
    bump();
  };
  const undo = () => revert("Undid"), redo = () => revert("Redid");
  const toggleStar = (ad: number) => { notes.toggleStar(ad); toast(`${notes.isStarred(ad) ? "Starred" : "Removed star from"} ${fnLabel(ad)}`); bump(); };
  const [renameReq, askRename] = useReducer((n: number) => n + 1, 0);
  const [xrefReq, askXrefs] = useReducer((n: number) => n + 1, 0);
  // Panels: their sizes and whether they show are remembered. Until chosen, the side panel leaves a narrower window to the code.
  const narrow = useMedia("(max-width: 1180px)"), tight = useMedia("(max-width: 1000px)");
  const [listWidth, setListWidth] = useStored("list-width", 280);
  const [listPref, setListPref] = useStored<boolean>("list-open", true);
  const [railPref, setRailPref] = useStored<boolean | null>("rail-open", null);
  const [compactRail, setCompactRail] = useState(false);
  // The inspector starts closed: it is opened from the header or its edge tab, and the choice is remembered.
  const [focus, setFocus] = useState(false);
  // The agent panel mounts only once the analyst opens it for this file. Mounting it starts their
  // Claude Code or Codex to list models, which contacts the provider; opening a file must not.
  // Once mounted it stays mounted, so a conversation survives hiding the panel.
  const [agentMountedFor, setAgentMountedFor] = useState<string | null>(null);
  useEffect(() => {
    if (agentSha && ((agentOpen && !focus) || agentView)) setAgentMountedFor(agentSha);
  }, [agentSha, agentOpen, agentView, focus]);
  const agentMounted = agentSha !== null && agentMountedFor === agentSha;
  const railOpen = compact ? compactRail : (railPref ?? false) && !focus;
  const [onlyChanged, setOnlyChanged] = useState(false);
  const listShownWidth = compact ? Math.min(listWidth, 190) : tight ? Math.min(listWidth, 230) : listWidth;

  // Cross-references are derived from the decompiled text: any identifier or hex literal that names a function.
  const { resolve, callers, callees, strRefs, fnStrings, strByAddr, importRefs, xrefs, codeIndex } = useReferences(a);
  /** The imported APIs each function calls, by name. */
  const apisByFn = useMemo(() => {
    const m = new Map<number, string[]>();
    // Reading a library variable such as stdout is not a call.
    const variables = new Set(a.image?.imports.filter((i) => i.data).map((i) => i.name));
    for (const [name, fns] of importRefs) if (!variables.has(name)) for (const ad of new Set(fns)) m.set(ad, [...(m.get(ad) ?? []), name]);
    for (const names of m.values()) names.sort((x, y) => x.localeCompare(y));
    return m;
  }, [importRefs, a.image]);
  const library = useMemo(() => new Set(a.capa?.library ?? []), [a.capa]);
  const libraryCount = useMemo(() => a.order.filter((ad) => library.has(ad)).length, [a.order, library]);
  // Triage signals: computed once the functions have settled, since they read the call graph and references.
  const importanceOf = useMemo(() => {
    if (fnSort !== "importance") return null;
    const strings = new Map([...fnStrings].map(([ad, l]) => [ad, l.length]));
    const imports = new Map<number, number>();
    for (const fns of importRefs.values()) for (const ad of fns) imports.set(ad, (imports.get(ad) ?? 0) + 1);
    const capabilities = new Map([...byFn].map(([ad, l]) => [ad, l.length]));
    return importance({ functions: triageFunctions(a, callees), capabilities, strings, imports, callers });
  }, [fnSort, a.functions, a.order, byFn, fnStrings, importRefs, callers, callees, tick]);
  const depthOf = useMemo(() => (fnSort === "bottom_up" ? callDepths(triageFunctions(a, callees)) : null), [fnSort, a.functions, a.order, callees]);
  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const shown = a.order.filter((ad) => {
      if (onlyCaps && !byFn.has(ad)) return false;
      if (onlyChanged && (embedded?.marks.get(ad) ?? "same") === "same") return false;
      if (onlyStars && !isStarred(ad)) return false;
      if (hideLibrary && library.has(ad)) return false;
      if (!needle) return true;
      const f = a.functions.get(ad);
      return hex(ad).includes(needle) || fnLabel(ad, f?.name).toLowerCase().includes(needle) ||
        (byFn.get(ad) ?? []).some((r) => r.name.toLowerCase().includes(needle));
    });
    // Most capability matches first; functions with the same count keep address order.
    if (fnSort === "importance" && importanceOf) shown.sort((x, y) => (importanceOf.get(y)?.score ?? 0) - (importanceOf.get(x)?.score ?? 0) || x - y);
    else if (fnSort === "bottom_up" && depthOf) shown.sort((x, y) => (depthOf.get(x) ?? 0) - (depthOf.get(y) ?? 0) || x - y);
    else if (fnSort === "caps") shown.sort((x, y) => (byFn.get(y)?.length ?? 0) - (byFn.get(x)?.length ?? 0) || x - y);
    else if (fnSort === "name") shown.sort((x, y) => fnLabel(x, a.functions.get(x)?.name).localeCompare(fnLabel(y, a.functions.get(y)?.name)) || x - y);
    return shown;
  }, [a.order, a.functions, q, onlyCaps, onlyStars, onlyChanged, embedded?.marks, embedded?.tick, fnSort, byFn, tick, hideLibrary, library, importanceOf, depthOf]);

  // A new order or filter starts at the top: the top is what the sort is for.
  const fnListRef = useRef<VirtualListHandle>(null);
  useEffect(() => { fnListRef.current?.scrollToIndex(0); }, [fnSort, hideLibrary, onlyCaps, onlyStars, onlyChanged]);

  // Keyboard: j/k step through the visible list from anywhere; the arrows only while the list has focus, so they still scroll and move inside other views.
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (!active || help) return;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette(""); return; }
      // Works from inside the chat box too, so the keyboard can leave it as easily as enter it.
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "j" && agent && project && agentSha && !mobile) { e.preventDefault(); setAgentOpen(!agentOpen); return; }
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "l" && agent && project && agentSha && !mobile) { e.preventDefault(); setAgentOpen(true); setTimeout(() => window.dispatchEvent(new Event("binfera-agent-focus")), 0); return; }
      const target = e.target as HTMLElement;
      if (target.closest?.("input, select, textarea, [contenteditable=true], .palette")) return;
      if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "z") { e.preventDefault(); if (e.shiftKey) redo(); else undo(); return; }
      if (e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "y") { e.preventDefault(); redo(); return; }
      if (e.key === ";" && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const ad = cursorRef.current ?? (typeof sel === "number" ? sel : null);
        if (ad !== null) { e.preventDefault(); editComment(ad); }
        return;
      }
      if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) { e.preventDefault(); (e.key === "ArrowLeft" ? back : forward)(); return; }
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "/" || e.key === "g") { e.preventDefault(); setPalette(e.key === "g" ? "0x" : ""); return; }
      if (e.key === "?") { e.preventDefault(); setHelp(true); return; }
      if (typeof sel === "number" && e.key === "n") { e.preventDefault(); askRename(); return; }
      if (typeof sel === "number" && e.key === "x") { e.preventDefault(); askXrefs(); return; }
      if (typeof sel === "number" && e.key === "s") { e.preventDefault(); toggleStar(sel); return; }
      if (e.key === "[" && !mobile) { setListPref(!listPref); return; }
      if (e.key === "]" && !mobile) { toggleRail(); return; }
      if (e.key === "f" && !mobile && !embedded) { setFocus((v) => !v); return; }
      if (e.key === "Escape" && focus) { setFocus(false); return; }
      if (e.key === "\\" && !mobile && typeof sel === "number") { toggleSplit(); return; }
      const inList = !!target.closest?.(".list");
      const dir = e.key === "j" || (inList && e.key === "ArrowDown") ? 1 : e.key === "k" || (inList && e.key === "ArrowUp") ? -1 : 0;
      if (!dir) return;
      e.preventDefault();
      const i = typeof sel === "number" ? list.indexOf(sel) : -1;
      const next = list[Math.min(list.length - 1, Math.max(0, i + dir))];
      if (next !== undefined) setSel(next);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [list, loc, active, help, mobile, listPref, railOpen, layout, agentOpen, agentSha, focus]);

  // What the comparison around this file asks for, and what it wants to know.
  const handledRequest = useRef(embedded?.request?.tick ?? 0);
  useEffect(() => {
    const req = embedded?.request;
    if (!req || req.tick === handledRequest.current) return;
    handledRequest.current = req.tick;
    // The comparison's function starts can differ from the decompiler's: use the one holding the address.
    if (containment && !a.order.includes(req.at)) goto(req.at);
    else { setCursor(req.at); setSel(req.at); }
  }, [embedded?.request]);
  const placed = typeof sel === "number" ? sel : null;
  // Opening a function counts as examining it; the list's progress follows.
  useEffect(() => { if (placed !== null && notes.markExamined(placed)) bump(); }, [placed, noteKey]);
  useEffect(() => { embedded?.onPlace(placed); }, [placed]);
  useEffect(() => { if (embedded) bump(); }, [embedded?.tick]);

  const total = a.order.length;
  const done = a.functions.size;
  const totalCaps = (a.capa?.rules ?? []).filter((r) => !r.lib).length;
  const progress = total ? done / total : 0;
  const goto = (ad: number) => {
    const o = ownersOf(a, containment, ad)[0];
    setCursor(ad);
    if (o !== undefined) setSel(o);
  };
  const image = a.image;
  /** Adds a pane of this kind beside the code unless one is showing; with three already open, it replaces the last. */
  const ensurePane = (view: string) => {
    const panes = panesOf(layout);
    if (!panes.includes(view as CodeView)) setLayout((panes.length < 3 ? [...panes, view] : [...panes.slice(0, -1), view]).join("+"));
  };
  /** A string clicked in the code: the Strings pane opens beside it, on that string. Phones and files with no functions go to the Strings page. */
  const openStringAt = (va: number, nav?: (va: number) => void) => {
    const text = strByAddr.get(va)?.s ?? "";
    if (mobile || !a.order.length) { showString(text); return; }
    setCursor(va);
    ensurePane("strings");
    nav?.(va);
    if (typeof sel !== "number") { const t = lastFn.current ?? a.order[0]; if (t !== undefined) setSel(t, true); }
  };
  const openString = (text: string, nav?: (va: number) => void) => {
    const x = a.strings.find((x) => x.s === text);
    if (x) openStringAt(x.a, nav); else showString(text);
  };
  /** An import clicked in code: the Imports pane opens beside it, on that import's slot. */
  const openImport = (name: string, nav?: (va: number) => void) => {
    const i = image?.imports.find((i) => i.name === name);
    if (mobile || !a.order.length || !i?.va) { setImpQuery(name); setSel("imports"); return; }
    setCursor(i.va);
    ensurePane("imports");
    nav?.(i.va);
    if (typeof sel !== "number") { const t = lastFn.current ?? a.order[0]; if (t !== undefined) setSel(t, true); }
  };
  /** A data address clicked in code: strings open the Strings pane; anything else shows in the Listing. */
  const openData = (va: number, nav?: (va: number) => void) => { if (strByAddr.has(va)) openStringAt(va, nav); else (nav ?? showData)(va); };
  /** Show an address in a hex pane beside the code, optionally selecting the bytes of a string. A phone opens its Hex tab; a file with no functions yet keeps the hex beside the Data list. */
  const showHex = (va: number, len = 0) => {
    setCursor(va);
    setHexSel(len ? { va, len } : null);
    if (mobile) { setSel("hex"); return; }
    if (!a.order.length) { if (typeof sel === "number" || sel === "capa") setSel(lastData.current); return; }
    ensurePane("hex");
    const target = codeOwner(va) ?? (typeof sel === "number" ? sel : lastFn.current ?? a.order[0]);
    if (target !== undefined) setSel(target, true);
  };
  /** Go to an address: the instruction when it is code, else the bytes. */
  /** An export or a library variable: its function when it is code, its line in the Listing when it is file data, its references when it has no bytes in the file (.bss). */
  const openSymbol = (va: number) => {
    const code = containment ? containment.has(va) : a.order.includes(va);
    if (code) { goto(va); return; }
    if (image && image.vaToOff(va) === null) {
      if (xrefCount(va)) { showRefs(va); return; }
      const where = image.sectionAt(va)?.name;
      toast(`${exportOf(va) ?? hex(va)} is uninitialised data${where ? " in " + where : ""}: no bytes in the file, and no code refers to it`);
      return;
    }
    const t = listingTarget(va);
    if (t === undefined) { showHex(va); return; }
    setCursor(va); setHexSel(null);
    ensurePane("listing");
    setListingReq((n) => n + 1);
    setSel(t, true);
  };
  const jump = (ad: number) => {
    const code = containment ? containment.has(ad) : a.order.includes(ad);
    if (code || !image || image.vaToOff(ad) === null) goto(ad); else showHex(ad);
  };
  // Where "we are" on the strip: the cursor, or the open function's entry until one is placed.
  const navPos = cursor ?? (typeof sel === "number" ? sel : null);
  // The open function's extent on the strip, so a click inside it moves the marker within a visible bracket.
  const navRange = (() => {
    const asm = typeof sel === "number" ? a.functions.get(sel)?.asm : undefined;
    return asm?.length ? { from: asm[0][0], to: asm[asm.length - 1][0] } : null;
  })();
  const dataAt = (ad: number) => !!image && image.vaToOff(ad) !== null && !(containment?.has(ad));


  // Cross-references are derived from the decompiled text: any identifier or hex literal that names a function.
  const showString = (text: string) => { setStrQuery(text); setStrOnlyRef(false); setStrIndicators(false); setSel("strings"); };
  const strAtVa = (va: number) => strByAddr.get(va)?.s;
  const textAtVa = (va: number) => (image && dataAt(va) ? textAt(image, va) : undefined);
  const showRefs = (what: number | string) => setPalette("x:" + (typeof what === "number" ? hex(what) : what));
  const ownerLabel = (va: number) => {
    const o = ownersOf(a, containment, va)[0];
    return o !== undefined && containment?.has(va) ? { address: o, label: fnLabel(o, a.functions.get(o)?.name) } : undefined;
  };
  const openAt = (fn: number, at: number) => { if (at >= 0) setCursor(at); setSel(fn, at >= 0); };
  /** Where a function mentions an address (or import name): the instruction, else the first decompiled line naming it. */
  const siteOf = (fn: number, target: number | string): number => {
    const f = a.functions.get(fn);
    const va = typeof target === "number" ? target : image?.imports.find((i) => i.name === target)?.va;
    const at = va ? xrefs.get(va)?.find((x) => x.fn === fn && x.at >= 0)?.at : undefined;
    if (at !== undefined) return at;
    if (!f?.text || !f.lines) return -1;
    const needles: string[] = typeof target === "string" ? [target] : [];
    if (typeof target === "number") {
      const h = target.toString(16);
      needles.push("0x" + h, "_" + h);
      const s = strByAddr.get(target)?.s;
      if (s) needles.push(JSON.stringify(s).slice(1, -1));
    }
    const lines = f.text.split("\n");
    const i = lines.findIndex((l) => needles.some((n) => l.toLowerCase().includes(n.toLowerCase())));
    return i >= 0 ? f.lines[i]?.[0] ?? -1 : -1;
  };
  /** Open a function at the line that references `target`, not at its entry. */
  const openRef = (fn: number, target?: number | string) => openAt(fn, target === undefined ? -1 : siteOf(fn, target));
  const search = (q: string): PaletteItem[] => {
    const pre = /^([cafsix]):\s*(.*)$/i.exec(q.trim());
    const scope = pre ? pre[1].toLowerCase() : "";
    const n = (pre ? pre[2] : q.trim()).toLowerCase(), out: PaletteItem[] = [];
    if (!n) return out;
    const label = (ad: number) => fnLabel(ad, a.functions.get(ad)?.name);
    if (scope === "x") {
      const isAddr = /^(0x)?[0-9a-f]+$/.test(n), ad = isAddr ? parseInt(n, 16) : NaN;
      const seen = new Set<string>();
      const push = (fn: number, at: number, target: number | string) => {
        const k = fn + ":" + at;
        if (seen.has(k)) return;
        seen.add(k);
        out.push({ kind: "xref", title: label(fn), detail: at >= 0 ? "at " + hex(at) : "in decompiled code", run: () => openAt(fn, at >= 0 ? at : siteOf(fn, target)) });
      };
      if (isAddr) {
        for (const r of xrefs.get(ad) ?? []) push(r.fn, r.at, ad);
        // Like IDA: a function's references include everything that calls it.
        for (const fn of callers.get(ad) ?? []) push(fn, -1, ad);
        // An import's pointer slot: every caller of that API.
        const imp = image?.imports.find((i) => i.va === ad)?.name;
        for (const fn of imp ? importRefs.get(imp) ?? [] : []) push(fn, -1, imp!);
      } else {
        // A name: an API the code calls, such as SetLastError, whose callers are every function that names it.
        const bare = n.replace(/^[a-z0-9]+_/, ""), name = [...importRefs.keys()].find((k) => k.toLowerCase() === n || k.toLowerCase() === bare) ?? [...importRefs.keys()].find((k) => k.toLowerCase().replace(/[aw]$/, "") === bare);
        for (const fn of name ? importRefs.get(name) ?? [] : []) push(fn, -1, name!);
        for (const { ad: fn, f, c } of name ? [] : codeIndex) if (new RegExp("\\b" + n.replace(/[^\w]/g, "") + "\\b").test(c) && f.text) push(fn, -1, n);
      }
      return out.slice(0, 200);
    }
    // Decompiled C: the matching line, in the function that has it.
    const searchCode = (limit: number) => {
      if (n.length < 3) return;
      let hits = 0;
      for (const { ad, f, c } of codeIndex) {
        let from = 0, per = 0;
        while (per < 3 && hits < limit) {
          const k = c.indexOf(n, from);
          if (k < 0) break;
          const start = f.text!.lastIndexOf("\n", k) + 1, end = f.text!.indexOf("\n", k);
          const line = f.text!.slice(start, end < 0 ? undefined : end).trim();
          const lineNo = f.text!.slice(0, start).split("\n").length - 1;
          out.push({ kind: "code", title: line.length > 120 ? line.slice(0, 120) + "…" : line, detail: label(ad), run: () => openAt(ad, f.lines?.[lineNo]?.[0] ?? -1) });
          per++; hits++; from = (end < 0 ? c.length : end) + 1;
        }
        if (hits >= limit) break;
      }
    };
    const searchAsm = (limit: number) => {
      if (n.length < 3) return;
      let hits = 0;
      for (const [ad, f] of a.functions) {
        for (const [at, , text] of f.asm ?? []) {
          if (!text.toLowerCase().includes(n)) continue;
          out.push({ kind: "asm", title: text, detail: hex(at) + " · " + label(ad), run: () => openAt(ad, at) });
          if (++hits >= limit) return;
        }
      }
    };
    if (scope === "c") { searchCode(80); return out; }
    if (scope === "a") { searchAsm(80); return out; }
    if (/^(0x)?[0-9a-f]{3,16}$/.test(n) && !scope) {
      const ad = parseInt(n, 16), count = xrefs.get(ad)?.length ?? 0;
      out.push({ kind: "go to", title: hex(ad), detail: containment?.has(ad) || a.order.includes(ad) ? "code" : image?.vaToOff(ad) != null ? "data" : "not mapped", run: () => jump(ad) });
      if (count) out.push({ kind: "xrefs", title: "References to " + hex(ad), detail: count + (count === 1 ? " place" : " places"), run: () => showRefs(ad) });
    }
    if (scope === "s") {
      let c = 0;
      for (const x of a.strings) if (x.s.toLowerCase().includes(n)) { out.push({ kind: "string", title: x.s.length > 90 ? x.s.slice(0, 90) + "…" : x.s, detail: hex(x.a), run: () => openStringAt(x.a) }); if (++c >= 60) break; }
      return out;
    }
    if (scope === "f") {
      let c = 0;
      for (const ad of a.order) if (label(ad).toLowerCase().includes(n) || hex(ad).includes(n)) { out.push({ kind: "function", title: label(ad), detail: hex(ad), run: () => setSel(ad) }); if (++c >= 60) break; }
      return out;
    }
    if (scope === "i") {
      for (const i of image?.imports ?? []) if (i.name.toLowerCase().includes(n)) out.push({ kind: "import", title: i.name, detail: i.dll, run: () => openImport(i.name) });
      for (const e of image?.exports ?? []) if (e.name.toLowerCase().includes(n)) out.push({ kind: "export", title: e.name, detail: e.forward ? "→ " + e.forward : hex(e.va), run: () => (e.va ? jump(e.va) : (setImpQuery(e.name), setSel("imports"))) });
      return out.slice(0, 80);
    }
    let c = 0;
    for (const ad of a.order) {
      const label = fnLabel(ad, a.functions.get(ad)?.name);
      if (label.toLowerCase().includes(n) || hex(ad).includes(n)) { out.push({ kind: "function", title: label, detail: hex(ad), run: () => setSel(ad) }); if (++c >= 15) break; }
    }
    c = 0;
    for (const r of a.capa?.rules ?? []) {
      if (r.lib || !r.name.toLowerCase().includes(n)) continue;
      out.push({ kind: "capability", title: r.name, detail: r.addresses[0] !== undefined && r.scope !== "file" ? hex(r.addresses[0]) : r.scope, run: () => (r.addresses[0] !== undefined && r.scope !== "file" ? goto(r.addresses[0]) : setSel("capa")) });
      if (++c >= 10) break;
    }
    c = 0;
    for (const i of image?.imports ?? []) {
      if (!i.name.toLowerCase().includes(n)) continue;
      out.push({ kind: "import", title: i.name, detail: i.dll, run: () => openImport(i.name) });
      if (++c >= 10) break;
    }
    c = 0;
    for (const e of image?.exports ?? []) {
      if (!e.name.toLowerCase().includes(n)) continue;
      out.push({ kind: "export", title: e.name, detail: hex(e.va), run: () => jump(e.va) });
      if (++c >= 10) break;
    }
    c = 0;
    for (const x of a.strings) {
      if (!x.s.toLowerCase().includes(n)) continue;
      out.push({ kind: "string", title: x.s.length > 90 ? x.s.slice(0, 90) + "…" : x.s, detail: hex(x.a), run: () => openStringAt(x.a) });
      if (++c >= 15) break;
    }
    searchCode(12);
    return out;
  };
  if (embedded) embedded.searchRef.current = search;
  const reportInput = (): ReportInput => {
    const rules = (a.capa?.rules ?? []).filter((r) => !r.lib);
    const d = image?.details;
    const kinds = new Map<string, string[]>();
    for (const i of indicators) kinds.set(i.kind, [...(kinds.get(i.kind) ?? []), i.value]);
    return {
      fileName: a.demo?.name ?? a.fileName, size: a.size, sha256: d?.facts.find((f) => f.group === "Hashes" && f.label === "SHA-256")?.value ?? a.capa?.sample.sha256,
      format: a.capa?.format ?? image?.format, os: a.capa?.os, arch: a.capa?.arch ?? a.arch ?? undefined,
      toolchains: image ? guessToolchains(a, image) : [],
      stringsShown: a.strings.length, stringsTotal: a.stringsTotal,
      packed: a.packed ? (a.packed.packer ? `packed with ${a.packed.packer}` : "looks packed") : undefined,
      findings: d?.anomalies.map((x) => ({ severity: x.severity, text: x.text })) ?? [],
      signatures: d?.signatures.map((x) => `${x.kind}${x.digestMatches === true ? ", digest matches the file" : x.digestMatches === false ? ", digest does not match the file" : ""}`) ?? [],
      capabilities: rules.map((r) => ({
        name: r.name, tactic: r.attack[0]?.tactic ?? "", attack: [...new Set(r.attack.map((x) => x.id))], matches: r.count,
        functions: [...new Set(r.addresses.map((va) => ownerLabel(va)?.label).filter((x): x is string => !!x))],
      })),
      indicators: [...kinds].map(([kind, values]) => ({ kind, values })),
      sections: (image?.sections ?? []).map((x) => ({ name: x.name, address: hex(x.va), size: Math.max(x.size, x.vsize), perms: x.perms, entropy: x.entropy })),
      comments: notes.allComments().map((c) => ({ ...c, address: hex(c.address) })),
      starred: a.order.filter((ad) => isStarred(ad)).map((ad) => label(ad)),
    };
  };
  const base = () => (a.demo?.name ?? a.fileName).replace(/\.[^.]*$/, "") || "analysis";
  const saveReport = (kind: "md" | "html") => {
    const input = reportInput();
    if (kind === "md") download(base() + ".report.md", reportMarkdown(input), "text/markdown");
    else download(base() + ".report.html", reportHtml(input), "text/html");
  };
  const saveCsv = (kind: "functions" | "strings" | "imports") => {
    const text = kind === "functions"
      ? csv(["address", "name", "starred", "capabilities", "callers", "calls"], a.order.map((ad) => [hex(ad), label(ad), isStarred(ad) ? "yes" : "", (byFn.get(ad) ?? []).map((r) => r.name).join("; "), callers.get(ad)?.length ?? 0, callees.get(ad)?.length ?? 0]))
      : kind === "strings"
        ? csv(["address", "encoding", "string"], a.strings.map((x) => [hex(x.a), x.w ? "UTF-16" : "ASCII", x.s]))
        : csv(["kind", "library", "name", "address"], [...(image?.imports ?? []).map((x) => ["import", x.dll, x.name, hex(x.va)]), ...(image?.exports ?? []).map((x) => ["export", x.forward ?? "", x.name, hex(x.va)])]);
    download(`${base()}.${kind}.csv`, text, "text/csv");
  };
  const exportJson = () => {
    const doc = {
      file: a.fileName, size: a.size, sha256: a.capa?.sample.sha256, arch: a.arch,
      capabilities: (a.capa?.rules ?? []).filter((r) => !r.lib).map((r) => ({ name: r.name, namespace: r.namespace, scope: r.scope, addresses: r.addresses })),
      functions: a.order.map((ad) => ({ address: ad, name: fnLabel(ad, a.functions.get(ad)?.name), starred: isStarred(ad), capabilities: (byFn.get(ad) ?? []).map((r) => r.name), calls: callees.get(ad) ?? [] })),
      sections: image?.sections, imports: image?.imports, exports: image?.exports, details: image?.details,
      strings: a.strings,
      comments: notes.allComments(),
      indicators: indicators.map((i) => ({ kind: i.kind, value: i.value, addresses: i.strings.map((x) => x.a) })),
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(doc, (_, v) => v, 1)], { type: "application/json" }));
    const link = Object.assign(document.createElement("a"), { href: url, download: a.fileName + ".binfera.json" });
    link.click();
    URL.revokeObjectURL(url);
  };

  const counts = useMemo(() => ({
    caps: a.order.filter((ad) => byFn.has(ad)).length,
    stars: a.order.filter((ad) => isStarred(ad)).length,
    changed: a.order.filter((ad) => (embedded?.marks.get(ad) ?? "same") !== "same").length,
  }), [a.order, byFn, embedded?.marks, embedded?.tick, tick]);
  const triage = useMemo(() => triageProgress(a.order, library, (ad) => notes.isExamined(ad), (ad) => notes.isDocumented(ad)), [a.order, library, tick]);
  const fnTools = (
  <div className="tools fn-tools">
    <div className="tool-row">
      <input placeholder="Filter functions" aria-label="Filter functions" value={q} onChange={(e) => setQ(e.target.value)} />
      <select className="sortsel" value={fnSort} onChange={(e) => setFnSort(e.target.value as typeof fnSort)} title="Sort functions" aria-label="Sort functions">
        <option value="address">Address</option>
        <option value="importance">Importance</option>
        <option value="bottom_up">Bottom-up</option>
        <option value="caps">Capabilities</option>
        <option value="name">Name</option>
      </select>
    </div>
    <div className="chips" role="group" aria-label="Show functions">
      <button aria-pressed={!onlyCaps && !onlyStars && !onlyChanged} onClick={() => { setOnlyCaps(false); setOnlyStars(false); setOnlyChanged(false); }}>All <em>{total}</em></button>
      <button aria-pressed={onlyCaps} disabled={!counts.caps && !onlyCaps} title={`${counts.caps} functions have capability matches`} onClick={() => { setOnlyCaps(true); setOnlyStars(false); setOnlyChanged(false); }}>Matched <em>{counts.caps}</em></button>
      <button aria-pressed={onlyStars} disabled={!counts.stars && !onlyStars} title="Functions you starred" onClick={() => { setOnlyStars(true); setOnlyCaps(false); setOnlyChanged(false); }}>★ Starred <em>{counts.stars}</em></button>
      {libraryCount > 0 && <button aria-pressed={hideLibrary} title="Hide functions the signature matcher identified as library code" onClick={() => setHideLibrary(!hideLibrary)}>Hide library <em>{libraryCount}</em></button>}
      {embedded && <button aria-pressed={onlyChanged} title="Functions that differ from the other file" onClick={() => { setOnlyChanged(true); setOnlyCaps(false); setOnlyStars(false); }}>Changed <em>{counts.changed}</em></button>}
    </div>
    {triage.total > 0 && (
      <div className="fn-progress" title={`${triage.examined} of ${triage.total} functions opened, ${triage.documented} named or commented${libraryCount ? " (library functions not counted)" : ""}`}>
        <span>Examined <b>{triage.examined}</b>/{triage.total}</span>
        <span>Documented <b>{triage.documented}</b>/{triage.total}</span>
      </div>
    )}
  </div>
  );
  /** Desktop: one line per function, windowed so thousands of functions stay quick. Details are in the tooltip. */
  const fnListCompact = (
    <VirtualList listRef={fnListRef} items={list} rowHeight={(ad) => (byFn.has(ad) ? 44 : 28)} selected={typeof sel === "number" ? list.indexOf(sel) : -1}
      empty={<p className="empty">{total ? "No matches." : a.tooLarge ? "Too large for the browser." : a.decompileError ? "No functions to show." : a.done ? "No functions found." : a.loading ? "Downloading the analysis engine…" : "Recovering functions…"}</p>}
      render={(ad) => {
        const f = a.functions.get(ad), rules = byFn.get(ad), name = fnLabel(ad, f?.name), mark = embedded?.marks.get(ad);
        const why = importanceOf?.get(ad);
        const detail = [hex(ad), ...(why ? [`importance ${why.score}: ${why.capabilities} capabilities · ${why.imports} imports · ${why.strings} strings · ${why.callers} callers`] : []), library.has(ad) ? "library function" : "", `called by ${callers.get(ad)?.length ?? 0} · calls ${callees.get(ad)?.length ?? 0}`, ...(rules?.map((r) => r.name) ?? [])].filter(Boolean).join("\n");
        return (
          <button aria-current={sel === ad ? "true" : undefined} title={detail} className={"item compact" + (sel === ad ? " on" : "") + (rules ? " cap-item" : "")} data-ctx-fn={ad} onClick={() => { setCursor(ad); setSel(ad, true); }}>
            <span className="fn"><code>{mark && <i className={"cmp-dot d-" + mark} title={MARK_TITLE[mark]} />}{isStarred(ad) && <span className="star">★ </span>}{notes.aiName(ad) && <span className={"ai-mark " + notes.aiName(ad)} title={`Named by AI (${notes.aiName(ad)})`}>✦ </span>}{name}{exportOf(ad) && <span className="exp-tag">export</span>}</code>{rules && <small className="fn-caps">{rules.map((r) => r.name).join(" · ")}</small>}</span>
            {rules && <em className="pill">{rules.length}</em>}
            {!f && <span className="dot" title="pending" />}
            {f?.error && <span className="dot err" title="failed" />}
          </button>
        );
      }} />
  );
  const activeFilters = (onlyCaps ? 1 : 0) + (onlyStars ? 1 : 0) + (embedded && onlyChanged ? 1 : 0) + (hideLibrary && libraryCount ? 1 : 0) + (fnSort !== "address" ? 1 : 0);
  const fnToolsMobile = (
    <div className="m-search">
      <input type="search" enterKeyHint="search" placeholder={`Search ${total || ""} functions`} aria-label="Filter functions" value={q} onChange={(e) => setQ(e.target.value)} />
      <button className={"m-filter" + (activeFilters ? " on" : "")} onClick={() => setFiltersOpen(true)} aria-label="Filter and sort">
        <svg viewBox="0 0 24 24" aria-hidden><path d="M4 7h16M7 12h10M10 17h4" /></svg>
        {activeFilters > 0 && <em>{activeFilters}</em>}
      </button>
    </div>
  );
  /** Phone: the same list, windowed. A function with capability matches gets a second line; both heights are fixed so the window can be computed. */
  const fnList = (
    <VirtualList className="m-fnlist" items={list} rowHeight={(ad) => (byFn.has(ad) ? 72 : 52)} selected={typeof sel === "number" ? list.indexOf(sel) : -1}
      empty={<p className="empty">{total ? "No matches." : a.tooLarge ? "Too large for the browser." : a.decompileError ? "No functions to show." : a.done ? "No functions found." : a.loading ? "Downloading the analysis engine…" : "Recovering functions…"}</p>}
      render={(ad) => {
        const f = a.functions.get(ad), rules = byFn.get(ad), name = fnLabel(ad, f?.name), mark = embedded?.marks.get(ad);
        return (
          <button aria-current={sel === ad ? "true" : undefined} title={rules?.map((r) => r.name).join("\n")} className={"item" + (sel === ad ? " on" : "") + (rules ? " cap-item" : "")} data-ctx-fn={ad} onClick={() => { setCursor(ad); setSel(ad, true); }}>
            <span className="fn">
              <span className="m-fnline">
                <code>{mark && <i className={"cmp-dot d-" + mark} title={MARK_TITLE[mark]} />}{isStarred(ad) && <span className="star">★ </span>}{notes.aiName(ad) && <span className={"ai-mark " + notes.aiName(ad)} title={`Named by AI (${notes.aiName(ad)})`}>✦ </span>}{name}{exportOf(ad) && <span className="exp-tag">export</span>}</code>
                {!name.endsWith(ad.toString(16).padStart(8, "0")) && <small className="m-fnaddr">{hex(ad)}</small>}
              </span>
              {rules && <small className="fn-caps">{rules.map((r) => r.name).join(" · ")}</small>}
            </span>
            {rules && <em className="pill">{rules.length}</em>}
            {!f && <span className="dot" title="pending" />}
            {f?.error && <span className="dot err" title="failed" />}
          </button>
        );
      }} />
  );

  const label = (ad: number) => fnLabel(ad, a.functions.get(ad)?.name);
  // Globals the program fills with `GetProcAddress` and a literal name read as imports.
  const slotByVa = useMemo(() => new Map([...(image?.imports ?? []).filter((i) => i.va), ...resolvedSlots(a.resolved)].map((i) => [i.va, i])), [image, a.resolved]);
  // A call to an import stub (`jmp [slot]`) names the API it jumps to, as IDA does.
  const slot = (va: number) => slotByVa.get(va) ?? (image ? importThunk(image, va, slotByVa) : undefined);
  const xrefCount = (va: number) => xrefs.get(va)?.length ?? 0;
  const mode: "overview" | "code" | "data" = sel === "capa" ? "overview" : typeof sel === "number" ? "code" : "data";
  // Sections live in File on a desktop; a phone keeps its Hex tab.
  const chip = sel === "imports" ? "imports" : sel === "hex" ? (mobile ? "sections" : "file") : sel === "file" ? "file" : "strings";
  const findings = image?.details?.anomalies.filter((x) => x.severity === "warn").length ?? 0;
  const openCode = () => { const t = typeof sel === "number" ? sel : lastFn.current ?? a.order[0]; if (t !== undefined) setSel(t); };

  // Strings, imports and sections are one explorer; the bytes of whatever is selected sit beside it.
  const hexFull = image ? <HexView image={image} cursor={cursor} tick={cursorTick} selection={hexSel} onCursor={(va) => { setCursor(va); setHexSel(null); }} onSelect={setHexSel} strAt={strAtVa} owner={ownerLabel} xrefCount={xrefCount} onXrefs={showRefs}
    onOpenCode={(va) => { const o = ownerLabel(va); if (o) { setCursor(va); setSel(o.address); } }} /> : <p className="empty">The file is not loaded.</p>;
  const dataBody = (
    <div className={"data" + (mobile ? " m" : "")}>
      {mobile && <div className="dtabs" role="tablist">
        <button className={chip === "file" ? "on" : ""} onClick={() => setSel("file")}>File {findings > 0 && <em>{findings}</em>}</button>
        <button className={chip === "strings" ? "on" : ""} onClick={() => setSel("strings")}>Strings <em>{a.strings.length || (a.done ? 0 : "…")}</em></button>
        <button className={chip === "imports" ? "on" : ""} onClick={() => setSel("imports")}>Imports <em>{image ? image.imports.length + image.exports.length : "…"}</em></button>
        <button className={chip === "sections" ? "on" : ""} onClick={() => setSel("hex")}>Hex <em>{image?.sections.length ?? "…"}</em></button>
      </div>}
      {mobile && chip === "sections" ? <div className="data-hex">{hexFull}</div> : (
        <div className={mobile ? "data-single" : "data-split"}>
          <div className="data-list">
            {chip === "strings" && <StringsView a={a} indicators={indicators} onlyIndicators={strIndicators} setOnlyIndicators={setStrIndicators} refs={strRefs} onGoto={openRef} query={strQuery} setQuery={setStrQuery} onHex={showHex} onlyRefPref={strOnlyRef} setOnlyRef={setStrOnlyRef} mobile={mobile} onPeek={showHex} />}
            {chip === "imports" && <ImportsView a={a} refs={importRefs} label={label} onFn={openRef} onAddr={jump} onSymbol={openSymbol} query={impQuery} setQuery={setImpQuery} mobile={mobile} />}
            {chip === "file" && image && <FileView image={image} fileName={a.fileName} cursor={cursor} onPick={(va) => showHex(va)} onAnalyze={embedded ? undefined : onFile} />}
          </div>
          {!mobile && !a.order.length && <div className="data-hex">{image ? <HexView compact image={image} cursor={cursor} tick={cursorTick} selection={hexSel} onCursor={(va) => { setCursor(va); setHexSel(null); }} onSelect={setHexSel} strAt={strAtVa} owner={ownerLabel} xrefCount={xrefCount} onXrefs={showRefs}
            onOpenCode={(va) => { const o = ownerLabel(va); if (o) { setCursor(va); setSel(o.address); } }} /> : null}</div>}
        </div>
      )}
    </div>
  );

  /** The function a code address belongs to; the open one when several share the address. Data has none. */
  const codeOwner = (va: number) => {
    if (!containment?.has(va)) return undefined;
    const owners = ownersOf(a, containment, va);
    return typeof sel === "number" && owners.includes(sel) ? sel : owners[0];
  };
  /** A click in the listing: the header, references and call graph follow the function it lands in. */
  const listingCursor = (va: number) => {
    setCursor(va);
    const owner = codeOwner(va);
    if (owner !== undefined && owner !== sel) { setListingReq((n) => n + 1); setSel(owner, true); }
  };
  const listing = (marked: Set<number>, at = cursor, navigate?: (va: number) => void) => (
    <Listing arrows={!mobile} a={a} cursor={at} marked={marked} tick={navigate ? at ?? 0 : cursorTick} onCursor={navigate ?? listingCursor} label={label} resolve={resolve} strAt={strAtVa} textAt={textAtVa}
      isData={dataAt} onData={(va) => openData(va, navigate)} onOpenFn={navigate ?? setSel} onString={(s) => openString(s, navigate)} xrefCount={xrefCount} onXrefs={showRefs} exportName={exportOf} slot={slot} onImport={(n) => openImport(n, navigate)}
      fnInfo={(ad) => { const r = byFn.get(ad); return `; called by ${callers.get(ad)?.length ?? 0} · calls ${callees.get(ad)?.length ?? 0}${r ? " · " + r.map((x) => x.name).join(", ") : ""}`; }} />
  );
  const pickSection = (va: number) => showHex(va);
  // The overview's Sections cards open the File page at its section table, not at the top of the page.
  const [scrollTo, setScrollTo] = useState<"sections" | null>(null);
  const showSections = () => { setSel("hex"); if (!mobile) setScrollTo("sections"); };
  useEffect(() => {
    if (!scrollTo || sel !== "hex") return;
    root.current?.querySelector(`[data-part="${scrollTo}"]`)?.scrollIntoView({ block: "start" });
    setScrollTo(null);
  }, [scrollTo, sel]);
  const overview = (
    <div className="ov-container">
      <div className="ov">
        <Glance a={a} functions={total} caps={totalCaps} indicators={indicators.length} onCode={openCode} onData={(k) => (k === "hex" ? showSections() : setSel(k))} onIndicators={() => { setStrQuery(""); setStrIndicators(true); setSel("strings"); }} />
        {image && <div className="ov-wide">
          <FirstLook a={a} image={image} indicators={indicators} caps={totalCaps} onPick={pickSection} onFile={() => setSel("file")} onIndicators={() => { setStrQuery(""); setStrIndicators(true); setSel("strings"); }} onCaps={() => document.querySelector(".ov .caps")?.scrollIntoView({ behavior: "smooth", block: "start" })} />
          <FeatureMap a={a} image={image} onPick={pickSection} onFn={(ad) => setSel(ad)} />
        </div>}
        <div className="ov-body">
          {mobile && image && <FindingsCard compact a={a} onPick={pickSection} onDetails={() => setSel("file")} />}
          <div className="ov-main"><CapabilityView a={a} fileLevel={fileLevel} onGoto={goto} owner={ownerLabel} /></div>
          {image && !mobile && (
            <aside className="ov-context" aria-label="File context">
              <FindingsCard a={a} onPick={pickSection} onDetails={() => setSel("file")} />
              <LayoutCard image={image} onPick={pickSection} onSections={showSections} />
            </aside>)}
        </div>
      </div>
    </div>
  );
  const here = cursor === null ? null : (() => {
    const sec = image?.sectionAt(cursor), o = ownerLabel(cursor), off = image?.vaToOff(cursor);
    return { sec: sec?.name, fn: o ? `${o.label}${cursor > o.address ? " +0x" + (cursor - o.address).toString(16) : ""}` : undefined, off };
  })();

  /** The function whose Listing shows va: its owner, else the open or last function. None before recovery finds any. */
  const listingTarget = (va: number) => codeOwner(va) ?? (typeof sel === "number" ? sel : lastFn.current ?? a.order[0]);
  /** Tapping the strip: place the cursor, and show it in the listing unless the Data lists are open. */
  const navigate = (va: number) => {
    setCursor(va); setHexSel(null);
    // Data mode has no code pane for the cursor to land in: show the bytes, as a click on a section does.
    if (mode === "data") { showHex(va); return; }
    const t = listingTarget(va);
    if (t !== undefined) { const panes = panesOf(layout); if (!panes.includes("listing")) setLayout([...panes.slice(0, -1), "listing"].join("+")); setListingReq((n) => n + 1); setSel(t, true); } else setSel(lastData.current);
  };
  /** Following a string or data label out of the code: to the Listing, which has its neighbours and references. Back returns from it. */
  const showData = (va: number) => {
    if (!image || listingTarget(va) === undefined) { showHex(va); return; } // no Listing to show it in yet
    const newPlace = va !== cursorRef.current && (codeOwner(va) ?? sel) === sel;
    navigate(va);
    if (newPlace) push(loc);
  };
  /** The right-click menu for whatever is under the pointer: a function, an instruction, a string, bytes. Null leaves the browser's own menu. */
  const contextItems = (target: Element): MenuEntry[] | null => {
    const copy = (text: string) => () => { void copyText(text).then(() => toast("Copied")); };
    const selected = (getSelection()?.toString() ?? "").trim();
    const items: MenuEntry[] = [];
    const sep = () => { if (items.length && items[items.length - 1] !== "separator") items.push("separator"); };
    const commentItem = (ad: number): MenuEntry => ({ label: notes.commentAt(ad) ? "Edit comment…" : "Add comment…", hint: ";", onClick: () => editComment(ad, target) });
    const fnItems = (ad: number) => {
      items.push(
        { label: "Open function", onClick: () => { setCursor(ad); setSel(ad, true); } },
        commentItem(ad),
        { label: "Rename…", hint: "N", onClick: () => { setSel(ad); setTimeout(askRename, 0); } },
        { label: isStarred(ad) ? "Remove star" : "Star", hint: typeof sel === "number" && sel === ad ? "S" : undefined, onClick: () => toggleStar(ad) },
      );
      sep();
      items.push({ label: "Copy name", onClick: copy(label(ad)) }, { label: "Copy address", onClick: copy(hex(ad)) });
      sep();
      items.push({ label: "Show references", onClick: () => showRefs(ad) }, { label: "Show bytes in Hex", onClick: () => showHex(ad) });
    };
    const addrItems = (va: number, more: MenuEntry[] = []) => {
      const owner = ownerLabel(va);
      items.push(commentItem(va), ...more);
      if (more.length) sep();
      items.push({ label: "Copy address", onClick: copy(hex(va)) });
      const off = image?.vaToOff(va);
      if (off != null) items.push({ label: "Copy file offset", onClick: copy(hex(off)) });
      sep();
      items.push({ label: "Show references", onClick: () => showRefs(va) }, { label: "Show bytes in Hex", onClick: () => showHex(va) });
      if (owner && owner.address !== sel) items.push({ label: `Open ${owner.label}`, onClick: () => { setCursor(va); setSel(owner.address, true); } });
    };
    const byteEl = target.closest<HTMLElement>("[data-o]");
    const strEl = target.closest<HTMLElement>("[data-ctx-str]");
    const fnEl = target.closest<HTMLElement>("[data-ctx-fn],[data-fn]");
    const varEl = target.closest<HTMLElement>("[data-id]");
    const insnEl = target.closest<HTMLElement>("[data-addr]");
    const rowEl = target.closest<HTMLElement>("[data-ctx-va]");
    if (byteEl && image) {
      const off = Number(byteEl.dataset.o), va = image.offToVa(off);
      const rowStart = off - (off % 16), row = image.bytes.subarray(rowStart, Math.min(image.bytes.length, rowStart + 16));
      const selOff = hexSel ? image.vaToOff(hexSel.va) : null;
      if (hexSel && selOff !== null && off >= selOff && off < selOff + hexSel.len) {
        const sb = image.bytes.subarray(selOff, selOff + hexSel.len);
        items.push(
          { label: "Copy selection as hex", onClick: copy(hexOf(sb)) },
          { label: "Copy selection as C array", onClick: copy(cArray(sb)) },
          { label: "Copy selection as text", onClick: copy(asText(sb)) },
        );
        sep();
      }
      items.push({ label: "Copy this row as hex", onClick: copy(hexOf(row)) }, { label: "Copy byte", onClick: copy(image.bytes[off].toString(16).padStart(2, "0")) }, { label: "Copy file offset", onClick: copy(hex(off)) });
      if (va !== null) { sep(); items.push({ label: "Copy address", onClick: copy(hex(va)) }, { label: "Show references", onClick: () => showRefs(va) }); const o = ownerLabel(va); if (o) items.push({ label: `Open ${o.label}`, onClick: () => { setCursor(va); setSel(o.address, true); } }); }
    } else if (strEl) {
      const va = Number(strEl.dataset.ctxStr), len = Number(strEl.dataset.ctxLen), text = strEl.dataset.ctxText ?? "";
      items.push({ label: "Copy string", onClick: copy(text) }, { label: "Copy address", onClick: copy(hex(va)) });
      sep();
      items.push({ label: "Show bytes in Hex", onClick: () => showHex(va, len) }, { label: "Show references", onClick: () => showRefs(va) });
    } else if (varEl && typeof sel === "number" && !fnEl && isLocalName(varEl.dataset.id ?? "", codeVocabulary(a.functions.get(sel)?.frame, () => false, a.functions.get(sel)?.text))) {
      items.push({ label: "Rename variable…", hint: "N", onClick: () => setTimeout(askRename, 0) }, { label: "Show references", hint: "X", onClick: () => setTimeout(askXrefs, 0) }, { label: "Copy name", onClick: copy(varEl.dataset.id ?? "") });
    } else if (fnEl) {
      fnItems(Number(fnEl.dataset.ctxFn ?? fnEl.dataset.fn));
    } else if (insnEl) {
      const va = Number(insnEl.dataset.addr), o = ownersOf(a, containment, va)[0];
      const row = o === undefined ? undefined : a.functions.get(o)?.asm?.find((r) => r[0] === va);
      addrItems(va, row ? [{ label: "Copy instruction", onClick: copy(row[2]) }, { label: "Copy instruction bytes", onClick: copy(row[1]) }] : []);
    } else if (rowEl) {
      addrItems(Number(rowEl.dataset.ctxVa));
    }
    if (selected) { sep(); items.push({ label: "Copy selected text", hint: isMac ? "⌘C" : "Ctrl+C", onClick: copy(selected) }); }
    while (items[items.length - 1] === "separator") items.pop();
    return items.length ? items : null;
  };
  const onContext = (e: React.MouseEvent) => {
    const t = e.target as Element;
    if (t.closest("input, textarea, select, [contenteditable=true]")) return;
    const items = contextItems(t);
    if (!items) return;
    e.preventDefault();
    setCtx({ x: e.clientX, y: e.clientY, items });
  };
  /** The keyboard's way in: the Menu key or Shift+F10 opens the menu for the focused row, or the cursor. */
  const onContextKey = (e: React.KeyboardEvent) => {
    if (!(e.key === "ContextMenu" || (e.shiftKey && e.key === "F10"))) return;
    const t = e.target as Element;
    if (t.closest("input, textarea, select")) return;
    const at = t.closest("[data-ctx-fn],[data-fn],[data-ctx-str],[data-addr],[data-ctx-va]") ?? t;
    const items = contextItems(at);
    if (!items) return;
    e.preventDefault();
    const r = at.getBoundingClientRect();
    setCtx({ x: r.left + Math.min(40, r.width / 2), y: r.bottom, items });
  };

  const againMenu: MenuItem[] = onAnalyzeAgain ? [{ label: "Analyze again", onClick: onAnalyzeAgain }] : [];
  const goMenu: MenuItem[] = [
    { label: "Undo", onClick: undo, disabled: !notes.canUndo() },
    { label: "Redo", onClick: redo, disabled: !notes.canRedo() },
    ...againMenu,
    ...(onCompare && !embedded ? [{ label: "Compare with…", onClick: onCompare }] : []),
    { label: "Back", onClick: back, disabled: !canBack },
    { label: "Forward", onClick: forward, disabled: !canForward },
    { label: "Locate in file…", onClick: () => setLocateOpen(true), disabled: !image },
    { label: "Report (Markdown)", onClick: () => saveReport("md"), disabled: !a.settled },
    { label: "Report (web page)", onClick: () => saveReport("html"), disabled: !a.settled },
    { label: "Functions (CSV)", onClick: () => saveCsv("functions"), disabled: !a.settled },
    { label: "Strings (CSV)", onClick: () => saveCsv("strings"), disabled: !a.settled },
    { label: "All data (JSON)", onClick: exportJson, disabled: !a.settled },
    { label: document.documentElement.dataset.theme === "dark" || (!storedTheme() && matchMedia("(prefers-color-scheme: dark)").matches) ? "Light mode" : "Dark mode", onClick: () => chooseTheme(document.documentElement.dataset.theme === "dark" || (!storedTheme() && matchMedia("(prefers-color-scheme: dark)").matches) ? "light" : "dark") },
  ];
  const strip = (
    <div className="m-strip">
      {image && image.sections.length > 0 && <Navigator compact a={a} position={navPos} range={navRange} onNavigate={navigate} />}
      <div className="m-cursor">
        {here ? <><code>{hex(cursor!)}</code>{here.sec && <span>{here.sec}</span>}{here.fn && <span>{here.fn}</span>}</> : <span>Tap the strip to place the cursor</span>}
      </div>
    </div>
  );
  const fnNote = typeof sel === "number" ? embedded?.note(sel) : null;
  const locatePane = (va: number, current: PanePlace): PanePlace => {
    const owners = ownersOf(a, containment, va);
    return { address: owners.includes(current.address) ? current.address : owners[0] ?? current.address, cursor: va };
  };
  /** Names where an address is when it is not inside the function a pane shows, so the pane does not claim it is. */
  const outsideOf = (fn: number, va: number): string | null => {
    const owners = ownersOf(a, containment, va);
    if (owners.includes(fn)) return null;
    if (owners.length) return `in ${fnLabel(owners[0], a.functions.get(owners[0])?.name)}`;
    return image?.sectionAt(va)?.name ? `in ${image.sectionAt(va)!.name}, outside any function` : "outside any function";
  };
  const navigatePanes = (va: number, fn?: number) => {
    if (typeof sel !== "number") return;
    const target = fn ?? locatePane(va, { address: sel, cursor }).address;
    setCursor(va);
    if (target !== sel) setSel(target, true);
  };
  const functionProps = (at: number, here: number | null, nav?: (va: number) => void): FnViewProps => ({
    a, address: at, cursor: here, rules: byFn.get(at) ?? [], resolve, onGoto: nav ?? setSel, mobile,
    onBack: () => { if (canBack) back(); else push({ ...loc, tab: "functions", detail: false }); },
    strings: (fnStrings.get(at) ?? []).map((v) => strByAddr.get(v)!).filter(Boolean),
    onString: (s) => openString(s, nav),
    callers: callers.get(at), callees: callees.get(at), callersOf: (ad) => callers.get(ad), calleesOf: (ad) => callees.get(ad), apisOf: (ad) => apisByFn.get(ad), xrefsReady: a.settled,
    strAt: strAtVa, textAt: textAtVa, onCursor: nav ?? setCursor, isData: dataAt, onData: (va) => openData(va, nav), slot,
    onImport: (n) => openImport(n, nav),
    layout, setLayout, listing: (marked) => listing(marked, here, nav), listingReq, listingSeen, strip, menuItems: goMenu, onSearch: () => setPalette(""),
    callGraph: (onOpen) => <CallGraph order={a.order} callees={callees} callers={callers} center={at} setCenter={nav ?? setSel} label={label} caps={(ad) => (byFn.get(ad) ?? []).map((r) => r.name)} onOpen={onOpen} ready={a.settled} />,
    onCode: nav ?? navigate, capsOf: (ad) => (byFn.get(ad) ?? []).map((r) => r.name),
    onHex: (va) => { setCursor(va); setSel("hex"); }, onComment: () => editComment(here ?? at), onNotesChange: bump,
    starred: isStarred(at), onStar: () => toggleStar(at),
    onRename: (n) => { const name = n === (a.functions.get(at)?.name ?? "") ? "" : n; notes.rename(at, name); embedded?.onRenamed(at, name); bump(); },
    renameReq, xrefReq, onXrefs: showRefs,
    onRenameAt: (ad, n) => { const name = n === (a.functions.get(ad)?.name ?? "") ? "" : n; notes.rename(ad, name); embedded?.onRenamed(ad, name); bump(); },
    listOpen: listPref, onToggleList: () => setListPref(!listPref), railOpen, onToggleRail: toggleRail, onToggleSplit: toggleSplit,
  });
  const renderPane: PaneRenderer = (view, here, nav, focused, asm) => {
    if (view === "hex") return image ? <HexView compact image={image} cursor={here.cursor} tick={here.cursor ?? 0} selection={hexSel} onCursor={nav} onSelect={setHexSel} strAt={strAtVa} owner={ownerLabel} xrefCount={xrefCount} onXrefs={showRefs} onOpenCode={nav} /> : <p className="empty">The file is not loaded.</p>;
    if (view === "strings" || view === "imports") return <PaneData view={view} a={a} cursor={here.cursor} strRefs={strRefs} importRefs={importRefs} label={label} indicators={indicators} navigate={nav} onBytes={(va, len) => showHex(va, len)} siteOf={siteOf} />;
    return <FunctionView {...functionProps(here.address, here.cursor, nav)} {...asm} mobile={false} paneView={view} shortcutsEnabled={focused} />;
  };
  const fnView = typeof sel === "number" && <FunctionView {...functionProps(sel, cursor)} renderPane={renderPane} locate={locatePane} outside={outsideOf} onPaneNavigate={navigatePanes} />;

  const retryCount = [...a.functions.values()].filter((f) => f.retry_pending).length;
  const status = a.tooLarge ? "Too large to analyze in the browser" : a.decompileError ? "Decompiler unavailable for this file" : a.done ? `${total} functions · ${totalCaps} capabilities in ${counts.caps} of them` : a.settled ? `${total.toLocaleString()} functions${NATIVE && retryCount ? ` · retrying ${retryCount} large functions` : " · matching capabilities"}` : a.loading ? a.loading.label : [!a.capa && !a.capaError && !a.capaTooLarge && "Matching capabilities", total ? `Decompiling ${done}/${total}` : "Recovering functions"].filter(Boolean).join(" · ");
  // Announced to screen readers only when the phase changes, not for every function.
  const phase = a.tooLarge || a.decompileError || a.done ? status : a.loading ? "Getting ready" : "Analyzing";
  useEffect(() => {
    if (embedded) return;
    if (active) document.title = (typeof sel === "number" ? label(sel) + " · " : "") + displayName + " · binfera";
    return () => { document.title = HOME_TITLE; };
  }, [active, sel, displayName, tick, a.functions]);
  // On a function page the tab bar slides away while reading down and returns on the way up, so code gets the whole screen.
  useEffect(() => {
    if (!mobile || !detail) { setChromeHidden(false); return; }
    const last = new WeakMap<Element, number>();
    const onScroll = (e: Event) => {
      const el = e.target as Element;
      if (!(el instanceof Element) || !el.closest(".m-body")) return;
      const y = el.scrollTop, prev = last.get(el) ?? y;
      last.set(el, y);
      if (Math.abs(y - prev) < 8 && y > 0) return;
      setChromeHidden(y > 120 && y > prev);
    };
    document.addEventListener("scroll", onScroll, { capture: true, passive: true });
    return () => { document.removeEventListener("scroll", onScroll, true); setChromeHidden(false); };
  }, [mobile, detail, sel]);
  const progressBar = !a.done && <div className="bar"><i style={{ width: `${Math.max(4, (a.loading ? a.loading.fraction ?? 0.04 : progress) * 100)}%` }} /></div>;

  const commentBox = commentEdit && <CommentEditor key={commentEdit.address} {...commentEdit} mobile={mobile} text={notes.commentAt(commentEdit.address) ?? ""}
    onSave={(text) => { notes.setComment(commentEdit.address, text); bump(); setCommentEdit(null); }} onClose={() => setCommentEdit(null)} />;

  if (mobile) {
    // The tab bar stays visible on a function page; a tab there leaves the page.
    const showTab = (t: Tab) => {
      setAgentView(false);
      const next: Loc = { sel: t === "capa" ? "capa" : t === "data" ? lastData.current : sel, tab: t, detail: false };
      if (next.sel !== sel || next.tab !== tab || next.detail !== detail) push(next);
    };
    // A function page belongs to Functions, whichever list it was opened from.
    const shown: Tab | "agent" = agentView ? "agent" : detail ? "functions" : tab;
    return (
      <div ref={root} className={"app mobile" + (chromeHidden ? " chrome-hidden" : "")}>
        {!detail && (
          <header className="m-head">
            <button className="brand sm" onClick={onNew} title="Home; this file stays open" aria-label="binfera home"><Wordmark /></button>
            <div className="file">
              <b title={a.fileName}>{displayName}</b>
              <span>{status}</span>
            </div>
            <button className="m-icon" aria-label="Search" onClick={() => setPalette("")}>
              <svg viewBox="0 0 24 24" aria-hidden><circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" /></svg>
            </button>
            <MoreMenu items={[...goMenu, { label: "Keyboard shortcuts", onClick: () => setHelp(true) }, { label: "Analyze another file", onClick: onNew }]} />
            {progressBar}
          </header>
        )}
        <ShellcodeNotice a={a} onChange={onShellcodeChange} />
                <div className="m-main" role={!agentView && detail ? "main" : undefined}>
          {agent && project && agentSha && agentMounted && (
            // Kept mounted while another tab shows, so a conversation and a run in progress survive it.
            <div className="m-agent" hidden={!agentView}>
              <AgentDock key={agentSha} notes={notes} tick={tick} symbols={() => a.order.map((ad) => ({ address: ad, name: label(ad) }))} onBusy={setAgentBusy} onClose={() => setAgentView(false)}
                onOpen={(ad) => { setAgentView(false); jump(ad); }}
                context={{ sha: agentSha, name: a.fileName, address: typeof sel === "number" ? sel : null, functionName: typeof sel === "number" ? label(sel) : null }} />
            </div>
          )}
          {!agentView && detail && fnNote}
          {!agentView && detail && fnView}
          {!agentView && !detail && tab === "functions" && <div className="m-list">{fnToolsMobile}{fnList}</div>}
          {!agentView && !detail && tab === "capa" && <main className="pane">{overview}</main>}
          {!agentView && !detail && tab === "data" && <main className="pane">{dataBody}</main>}
        </div>
        <nav className="tabbar">
          <button className={shown === "capa" ? "on" : ""} onClick={() => showTab("capa")}>
            <svg viewBox="0 0 24 24" aria-hidden><path d="M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6l8-3z" /></svg>
            <span>Overview</span><em>{a.capa ? totalCaps : "…"}</em>
          </button>
          <button className={shown === "functions" ? "on" : ""} onClick={() => showTab("functions")}>
            <svg viewBox="0 0 24 24" aria-hidden><path d="M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16" /></svg>
            <span>Code</span><em>{total || "…"}</em>
          </button>
          <button className={shown === "data" ? "on" : ""} onClick={() => showTab("data")}>
            <svg viewBox="0 0 24 24" aria-hidden><path d="M4 7V5h16v2M12 5v14M9 19h6" /></svg>
            <span>Data</span><em>{a.strings.length || (a.done ? 0 : "…")}</em>
          </button>
          {agent && project && agentSha && (
            <button className={shown === "agent" ? "on" : ""} onClick={() => setAgentView(true)}>
              <svg viewBox="0 0 24 24" aria-hidden><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3z" /></svg>
              <span>Agent</span>{agentBusy && <i className="agent-dot" role="status" aria-label="The agent is working" />}
            </button>
          )}
        </nav>
        {locateOpen && (
          <Sheet title="Locate in file" onClose={() => setLocateOpen(false)}>
            <div onClick={() => setLocateOpen(false)}>{strip}</div>
          </Sheet>
        )}
        {filtersOpen && (
          <Sheet title="Filter and sort" onClose={() => setFiltersOpen(false)}>
            <div className="sheet-form">
              <label><input type="checkbox" checked={onlyCaps} onChange={(e) => setOnlyCaps(e.target.checked)} /> Only functions with capabilities</label>
              <label><input type="checkbox" checked={onlyStars} onChange={(e) => setOnlyStars(e.target.checked)} /> Only starred functions</label>
              {libraryCount > 0 && <label><input type="checkbox" checked={hideLibrary} onChange={(e) => setHideLibrary(e.target.checked)} /> Hide library functions ({libraryCount})</label>}
              {embedded && <label><input type="checkbox" checked={onlyChanged} onChange={(e) => setOnlyChanged(e.target.checked)} /> Only changed functions</label>}
              <fieldset className="sheet-radios">
                <legend>Sort by</legend>
                {(["address", "importance", "bottom_up", "caps", "name"] as const).map((k) => (
                  <label key={k}><input type="radio" name="fn-sort" checked={fnSort === k} onChange={() => setFnSort(k)} /><span>{SORT_LABELS[k]}<small>{SORT_HINTS[k]}</small></span></label>
                ))}
              </fieldset>
              <button className="sheet-done" onClick={() => setFiltersOpen(false)}>Show {list.length} {list.length === 1 ? "function" : "functions"}</button>
            </div>
          </Sheet>
        )}
        {!embedded && <ToastHost />}
        {palette !== null && <Palette initial={palette} search={embedded?.search ?? search} onClose={() => setPalette(null)} />}
        {commentBox}
        {help && <Shortcuts extra={embedded?.keys} onClose={() => setHelp(false)} />}
        <div className="sr-only" role="status">{phase}</div>
      </div>
    );
  }

  return (
    <div ref={root} className="app" onContextMenu={onContext} onKeyDown={onContextKey} {...(embedded ? {} : {
      onDragOver: (e: React.DragEvent) => {
        if (!e.dataTransfer.types.includes("Files")) { setDragging(false); return; }
        e.preventDefault(); setDragging(true);
      },
      onDragLeave: (e: React.DragEvent) => { if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragging(false); },
      onDrop: (e: React.DragEvent) => { setDragging(false); if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) onFile(f); },
    })}>
      <header className="topbar">
        {!embedded && <button className="brand sm" onClick={onNew} title="Home; this file stays open" aria-label="binfera home"><Wordmark /></button>}
        <div className="navbtns">
          <button className="ghost" onClick={back} disabled={!canBack} title={`Back (${isMac ? "⌥" : "Alt"}+←)`} aria-label="Back">←</button>
          <button className="ghost" onClick={forward} disabled={!canForward} title={`Forward (${isMac ? "⌥" : "Alt"}+→)`} aria-label="Forward">→</button>
        </div>
        <button className="searchbox" onClick={() => setPalette("")} title={`Search and go to address (${searchKey} or /)`}>
          <svg viewBox="0 0 24 24" aria-hidden><circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" /></svg>
          <span>{embedded ? "Search both files…" : "Search functions, strings, code, addresses…"}</span><kbd>{searchKey}</kbd>
        </button>
        {!compact && <button type="button" className="filechip" title={`Open file view: ${a.fileName}`} aria-label={`Open file view for ${displayName}`} onClick={() => setSel("file")}>
          <b>{displayName}</b>
          <span>{bytes(a.size)}{a.capa && ` · ${a.capa.format.toUpperCase()} ${a.capa.arch}`}</span>
        </button>}
        {!compact && <ReportMenu disabled={!a.settled} groups={[
          { title: "Report", items: [{ label: "Summary report", note: "Markdown", onClick: () => saveReport("md") }, { label: "Summary report", note: "Web page", onClick: () => saveReport("html") }] },
          { title: "Tables", items: [{ label: "Functions", note: "CSV", onClick: () => saveCsv("functions") }, { label: "Strings", note: "CSV", onClick: () => saveCsv("strings") }, { label: "Imports and exports", note: "CSV", onClick: () => saveCsv("imports") }] },
          ...(onAnalyzeAgain ? [{ title: "Analysis", items: againMenu }] : []),
          { title: "Everything", items: [{ label: "All analysis data", note: "JSON", onClick: exportJson }] },
        ]} />}
        {!compact && <ThemeToggle />}
        {!embedded && onCompare && <button className="ghost" onClick={onCompare} title="Compare this file with another: choose the second file next">Compare…</button>}
        {!embedded && <button className="ghost" onClick={onNew} title="Open another file; this one stays available">New</button>}
        {agent && project && agentSha && (
          <button className={"ghost agent-toggle" + (agentOpen ? " on" : "")} aria-pressed={agentOpen} onClick={() => setAgentOpen(!agentOpen)} title={`Work with your agent on this file (${isMac ? "⌘" : "Ctrl "}J)`}>
            <svg viewBox="0 0 24 24" aria-hidden><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3zM18.5 15l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z" /></svg>
            Agent{agentBusy && <i className="agent-dot" role="status" aria-label="The agent is working" />}
          </button>
        )}
        {progressBar}
      </header>

      <ShellcodeNotice a={a} onChange={onShellcodeChange} />
      <div className="shell">
        <nav className="modenav" aria-label="Views">
          <button className={mode === "overview" ? "on" : ""} aria-current={mode === "overview" ? "page" : undefined} onClick={() => setSel("capa")}>
            <svg viewBox="0 0 24 24" aria-hidden><rect x="4" y="4" width="7" height="7" rx="1.5" /><rect x="13" y="4" width="7" height="7" rx="1.5" /><rect x="4" y="13" width="7" height="7" rx="1.5" /><rect x="13" y="13" width="7" height="7" rx="1.5" /></svg>
            <span>Overview</span>
          </button>
          <button className={mode === "code" ? "on" : ""} aria-current={mode === "code" ? "page" : undefined} onClick={() => openCode()}>
            <svg viewBox="0 0 24 24" aria-hidden><path d="M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16" /></svg>
            <span>Code</span>
          </button>
          <button className={mode === "data" ? "on" : ""} aria-current={mode === "data" ? "page" : undefined} onClick={() => setSel(lastData.current)}>
            <svg viewBox="0 0 24 24" aria-hidden><ellipse cx="12" cy="6" rx="7" ry="3" /><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" /></svg>
            <span>Data</span>
          </button>
        </nav>
        <div className="main-col">
          {mode !== "overview" && image && image.sections.length > 0 && (
            <div className="nav-row">
              {!(focus && mode === "code") && <span className="nav-label" title="The whole file, left to right. Click to jump; the red mark is the cursor.">File map</span>}
              {!(focus && mode === "code") && <Navigator a={a} position={navPos} range={navRange} onNavigate={navigate} />}
              <details className="nav-key">
                <summary>Legend</summary>
                <div className="nav-legend">
                  <span><i style={{ background: "var(--c-fn)" }} />code</span>
                  <span><i style={{ background: "color-mix(in srgb, var(--c-fn) 22%, var(--panel))" }} />not disassembled</span>
                  <span><i style={{ background: "var(--c-str)" }} />strings</span>
                  <span><i style={{ background: "var(--c-num)" }} />imports</span>
                  <span><i style={{ background: "var(--line)" }} />data</span>
                </div>
              </details>
            </div>
          )}
          <div className={"body " + (mode === "code" ? "has-fns" : mode === "data" ? "has-cats" : "wide")}
            style={mode === "code" ? { gridTemplateColumns: listPref && !focus ? `${listShownWidth}px minmax(0, 1fr)` : "minmax(0, 1fr)" } : undefined}>
            {mode === "code" && listPref && !focus && (
              <aside aria-label="Functions">
                {fnTools}
                {fnListCompact}
              </aside>
            )}
            {mode === "code" && listPref && !focus && <Splitter label="Resize the function list" value={listShownWidth} min={200} max={560} onChange={setListWidth} style={{ left: listShownWidth }} />}
            {mode === "data" && (
              <aside className="cats">
                <h3>Data</h3>
                <button aria-current={chip === "file" ? "true" : undefined} className={"item" + (chip === "file" ? " on" : "")} onClick={() => setSel("file")}><span>File</span>{findings > 0 && <em>{findings}</em>}</button>
                <button aria-current={chip === "strings" ? "true" : undefined} className={"item" + (chip === "strings" ? " on" : "")} onClick={() => setSel("strings")}><span>Strings</span><em>{a.strings.length || (a.done ? 0 : "…")}</em></button>
                <button aria-current={chip === "imports" ? "true" : undefined} className={"item" + (chip === "imports" ? " on" : "")} onClick={() => setSel("imports")}><span>Imports &amp; exports</span><em>{image ? image.imports.length + image.exports.length : "…"}</em></button>
              </aside>
            )}
            <main className="pane">{mode === "overview" ? overview : mode === "data" ? dataBody : fnView ? <>{fnNote}{fnView}</> : <p className="empty">No functions to show.</p>}</main>
          </div>
        </div>
        {agent && project && agentSha && agentMounted && (
          // Kept mounted while closed, so the conversation and a run in progress survive hiding the panel.
          <aside className={"agent-dock" + (overlayDock ? " overlay" : "")} hidden={!agentOpen || focus} style={{ width: Math.min(agentWidth, overlayDock ? 520 : 720) }} aria-label="Agent">
            <Splitter label="Resize the agent panel" value={agentWidth} min={300} max={720} invert onChange={setAgentWidth} style={{ left: 0 }} />
            <AgentDock key={agentSha} notes={notes} tick={tick} symbols={() => a.order.map((ad) => ({ address: ad, name: label(ad) }))} onBusy={setAgentBusy} onClose={() => setAgentOpen(false)} onOpen={jump}
              context={{ sha: agentSha, name: a.fileName, address: typeof sel === "number" ? sel : null, functionName: typeof sel === "number" ? label(sel) : null }} />
          </aside>
        )}
        {agent && project && agentSha && !agentOpen && !focus && (
          <button className="edge-tab agent-tab" onClick={() => setAgentOpen(true)} title={`Open the agent (${isMac ? "⌘" : "Ctrl "}J)`}><span>Agent ✦</span>{agentBusy && <i className="agent-dot" role="status" aria-label="The agent is working" />}</button>
        )}
        {focus && <button className="focus-exit" onClick={() => setFocus(false)} title="Leave focus mode (F or Esc)">Exit focus</button>}
      </div>
      <footer className="statusbar">
        <span className="sb-status">{a.done ? "●" : "◌"} {status}</span>
        <span className="sb-cursor">
          {here ? (
            <>
              <code>{hex(cursor!)}</code>
              {here.sec && <span>{here.sec}</span>}
              {here.fn && <span>{here.fn}</span>}
              {here.off != null && <span>file offset {hex(here.off)}</span>}
            </>
          ) : <span>No cursor yet</span>}
          {!embedded && <BuildVersion />}
          <button className="sb-help" onClick={() => setHelp(true)} aria-label="Keyboard shortcuts" title="Keyboard shortcuts (?)">?</button>
        </span>
      </footer>
      <div className="sr-only" role="status">{phase}</div>
      {dragging && <div className="overlay">Drop to analyze a new binary</div>}
      {!embedded && <ToastHost />}
      {palette !== null && <Palette initial={palette} search={embedded?.search ?? search} onClose={() => setPalette(null)} />}
      {commentBox}
      {help && <Shortcuts extra={embedded?.keys} onClose={() => setHelp(false)} />}
      {ctx && <ContextMenu x={ctx.x} y={ctx.y} items={ctx.items} onClose={() => setCtx(null)} />}
    </div>
  );
}
