import type { Analysis, CapaRule, StringEntry } from "../types";
import type { FunctionOrigin } from "../familyOrigin";
import { OriginBadge } from "./CodeOrigin";
import { hex } from "../workspace/labels";
import { useEffect, useMemo, useReducer, useRef, useState } from "react";
import GraphView from "../GraphView";
import { CallTree } from "./CallTree";
import { linesWithSetup } from "../graph";
import { useNotes } from "../names";
import Asm, { type AsmHandle } from "../Asm";
import { cachedFunctionArrows } from "../BranchArrows";
import { applyNames, Code, importKey } from "../highlight";
import { fileHandleOrigins } from "../fileHandleOrigins";
import { resolvedSlots } from "../resolved";
import MoreMenu, { type MenuItem } from "../MoreMenu";
import { panesOf, VIEW_NAMES, type CodeView, type Layout } from "../workspace/location";
import { revealIn, Splitter, useMedia, useStored } from "../workspace/panels";
import CodePanes, { type PanePlace, type PaneRenderer } from "../workspace/CodePanes";
import { PackedNotice } from "./AnalysisStatus";
import { FunctionWarnings } from "./FunctionWarnings";
import { NATIVE } from "../engine/assets";
import { StackFrame } from "./StackFrame";
import { EmulatePanel } from "./EmulatePanel";
import { instructionNotes } from "../annotations";
import { codeVocabulary, isLocalName } from "../highlight";

function DecompileNotice({ a, address }: { a: Analysis; address: number }) {
  const [busy, setBusy] = useState(false);
  const f = a.functions.get(address);
  if (!f?.error && !f?.retry_pending) return null;
  const limited = /deadline exceeded|work limit exceeded/.test(f.error ?? "");
  return <div className="notice error">
    {f.retry_pending && NATIVE && !a.done ? <p>This function is large. Still trying with a longer limit…</p>
      : <p>{limited ? "This function is too large to decompile within the time limit. Asm, Control flow and Listing still work." : f.error}</p>}
    {f.retry_pending && !NATIVE && a.retryFunction && <button disabled={busy} onClick={async () => {
      setBusy(true);
      try { await a.retryFunction!(address); } finally { setBusy(false); }
    }}>{busy ? "Trying with a longer limit…" : "Try with a longer limit"}</button>}
    {limited && <details><summary>Engine message</summary>{f.error}</details>}
  </div>;
}

export type { Layout };

const PEEK_LINES = 14, PEEK_WIDTH = 480, PEEK_HEIGHT = 340;

/** A function at a glance, shown while hovering a link to it, without leaving the place being read. */
function FnPeek({ a, address, rect, caps, display }: { a: Analysis; address: number; rect: DOMRect; caps: string[]; display: (t: string) => string | undefined }) {
  const notes = useNotes();
  const f = a.functions.get(address);
  const lines = (f?.text ?? "").replace(/^\n+/, "").trimEnd().split("\n");
  const below = window.innerHeight - rect.bottom > PEEK_HEIGHT || rect.top < PEEK_HEIGHT;
  const style: React.CSSProperties = { left: Math.max(8, Math.min(rect.left, window.innerWidth - PEEK_WIDTH - 8)), width: PEEK_WIDTH, maxHeight: PEEK_HEIGHT, ...(below ? { top: rect.bottom + 6 } : { bottom: window.innerHeight - rect.top + 6 }) };
  return (
    <div className="fn-peek" style={style} aria-hidden>
      <div className="fn-peek-head"><b>{notes.label(address, f?.name ?? a.names.get(address))}</b><code>{hex(address)}</code></div>
      {caps.length > 0 && <div className="fn-peek-caps">{caps.slice(0, 4).map((c) => <span key={c} className="cap">{c}</span>)}{caps.length > 4 && <small>+{caps.length - 4}</small>}</div>}
      {f?.text ? <Code text={lines.slice(0, PEEK_LINES).join("\n")} display={display} /> : <p className="fine">{f?.error ? "This function could not be decompiled." : "Still decompiling…"}</p>}
      {lines.length > PEEK_LINES && <small className="fn-peek-more">{lines.length - PEEK_LINES} more lines</small>}
    </div>
  );
}

const PanelIcon = ({ side }: { side: "left" | "right" }) => (
  <svg viewBox="0 0 24 24" aria-hidden><rect x="3.5" y="5" width="17" height="14" rx="2" /><path d={side === "left" ? "M9 5v14" : "M15 5v14"} /></svg>
);

/** Compact list of functions in the xref rail. */
function XrefGroup({ title, items, a, onGoto, pending }: { title: string; items?: number[]; a: Analysis; onGoto: (ad: number) => void; pending: boolean }) {
  const notes = useNotes();
  return (
    <section className="rail-sec">
      <h3>{title} {items && <small>{items.length}</small>}</h3>
      {!items ? <p className="fine">{pending ? "Computed when decompilation finishes" : "-"}</p>
        : items.length === 0 ? <p className="fine">None</p>
        : items.map((ad) => <button key={ad} className="rail-item" data-fn={ad} onClick={() => onGoto(ad)}>{notes.label(ad, a.functions.get(ad)?.name)}</button>)}
    </section>
  );
}

type MobileTab = "c" | "asm" | "graph" | "listing" | "refs" | "emu";

export interface FnViewProps {
  a: Analysis; address: number; rules: CapaRule[];
  origin?: FunctionOrigin;
  resolve: (t: string) => number | undefined; onGoto: (ad: number) => void;
  callers?: number[]; callees?: number[]; xrefsReady: boolean;
  /** Any function's callers and callees, for the phone's call tree. */
  callersOf?: (ad: number) => number[] | undefined; calleesOf?: (ad: number) => number[] | undefined;
  /** The imported APIs a function calls. */
  apisOf?: (ad: number) => string[] | undefined;
  strings: StringEntry[]; onString: (text: string) => void; strAt: (ad: number) => string | undefined;
  /** Text at a data address that the strings list leaves out. */
  textAt: (ad: number) => string | undefined;
  /** Phone layout: a full-screen page with a back button and C / Asm / Refs tabs. */
  mobile?: boolean; onBack?: () => void;
  /** The shared address cursor: the instruction it names is selected here, and clicks move it. */
  cursor: number | null; onCursor: (ad: number) => void;
  /** Whether an address is file data, and showing it in the Listing. */
  isData: (ad: number) => boolean; onData: (ad: number) => void;
  slot: (va: number) => { name: string; dll: string } | undefined; onImport: (name: string) => void;
  onComment: () => void; onNotesChange: () => void;
  starred: boolean; onStar: () => void; onRename: (name: string) => void;
  /** Rename any function by address, and show the references to an address (the x shortcut). */
  onRenameAt: (ad: number, name: string) => void; onXrefs: (what: number | string) => void;
  xrefReq: number;
  /** Bumped by the rename shortcut, to edit the name in place. */
  renameReq: number;
  /** Desktop: the function list and side panel can be hidden for more room. */
  listOpen?: boolean; onToggleList?: () => void; railOpen?: boolean; onToggleRail?: () => void;
  /** Shows a branch target this function's rows do not have. */
  onCode: (va: number) => void;
  /** Capability names matched in any function, for its preview. */
  capsOf: (ad: number) => string[];
  /** Toggles between one pane and the previous layout. */
  onToggleSplit?: () => void;
  /** Which views the code panes show; Listing shows the whole file instead of this function. */
  layout: Layout; setLayout: (l: Layout) => void;
  paneView?: CodeView;
  shortcutsEnabled?: boolean;
  renderPane?: PaneRenderer;
  outside?: (fn: number, va: number) => string | null;
  locate?: (va: number, current: PanePlace) => PanePlace;
  onPaneNavigate?: (va: number, fn?: number) => void;
  onShowAsm?: (va: number) => void;
  /** Phone: opens the bytes at an address in the Hex view. */
  onHex?: (va: number) => void;
  /** Shows file bytes in the Hex view, selected (the Emulate tab's output). */
  onBytes?: (va: number, len: number) => void;
  /** Opens a function at one of its instructions (an emulated call site). */
  onSite?: (fn: number, at: number) => void;
  asmJump?: { va: number };
  /** The Listing, with the instructions of the selected C line marked. */
  listing: (marked: Set<number>) => React.ReactNode; callGraph: (onOpen: (ad: number) => void) => React.ReactNode;
  /** Phone only: bumped when the strip is tapped, to show the listing; the strip itself; the ⋯ menu's shared items; opening search. */
  listingReq: number;
  /** The last Listing request a function page acted on. Kept by the workspace, so a request made from Data opens the Listing tab of the page it mounts. */
  listingSeen?: React.MutableRefObject<number>;
  /** Desktop: a view to show in a side pane, and the last such request handled (see CodePanes). */
  peekReq?: { view: CodeView; n: number } | null;
  peekSeen?: React.MutableRefObject<number>;
  strip: React.ReactNode; menuItems: MenuItem[]; onSearch: () => void;
}

/** The instruction last clicked in any ASM view, so sibling ASM panes can mirror it exactly. */
let asmPick: number | null = null;

export function FunctionView({ a, address, rules, origin, resolve, onGoto, callers, callees, callersOf, calleesOf, apisOf, xrefsReady, strings, onString, strAt, textAt, mobile, onBack, cursor, onCursor, isData, onData, slot, onImport, onComment, onNotesChange, starred, onStar, onRename, onRenameAt, onXrefs, xrefReq, renameReq, listOpen, onToggleList, railOpen, onToggleRail, onToggleSplit, capsOf, onCode, layout, setLayout, listing, callGraph, listingReq, listingSeen, peekReq, peekSeen, strip, menuItems, onSearch, paneView, renderPane, locate, outside, onPaneNavigate, onShowAsm, onHex, onBytes, onSite, asmJump, shortcutsEnabled = true }: FnViewProps) {
  const notes = useNotes();
  const fnLabel = (ad: number, name?: string | null) => notes.label(ad, name ?? a.functions.get(ad)?.name ?? a.names.get(ad));
  const exportOf = (ad: number) => notes.exportOf(ad);
  const f = a.functions.get(address);
  const argNotes = useMemo(() => instructionNotes(f, a.arch), [f, a.arch]);
  const importNames = useMemo(() => new Set([...(a.image?.imports ?? []), ...resolvedSlots(a.resolved)].flatMap((i) => [importKey(i), i.name])), [a.image, a.resolved]);
  const vocabulary = useMemo(() => codeVocabulary(f?.frame, (name) => importNames.has(name), f?.text), [f?.frame, f?.text, importNames]);
  const handleHints = useMemo(() => f?.text && (mobile || paneView === "c")
    ? fileHandleOrigins(f.text, (name) => importNames.has(name)) : undefined, [f?.text, importNames, mobile, paneView]);
  const [copied, setCopied] = useState(false);
  // The decompiler prints each statement on one line; the pane wraps it to its width.
  const [wrap, setWrap] = useState(true);
  const [inspector, setInspector] = useState<"refs" | "stack" | "emulate">("refs");
  const inlineStr = true; // strings a data label points at are written inline
  // Analyst names and export names replace the decompiler's in the body, and in what is copied.
  const fnDisplay = (t: string) => { const r = resolve(t); return r === undefined ? undefined : notes.renamed(r) ?? (t.startsWith("FUN_") ? exportOf(r) ?? notes.trustedOf(r)?.name : undefined); };
  // Local variables carry the analyst's names for this function only.
  const display = (t: string) => fnDisplay(t) ?? notes.varName(address, t);
  const copy = () => { if (f?.text) navigator.clipboard.writeText(applyNames(f.text, display)).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); }); };
  const noSelf = (t: string) => { const r = resolve(t); return r === address ? undefined : r; };
  // The decompiler prints most strings as literals, without an address: look for the one this function refers to.
  const openString = (text: string, at?: number) => {
    const found = at ?? strings.find((x) => x.s === text)?.a ?? f?.data_refs?.find((r) => textAt(r.to) === text)?.to ?? a.strings.find((x) => x.s === text)?.a;
    if (found !== undefined) onData(found); else onString(text);
  };

  // The name edits in place: Enter or leaving the field keeps it, Escape does not.
  const [editing, setEditing] = useState(false);
  const closed = useRef(false);
  useEffect(() => setEditing(false), [address]);
  const handledRename = useRef(renameReq);
  const nameField = (
    <input className="rename" autoFocus aria-label="Function name" defaultValue={fnLabel(address, f?.name)} spellCheck={false} onFocus={(e) => e.target.select()}
      onBlur={(e) => finish(e.target.value)}
      onKeyDown={(e) => { if (e.key === "Enter") finish(e.currentTarget.value); else if (e.key === "Escape") { e.stopPropagation(); finish(); } }} />
  );

  // A clicked word lights up wherever it is used, in every pane. A style rule does it, without rendering the code again.
  // The identifier last clicked in the code: what n renames and x looks up, as in IDA.
  const picked_id = useRef<string | null>(null);
  const [varEdit, setVarEdit] = useState<{ id: string; fn?: number; rect: DOMRect } | null>(null);
  const [, bumpVars] = useReducer((n: number) => n + 1, 0);
  const wordRect = () => {
    const el = word ? document.querySelector(`.cockpit [data-tok="${CSS.escape(word)}"]`) : null;
    return el?.getBoundingClientRect() ?? new DOMRect(window.innerWidth / 2 - 100, 120, 200, 20);
  };
  const [word, setWord] = useState<string | null>(null);
  const wordStyle = word && <style>{`.cockpit [data-tok="${CSS.escape(word)}"] { background: var(--tok); border-radius: 2px; box-shadow: 0 0 0 1px var(--tok); }`}</style>;

  const [peek, setPeek] = useState<{ address: number; rect: DOMRect } | null>(null);
  const peekTimer = useRef(0);
  const canHover = useMedia("(hover: hover)");
  const hidePeek = () => { window.clearTimeout(peekTimer.current); setPeek(null); };
  useEffect(hidePeek, [address]);
  const peekEvents = !canHover ? {} : {
    onMouseOver: (e: React.MouseEvent) => {
      const link = (e.target as Element).closest?.("[data-fn]") as HTMLElement | null;
      window.clearTimeout(peekTimer.current);
      if (!link) { setPeek(null); return; }
      peekTimer.current = window.setTimeout(() => setPeek({ address: Number(link.dataset.fn), rect: link.getBoundingClientRect() }), 300);
    },
    onMouseLeave: hidePeek, onScrollCapture: hidePeek,
  };
  const [tokenBar, setTokenBar] = useState<{ text: string; id: string | null; at: number | null } | null>(null);
  const pickWord = (e: React.MouseEvent) => {
    hidePeek();
    const el = (e.target as Element).closest?.("[data-tok]") as HTMLElement | null;
    setWord(el?.dataset.tok ?? null);
    picked_id.current = el?.dataset.id ?? null;
    // A phone has no n, x or right-click: a tapped word offers its actions in a bar. A link follows itself.
    const row = (e.target as Element).closest?.("[data-addr]") as HTMLElement | null;
    setTokenBar(mobile && el && !el.closest("a") ? { text: el.textContent ?? "", id: el.dataset.id ?? null, at: row ? Number(row.dataset.addr) : null } : null);
  };
  // A right-click picks the word too, so the menu's Rename acts on it as n does.
  const codeEvents = { ...peekEvents, onClickCapture: pickWord, onContextMenuCapture: pickWord };
  const peekCard = peek && <FnPeek a={a} address={peek.address} rect={peek.rect} caps={capsOf(peek.address)} display={fnDisplay} />;
  /** Rename what was last picked: a called function, a local, else this function. Shared by n and the phone's action bar. */
  const renameWord = () => {
    const id = picked_id.current;
    const r = id ? resolve(id) : undefined;
    if (id && r !== undefined && r !== address) setVarEdit({ id, fn: r, rect: wordRect() });                       // a called function
    else if (id && r === undefined && isLocalName(id, vocabulary)) setVarEdit({ id, rect: wordRect() });           // a local variable
    else setEditing(true);
  };
  /** The references to what was last picked, else to this function. */
  const xrefWord = () => {
    const id = picked_id.current, r = id ? resolve(id) : undefined;
    const tail = id && (id.startsWith("0x") ? id : /_([0-9a-fA-F]{5,16})$/.exec(id)?.[1]);
    const lit = tail ? parseInt(tail, 16) : NaN;
    onXrefs(r !== undefined ? r : !Number.isNaN(lit) ? lit : id && /^[A-Za-z_][\w$@?]*$/.test(id) && !isLocalName(id, vocabulary) ? id : address);
  };
  useEffect(() => {
    if (!shortcutsEnabled) { handledRename.current = renameReq; return; }
    if (renderPane && !mobile) return;
    if (renameReq === handledRename.current) return;
    handledRename.current = renameReq;
    renameWord();
  }, [renameReq]);
  // x: the references to the word last clicked, else to this function.
  const handledXref = useRef(xrefReq);
  useEffect(() => {
    if (!shortcutsEnabled) { handledXref.current = xrefReq; return; }
    if (renderPane && !mobile) return;
    if (xrefReq === handledXref.current) return;
    handledXref.current = xrefReq;
    xrefWord();
  }, [xrefReq]);
  useEffect(() => { picked_id.current = null; setVarEdit(null); setTokenBar(null); }, [address]);
  const finishVar = (name?: string) => {
    const e = varEdit; setVarEdit(null);
    if (!e || name === undefined) return;
    if (e.fn !== undefined) onRenameAt(e.fn, name === fnLabel(e.fn, a.functions.get(e.fn)?.name) ? "" : name);
    else { notes.renameVar(address, e.id, name === e.id ? "" : name); bumpVars(); onNotesChange(); }
  };
  const varBox = varEdit && (
    <input className="rename rename-float" autoFocus aria-label={"Rename " + varEdit.id} spellCheck={false} style={{ top: varEdit.rect.bottom + 4, left: Math.max(8, varEdit.rect.left) }}
      defaultValue={varEdit.fn !== undefined ? fnLabel(varEdit.fn, a.functions.get(varEdit.fn)?.name) : display(varEdit.id) ?? varEdit.id} onFocus={(e) => e.target.select()}
      onBlur={(e) => finishVar(e.target.value)}
      onKeyDown={(e) => { if (e.key === "Enter") finishVar(e.currentTarget.value); else if (e.key === "Escape") { e.stopPropagation(); setVarEdit(null); } }} />
  );
  const startRename = () => { closed.current = false; setEditing(true); };
  const finish = (name?: string) => { if (closed.current) return; closed.current = true; setEditing(false); if (name !== undefined && name !== fnLabel(address, f?.name)) onRename(name); };
  useEffect(() => { if (editing) closed.current = false; }, [editing]);

  const panes = panesOf(layout);
  const [railWidth, setRailWidth] = useStored("rail-width", 240);
  const hasAsm = !!f?.asm?.length;
  // Phones wrap long instructions, so rows have no fixed height to draw arrows against.
  const arrows = hasAsm && !mobile && paneView === "asm" ? cachedFunctionArrows(f!.asm!, a.arch) : undefined;

  // Clicking a C line or an instruction highlights its counterpart(s) on the other side.
  const [focus, setFocus] = useState<{ kind: "c"; line: number } | { kind: "a"; ad: number; group?: boolean } | null>(null);
  useEffect(() => setFocus(null), [address]);
  // The shared cursor selects its instruction here (from a capability match, a hex click, a link) and scrolls to it.
  const selfScroll = useRef(false), picked = useRef<number | null>(null);
  useEffect(() => {
    if (cursor === null || !f?.asm) return;
    if (picked.current === cursor) { picked.current = null; return; }
    // A click in another ASM pane selects just that instruction here too; any other arrival shows the whole C line.
    if (f.asm.some((r) => r[0] === cursor)) { selfScroll.current = true; setFocus({ kind: "a", ad: cursor, group: asmPick !== cursor }); } // arriving: the whole C line's instructions, as a click on that line shows
  }, [cursor, address, f]);
  const focusInstruction = (ad: number) => { selfScroll.current = true; setFocus({ kind: "a", ad }); };
  useEffect(() => { if (asmJump) focusInstruction(asmJump.va); }, [asmJump]);
  const capAt = useMemo(() => {
    const m = new Map<number, string[]>();
    for (const r of rules) for (const ad of r.addresses) m.set(ad, [...(m.get(ad) ?? []), r.name]);
    return m;
  }, [rules]);
  const lines = useMemo(() => (f?.lines && f.asm ? linesWithSetup(f.lines, f.asm, a.arch, f.cfg) : []), [f, a.arch]);
  const hlAddrs = useMemo(() => new Set(focus?.kind === "c" ? lines[focus.line] ?? [] : focus?.kind === "a" ? (focus.group ? [focus.ad, ...(lines.find((l) => l.includes(focus.ad)) ?? [])] : [focus.ad]) : []), [focus, f]);
  const hlLines = useMemo(() => {
    const set = new Set<number>();
    if (focus?.kind === "c") set.add(focus.line);
    if (focus?.kind === "a") lines.forEach((l, i) => { if (l.includes(focus.ad)) set.add(i); });
    return set;
  }, [focus, f]);
  const cPane = useRef<HTMLDivElement>(null), asm = useRef<AsmHandle>(null);
  const revealAsm = (center = false) => {
    // Match the first highlighted row, including ones outside the mounted window.
    const ad = f?.asm?.find((r) => hlAddrs.has(r[0]))?.[0];
    if (ad !== undefined) asm.current?.scrollToAddress(ad, center);
  };
  useEffect(() => {
    // Bring the counterpart into view in the pane that was not clicked.
    if (focus?.kind === "c") revealAsm();
    else if (focus?.kind === "a") {
      if (cursor === address && cPane.current) cPane.current.scrollTop = 0;
      else revealIn(cPane.current, ".ln.hl");
    }
    if (selfScroll.current && focus) {
      selfScroll.current = false;
      revealAsm(true);
      if (cursor === address && cPane.current) cPane.current.scrollTop = 0;
      else revealIn(cPane.current, ".ln.hl", true);
    }
  }, [focus]);
  // IDA-style: a comment on an instruction appears on the C line that instruction belongs to.
  const lineComments = notes.hasComments() ? (() => {
    const m = new Map<number, string>();
    lines.forEach((addrs, i) => {
      const found = [...new Set(addrs.filter((ad) => ad !== address).map((ad) => notes.commentAt(ad, true)).filter((t): t is string => !!t))];
      if (found.length) m.set(i, found.join(" · "));
    });
    return m;
  })() : undefined;
  const trimmed = f?.text ? f.text.replace(/^\n+/, "") : "";
  const lineOffset = f?.text ? f.text.length - f.text.replace(/^\n+/, "").length : 0;
  // A pane opened beside the others starts at the selection, not at the top.
  useEffect(() => {
    revealAsm(true);
    if (cursor === address && cPane.current) cPane.current.scrollTop = 0;
    else revealIn(cPane.current, ".ln.hl", true);
  }, [layout]);

  const pickCLine = (line: number) => {
    setFocus({ kind: "c", line });
    // A brace or declaration has no instruction of its own: the nearest line that has one moves the cursor.
    let first: number | undefined;
    for (let d = 0; d < lines.length && first === undefined; d++) first = lines[line - d]?.[0] ?? lines[line + d]?.[0];
    if (first !== undefined) { picked.current = first; onCursor(first); }
  };

  const cContent = (
    <>
              {!f && <div className="notice"><span className="spin" /> Decompiling…</div>}
              <DecompileNotice key={address} a={a} address={address} />
              {f?.text && (
                <>
                  {!mobile && <div className="c-tools"><button onClick={copy} title="Copy the decompiled C, with your names">{copied ? "Copied" : "Copy C"}</button><button aria-pressed={wrap} onClick={() => setWrap((w) => !w)} title="Wrap long lines">Wrap</button></div>}
                  <PackedNotice a={a} />
                  {(f.incomplete || (f.warnings?.length ?? 0) > 0) && (
                    <FunctionWarnings f={f} onShowAsm={mobile ? showMobileAsm : onShowAsm} />
                  )}
                  <Code text={trimmed.trimEnd()} lineOffset={lineOffset} comments={lineComments} active={hlLines} onLine={pickCLine}
                    handleOrigins={handleHints?.size ? { hints: handleHints, jump: (line) => {
                      pickCLine(line);
                      revealIn(cPane.current, `[data-ln="${line}"]`);
                    } } : undefined}
                    resolve={noSelf} display={display} onGoto={onGoto} onString={openString} strAt={strAt} inlineStrings={inlineStr} data={{ is: isData, go: onData }} vocabulary={vocabulary} />
                </>
              )}
              {a.decompileError && <div className="notice error">Decompiler: {a.decompileError}</div>}
    </>
  );
  const aContent = (
    <>
              {hasAsm ? <Asm scrollRef={asm} focusable arrows={arrows} arch={a.arch} onCode={onCode} rows={f!.asm!} labels={f!.labels} self={address} resolve={resolve} onGoto={onGoto} strAt={strAt} textAt={textAt} label={(ad) => f?.labels?.[ad] ?? fnLabel(ad, a.functions.get(ad)?.name)} active={hlAddrs} onPick={(ad) => { picked.current = ad; asmPick = ad; setFocus({ kind: "a", ad }); onCursor(ad); }} capAt={capAt} isData={isData} onData={onData} slot={slot} onImport={onImport} argNotes={argNotes} />
                : <p className="fine">{f ? "No instruction listing." : "Waiting for analysis…"}</p>}
    </>
  );
  const graphContent = hasAsm
    ? <GraphView recovered={f?.cfg} rows={f!.asm!} arch={a.arch} self={address} name={fnLabel(address, f?.name)} rules={rules} resolve={resolve} onGoto={onGoto} strAt={strAt} textAt={textAt} label={(ad) => fnLabel(ad, a.functions.get(ad)?.name)} cursor={cursor} onCursor={onCursor} marked={hlAddrs} slot={slot} onImport={onImport} isData={isData} onData={onData} onCode={onCode} argNotes={argNotes} />
    : <p className="fine">{f ? "No instruction listing." : "Waiting for analysis…"}</p>;
  const refsContent = (
    <>
          <XrefGroup title="Calls" items={xrefsReady ? callees ?? [] : undefined} a={a} onGoto={onGoto} pending={!xrefsReady} />
          <XrefGroup title="Called by" items={xrefsReady ? callers ?? [] : undefined} a={a} onGoto={onGoto} pending={!xrefsReady} />
          <section className="rail-sec">
            <h3>Strings {xrefsReady && <small>{strings.length}</small>}</h3>
            {!xrefsReady ? <p className="fine">Computed when decompilation finishes</p>
              : strings.length === 0 ? <p className="fine">None</p>
              : strings.map((x) => (
                <button key={x.a} className="rail-item str-item" onClick={() => openString(x.s, x.a)} title={hex(x.a) + " - show in the Listing"}>{x.s}</button>
              ))}
          </section>
    </>
  );

  const frameContent = <StackFrame frame={f?.frame} arch={a.arch} pending={!f} onWord={setWord} onInstruction={(ad) => { focusInstruction(ad); onCursor(ad); }} />;

  const [expandedCapsFor, setExpandedCapsFor] = useState<number | null>(null);
  const [mTab, setMTab] = useState<MobileTab>("c");
  const [rel, setRel] = useState<"callees" | "callers" | "strings" | "stack">("callees");
  function showMobileAsm(ad: number) {
    if (cursor !== ad) picked.current = ad;
    focusInstruction(ad);
    onCursor(ad);
    setMTab("asm");
  }
  const touch = useRef<{ x: number; y: number } | null>(null);
  useEffect(() => { setMTab("c"); }, [address]);
  const ownReq = useRef(listingReq), handledReq = listingSeen ?? ownReq;
  useEffect(() => { if (listingReq !== handledReq.current) { handledReq.current = listingReq; setMTab("listing"); } }, [listingReq, address]);
  // Tapping a C line selects its instructions (and the reverse); show them when the tab opens.
  useEffect(() => {
    if (!mobile) return;
    if (mTab === "asm") revealAsm(true);
    else [...document.querySelectorAll<HTMLElement>(".m-body .ln.hl")].find((el) => el.offsetParent)?.scrollIntoView({ block: "center" });
  }, [mTab, mobile]);
  const callsContent = callGraph((ad) => {
    onGoto(ad);
    if (mobile) setMTab("c");
    else if (!panes.includes("c")) setLayout([...panes, "c"].join("+"));
  });
  const inspectorTabs = (
    <div className="inspector-tabs" role="group" aria-label="Function details">
      <button aria-pressed={inspector === "refs"} onClick={() => setInspector("refs")}>References</button>
      <button aria-pressed={inspector === "stack"} onClick={() => setInspector("stack")}>Stack frame</button>
      <button aria-pressed={inspector === "emulate"} onClick={() => setInspector("emulate")}>Emulate</button>
    </div>
  );
  // Keyed by address: each function keeps its own arguments and results.
  const emulateContent = (
    <EmulatePanel key={address} a={a} address={address} text={f?.text} callers={xrefsReady ? callers : undefined} label={(ad) => fnLabel(ad, a.functions.get(ad)?.name)} mobile={mobile}
      onSite={(fn, at) => { if (onSite) onSite(fn, at); else { onGoto(fn); onCursor(at); } if (mobile) setMTab("asm"); }}
      onBytes={onBytes} />
  );
  const contents: Partial<Record<CodeView, React.ReactNode>> = { c: cContent, asm: aContent, graph: graphContent, calls: callsContent, listing: listing(hlAddrs) };
  if (paneView) return (
    <div className={"cockpit pane-only" + (wrap ? " wrap" : "")} {...codeEvents}>
      {wordStyle}
      {editing && <div className="pane-rename"><span>Function name</span>{nameField}</div>}
      <div className={"cp-pane" + (paneView === "graph" || paneView === "calls" || paneView === "listing" ? " graph-pane" : "")} ref={paneView === "c" ? cPane : undefined}>{contents[paneView]}</div>
      {peekCard}{varBox}
    </div>
  );
  const functionComments = notes.comments(address).length > 0 && (
    <div className="fn-comment" aria-label="Function comment">
      {notes.comments(address).map((c, i) => <p key={i}><span className="fn-by">{c.source === "ai" ? "AI" : "You"}</span>{c.text}</p>)}
    </div>
  );
  const capButton = (rule: CapaRule) => (
    <button key={rule.name} className="cap" title={(rule.namespace ?? "") + " · click to show the match"} onClick={() => {
      const instructions = new Set(f?.asm?.map(([at]) => at));
      const matches = rule.addresses.filter((ad) => ad === address || instructions.has(ad));
      const ad = matches.flatMap((site) => rule.evidence.get(site) ?? []).find((at) => instructions.has(at)) ?? matches[0];
      if (ad !== undefined) { selfScroll.current = true; setFocus({ kind: "a", ad }); onCursor(ad); }
    }}>{rule.name}</button>
  );

  if (mobile) {
    const refCount = (callees?.length ?? 0) + (apisOf?.(address)?.length ?? 0) + (callers?.length ?? 0) + strings.length;
    const fnName = (ad: number) => fnLabel(ad, a.functions.get(ad)?.name);
    const calls = (callees?.length ?? 0) + (apisOf?.(address)?.length ?? 0);
    const relTabs = [["callees", "Calls", calls], ["callers", "Called by", callers?.length], ["strings", "Strings", strings.length], ["stack", "Stack", undefined]] as const;
    // Calls, callers, strings and the frame in one place; the call graph's depth is the tree's expand arrows.
    const mobileRefs = (
      <>
        <div className="m-subseg" role="tablist" aria-label="Function references">
          {relTabs.map(([k, name, n]) => (
            <button key={k} role="tab" aria-selected={rel === k} className={rel === k ? "on" : ""} onClick={() => setRel(k)}>
              {name}{xrefsReady && n !== undefined && <em>{n}</em>}
            </button>
          ))}
        </div>
        {(rel === "callees" || rel === "callers") && (!xrefsReady
          ? <p className="ct-empty">Calls are known once decompilation finishes.</p>
          : <CallTree key={rel + address} root={address} dir={rel} edges={(ad) => ad === address ? (rel === "callees" ? callees : callers) : (rel === "callees" ? calleesOf : callersOf)?.(ad)}
              apis={rel === "callees" ? apisOf : undefined} onApi={onImport}
              label={fnName} caps={capsOf} onOpen={(ad) => { setMTab("c"); onGoto(ad); }} />)}
        {rel === "strings" && (!xrefsReady ? <p className="ct-empty">Computed when decompilation finishes.</p>
          : strings.length === 0 ? <p className="ct-empty">This function references no strings.</p>
          : <div className="m-strs">{strings.map((x) => (
            <button key={x.a} className="m-str" onClick={() => openString(x.s, x.a)}><span>{x.s}</span><code>{hex(x.a)}</code></button>
          ))}</div>)}
        {rel === "stack" && <div className="rail m-frame">{frameContent}</div>}
      </>
    );
    // Capability chips scroll away with the code instead of pinning a row to the screen.
    const capChips = (rules.length > 0 || (origin && origin.kind !== "unique")) && (
      <div className="m-caps">
        <OriginBadge origin={origin} />
        {rules.map(capButton)}
      </div>
    );
    // A horizontal swipe on text moves between views; graphs and the listing keep the gesture for panning.
    const order: MobileTab[] = ["c", "asm", "graph", "listing", "refs"];
    const swipeable = mTab === "c" || mTab === "asm" || mTab === "refs";
    const swipe = {
      onTouchStart: (e: React.TouchEvent) => { const t = e.touches[0]; touch.current = swipeable ? { x: t.clientX, y: t.clientY } : null; },
      onTouchEnd: (e: React.TouchEvent) => {
        const s = touch.current; touch.current = null;
        if (!s) return;
        const t = e.changedTouches[0], dx = t.clientX - s.x, dy = t.clientY - s.y;
        if (Math.abs(dx) < 70 || Math.abs(dx) < Math.abs(dy) * 2) return;
        const next = order[order.indexOf(mTab) + (dx < 0 ? 1 : -1)];
        if (next) setMTab(next);
      },
    };
    return (
      <div className={"cockpit m" + (wrap ? " wrap" : "")}>
        <div className="m-bar">
          <button className="m-back" onClick={onBack} aria-label="Back"><svg viewBox="0 0 24 24" aria-hidden><path d="M15 5l-7 7 7 7" /></svg></button>
          <div className="m-title">
            {editing ? nameField : <h1>{starred && <span className="star">★ </span>}{notes.aiName(address) && <span className={"ai-mark " + notes.aiName(address)} title={`Named by AI (${notes.aiName(address)})`}>✦ </span>}{fnLabel(address, f?.name)}</h1>}
            <code>{copied ? "Copied" : hex(address)}</code>
          </div>
          <button className={"m-icon m-star" + (starred ? " on" : "")} aria-label={starred ? "Remove star" : "Star this function"} aria-pressed={starred} onClick={onStar}>{starred ? "★" : "☆"}</button>
          <button className="m-icon" aria-label="Search" onClick={onSearch}>
            <svg viewBox="0 0 24 24" aria-hidden><circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" /></svg>
          </button>
          <MoreMenu items={[
            { label: starred ? "Remove star" : "Star function", onClick: onStar },
            { label: "Rename…", onClick: startRename },
            { label: notes.commentAt(cursor ?? address) ? "Edit comment…" : "Add comment…", onClick: onComment },
            { label: "Copy C", onClick: copy, disabled: !f?.text },
            { label: wrap ? "Wrap lines: on" : "Wrap lines: off", onClick: () => setWrap((w) => !w) },
            ...menuItems,
          ]} />
        </div>
        <div className="m-seg" role="tablist">
          {([["c", "C"], ["asm", "Asm"], ["graph", "Flow"], ["listing", "Listing"], ["refs", "Refs"], ["emu", "Emulate"]] as const).map(([k, name]) => (
            <button key={k} role="tab" aria-selected={mTab === k} className={mTab === k ? "on" : ""} onClick={() => setMTab(k)}>
              {name}{k === "refs" && xrefsReady && refCount > 0 && <em>{refCount}</em>}
            </button>
          ))}
        </div>
        {functionComments}
        {wordStyle}
        <div className="m-body" {...codeEvents} {...swipe}>
          {mTab === "c" && <div className="cp-pane" ref={cPane}>{capChips}{cContent}</div>}
          {mTab === "asm" && <div className="cp-pane">{capChips}{aContent}</div>}
          {mTab === "graph" && <div className="cp-pane graph-pane">{graphContent}</div>}
          {mTab === "listing" && <div className="cp-pane graph-pane">{listing(hlAddrs)}</div>}
          {mTab === "refs" && <div className="cp-pane m-refs">{mobileRefs}</div>}
          {mTab === "emu" && <div className="cp-pane m-emu">{emulateContent}</div>}
        </div>
        {tokenBar && (
          <div className="m-tokbar" role="toolbar" aria-label={"Actions for " + tokenBar.text}>
            <code>{tokenBar.text.length > 18 ? tokenBar.text.slice(0, 17) + "…" : tokenBar.text}</code>
            <button onClick={() => { setTokenBar(null); renameWord(); }}>Rename</button>
            <button onClick={() => { setTokenBar(null); xrefWord(); }}>Xrefs</button>
            <button onClick={() => { setTokenBar(null); onComment(); }}>Comment</button>
            <button onClick={() => { void navigator.clipboard?.writeText(tokenBar.id ? display(tokenBar.id) ?? tokenBar.id : tokenBar.text); setTokenBar(null); }}>Copy</button>
            <button onClick={() => {
              const literal = /^0x[0-9a-f]+$/i.test(tokenBar.text) ? parseInt(tokenBar.text, 16) : null;
              setTokenBar(null);
              onHex?.(literal ?? tokenBar.at ?? cursor ?? address);
            }}>Hex</button>
            <button className="m-tok-x" aria-label="Dismiss" onClick={() => setTokenBar(null)}>×</button>
          </div>
        )}
        {peekCard}{varBox}
      </div>
    );
  }

  const railSize = inspector === "stack" ? Math.max(railWidth, 300) : inspector === "emulate" ? Math.max(railWidth, 340) : railWidth;
  // One match reads inline; several collapse into one trigger so the title keeps its room.
  const capsExpanded = rules.length > 1 && expandedCapsFor === address;
  return (
    <div className={"cockpit" + (wrap ? " wrap" : "")}>
      <div className="cp-head">
        <button className="icon-btn" onClick={onToggleList} aria-pressed={listOpen} aria-label="Function list" title="Show or hide the function list ([)"><PanelIcon side="left" /></button>
        <div className="cp-title">
          {editing ? nameField : <h1 title={fnLabel(address, f?.name)} onDoubleClick={startRename}>{notes.aiName(address) && <span className={"ai-mark " + notes.aiName(address)} title={`Named by AI (${notes.aiName(address)})`}>✦ </span>}{fnLabel(address, f?.name)}</h1>}
          <code className="addr">{copied ? "Copied" : hex(address)}</code>
        </div>
        <div className="cp-caps-inline">
          <OriginBadge origin={origin} />
          {exportOf(address) && <span className="cap export" title="Named by the file's export table">export {exportOf(address)}</span>}
          {rules.length === 1 && capButton(rules[0])}
        </div>
        {rules.length > 1 && (
          <button type="button" className="cap cap-more" aria-expanded={capsExpanded} aria-controls="cp-caps-list"
            title={rules.map((r) => r.name).join("\n")}
            onClick={() => setExpandedCapsFor(capsExpanded ? null : address)}>
            {rules.length} capabilities <span aria-hidden>{capsExpanded ? "▴" : "▾"}</span>
          </button>
        )}
        <span className="cp-spacer" />
        <button className="icon-btn" onClick={onComment} aria-label="Edit comment" title="Add or edit a comment (;)">;</button>
        <button className={"icon-btn star-btn" + (starred ? " on" : "")} onClick={onStar} aria-pressed={starred} aria-label="Star this function" title="Star this function (s)">{starred ? "★" : "☆"}</button>
        <button className="icon-btn" onClick={onToggleRail} aria-pressed={railOpen} aria-label="Function inspector" title="Show or hide the function inspector (])"><PanelIcon side="right" /></button>
      </div>
      {capsExpanded && <div className="cp-caps-expanded" id="cp-caps-list" role="group" aria-label="Capabilities matched in this function">{rules.map(capButton)}</div>}
      {/* The same height with or without matches, so the code does not move from function to function. */}
      {mobile && <div className="cp-caps">
        {exportOf(address) && <span className="cap export" title="Named by the file's export table">export {exportOf(address)}</span>}
        {rules.map(capButton)}
        {a.capa && !rules.length && !exportOf(address) && <span className="fine">No capabilities matched here</span>}
      </div>}

      {functionComments}

      <div className="cp-body" style={{ gridTemplateColumns: railOpen ? `minmax(0, 1fr) ${railSize}px` : "minmax(0, 1fr)" }}>
        {!railOpen && !mobile && <button className="edge-tab inspector-tab" onClick={onToggleRail} title="Open the function inspector (])"><span>Inspector</span></button>}
        {renderPane && locate && onPaneNavigate && <CodePanes outside={outside} layout={layout} setLayout={setLayout} place={{ address, cursor }} onNavigate={onPaneNavigate} locate={locate} render={renderPane} fileName={a.demo?.name ?? a.fileName} fileTitle={a.fileName} label={(ad) => fnLabel(ad, a.functions.get(ad)?.name)} peek={peekReq} peekSeen={peekSeen} />}

        {railOpen && (
          <aside className="rail" aria-label="Function inspector" {...peekEvents}>
            <div className="inspector-head">
              {inspectorTabs}
              <button className="inspector-close" onClick={onToggleRail} aria-label="Close function inspector">×</button>
            </div>
            {inspector === "refs" ? refsContent : inspector === "stack" ? frameContent : emulateContent}
          </aside>
        )}
        {railOpen && <Splitter invert label="Resize the side panel" value={railSize} min={180} max={640} onChange={setRailWidth} style={{ right: railSize }} />}
      </div>
      {wordStyle}
      {peekCard}{varBox}
    </div>
  );
}
