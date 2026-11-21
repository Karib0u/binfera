import { useImperativeHandle, useMemo, useRef, type Ref } from "react";
import VirtualList, { type VirtualListHandle } from "./workspace/VirtualList";
import { revealIn } from "./workspace/panels";
import { ArrowPaths, gutterWidth, type Arrow } from "./BranchArrows";
import { ADDR_IN_ASM, asmAddress, operandNote, rowFlow, type Arch } from "./graph";
import { importKey, tokenized, tokKey } from "./highlight";
import { useNotes } from "./names";

const ROW = 20, VIRTUAL_THRESHOLD = 1500;

export interface AsmHandle { scrollToAddress: (address: number, center?: boolean) => void }

/** Assembly listing; branch/call targets link to functions and string addresses show the string. */
export default function Asm({ rows, self, resolve, onGoto, strAt, textAt, label, active, onPick, capAt, isData, onData, slot, onImport, labels, focusable, arrows, arch, onCode, scrollRef, argNotes }: {
  scrollRef?: Ref<AsmHandle>;
  /** The call arguments an instruction sets up and the stack symbols it uses, by address (`annotations.ts`). */
  argNotes?: Map<number, string>;
  /** Reads which address is a branch target: it goes to code, never to the hex view. */
  arch: Arch;
  /** A branch target outside these rows. */
  onCode: (va: number) => void;
  /** Branch arrows beside the rows, which then have a fixed height. */
  arrows?: Arrow[];
  /** A whole function's listing: focus it and the arrow keys move the selected instruction. */
  focusable?: boolean;
  labels?: Record<string, string>;
  /** The import a pointer-slot address holds, so `call [0x140003330]` reads as the API it calls. */
  slot?: (va: number) => { name: string; dll: string } | undefined; onImport?: (name: string) => void;
  active: Set<number>; onPick: (ad: number) => void;
  /** Capability names matched at an instruction address. */
  capAt: Map<number, string[]>; isData: (ad: number) => boolean; onData: (ad: number) => void;
  label: (ad: number) => string;
  rows: [number, string, string][]; self: number;
  resolve: (t: string) => number | undefined; onGoto: (ad: number) => void; strAt: (ad: number) => string | undefined;
  /** Text at a data address that the strings list leaves out. */
  textAt?: (ad: number) => string | undefined;
}) {
  const box = useRef<HTMLDivElement>(null), list = useRef<VirtualListHandle>(null);
  const windowed = rows.length > VIRTUAL_THRESHOLD;
  const rowOf = useMemo(() => new Map(rows.map((r, i) => [r[0], i])), [rows]);
  const scrollToAddress = (ad: number, center = false) => {
    const index = rowOf.get(ad);
    if (index === undefined) return;
    if (windowed) list.current?.scrollToIndex(index, center);
    else revealIn(box.current?.closest<HTMLElement>(".cp-pane"), `[data-addr="${ad}"]`, center);
  };
  useImperativeHandle(scrollRef, () => ({ scrollToAddress }));
  const pick = (ad: number) => { onPick(ad); scrollToAddress(ad); };
  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.target !== e.currentTarget || (e.key !== "ArrowDown" && e.key !== "ArrowUp")) return;
    e.preventDefault();
    const now = rows.findIndex((r) => active.has(r[0]));
    const next = rows[now < 0 ? 0 : Math.min(rows.length - 1, Math.max(0, now + (e.key === "ArrowDown" ? 1 : -1)))];
    if (next) pick(next[0]);
  };
  const notes = useNotes();
  const lanes = arrows?.length ? Math.max(...arrows.map((r) => r.lane)) + 1 : 0, gutter = gutterWidth(lanes);
  const renderRow = ([ad, bytes, text]: [number, string, string], index: number) => {
    const flow = rowFlow([ad, bytes, text], arch);
    const branch = flow.kind === "jump" || flow.kind === "cond" || flow.kind === "call" ? flow.target : undefined;
    const sp = text.indexOf(" ");
    const mnem = sp < 0 ? text : text.slice(0, sp), ops = sp < 0 ? "" : text.slice(sp);
    const parts: React.ReactNode[] = [];
    let last = 0, k = 0, note: string | undefined;
    for (const m of ops.matchAll(ADDR_IN_ASM)) {
      const v = asmAddress(m), target = resolve("0x" + v.toString(16));
      parts.push(<span key={k++}>{tokenized(ops.slice(last, m.index))}</span>);
      const lit = "0x" + v.toString(16);
      parts.push(target !== undefined && target !== self
        ? <a key={k++} href={"#" + lit} className="xref tk-f" data-tok={tokKey(label(target))} data-fn={target} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onGoto(target); }}>{label(target)}</a>
        : slot?.(v)
          ? <a key={k++} href={"#" + lit} className="xref tk-f" data-tok={importKey(slot(v)!)} title={slot(v)!.dll + " · " + lit} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onImport?.(slot(v)!.name); }}>{slot(v)!.name}</a>
        : v === branch
          ? <a key={k++} href={"#" + lit} className="xref tk-n" data-tok={tokKey(lit)} title="Go to this instruction" onClick={(e) => {
              e.preventDefault(); e.stopPropagation();
              if (!rowOf.has(v)) { onCode(v); return; }
              pick(v);
            }}>{lit}</a>
        : isData(v)
          ? <a key={k++} href={"#" + lit} className="xref tk-n" data-tok={tokKey(lit)} title="Show in the Listing" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onData(v); }}>{lit}</a>
          : <span key={k++} className="tk-n" data-tok={tokKey(lit)}>{lit}</span>);
      last = m.index! + m[0].length;
      note ??= operandNote(text, sp + m.index!, v, strAt, v === branch ? undefined : textAt);
    }
    parts.push(<span key={k++}>{tokenized(ops.slice(last))}</span>);
    return (
      <div className={"insn" + (active.has(ad) ? " hl" : "")} key={index} data-addr={ad} onClick={() => onPick(ad)}>
        <code className="ia">{ad.toString(16).padStart(8, "0")}</code>
        <code className="ib">{bytes}</code>
        <code className="it">{labels?.[ad] && <span className="tk-f">{labels[ad]}: </span>}<span className="tk-k" data-tok={mnem}>{mnem}</span>{parts}{argNotes?.get(ad) && <span className="tk-c tk-arg">  ; {argNotes.get(ad)}</span>}{note && <span className="tk-c">  ; {JSON.stringify(note.length > 60 ? note.slice(0, 60) + "…" : note)}</span>}{capAt.has(ad) && <span className="tk-cap">  ; capa: {capAt.get(ad)!.join(", ")}</span>}{ad !== self && notes.commentAt(ad) && <span className="tk-c ucm" title={notes.commentAt(ad)}>  ; {notes.commentAt(ad, true)}</span>}</code>
      </div>
    );
  };
  const arrowRows = useMemo(() => arrows?.map((r) => ({ ...r, y1: rowOf.get(r.from)! * ROW + ROW / 2, y2: rowOf.get(r.to)! * ROW + ROW / 2 })) ?? [], [arrows, rowOf]);
  const renderArrows = (top: number, height: number) => gutter > 0 && (
    <svg className="arrows" style={windowed ? { left: -gutter } : undefined} width={gutter} height={rows.length * ROW} aria-hidden>
      <ArrowPaths width={gutter} active={active} arrows={arrowRows} visible={windowed ? { top: top - ROW * 6, bottom: top + height + ROW * 6 } : undefined} onPick={pick} />
    </svg>
  );
  return (
    <div ref={box} className={"asm" + (arrows ? " with-arrows" : "") + (windowed ? " asm-windowed" : "")} style={gutter ? { paddingLeft: gutter } : undefined} tabIndex={focusable ? 0 : undefined} aria-label={focusable ? "Assembly" : undefined} onKeyDown={focusable ? onKey : undefined}>
      {windowed
        ? <VirtualList items={rows} rowHeight={ROW} render={renderRow} listRef={list} scrollParent=".cp-pane" overlay={renderArrows} />
        : <>{renderArrows(0, rows.length * ROW)}{rows.map(renderRow)}</>}
    </div>
  );
}
