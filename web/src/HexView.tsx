import { useEffect, useMemo, useRef, useState } from "react";
import type { ImageInfo } from "./engine/image";
import { sectionKind } from "./views/SectionLegend";
import { EntropyStrip } from "./views/EntropyStrip";
import { DataInspector } from "./views/DataInspector";
import { buildSpans, spanAt } from "./engine/structs";
import { useMobile } from "./workspace/useMobile";

const hex = (n: number, pad = 0) => n.toString(16).padStart(pad, "0");

export interface HexSelection { va: number; len: number }

/** The raw file, sixteen bytes a row, with the section map beside it. The cursor is a virtual address shared with the code views. */
export default function HexView({ image, cursor, tick, selection, onCursor, strAt, owner, onOpenCode, xrefCount, onXrefs, compact }: {
  /** Without the section list: the Data explorer lists sections itself. */
  compact?: boolean;
  xrefCount: (va: number) => number; onXrefs: (va: number) => void;
  image: ImageInfo; cursor: number | null; tick: number; selection: HexSelection | null;
  onCursor: (va: number) => void; strAt: (va: number) => string | undefined;
  /** The function containing an address, with its display name. */
  owner: (va: number) => { address: number; label: string } | undefined;
  onOpenCode: (va: number) => void;
}) {
  // A phone shows eight bytes a row, larger, so the ASCII column and every byte fit and can be tapped.
  const mobile = useMobile();
  const WIDTH = mobile ? 8 : 16, ROW = mobile ? 30 : 20;
  const box = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0), [height, setHeight] = useState(600);
  const [inspecting, setInspecting] = useState(() => { try { return localStorage.getItem("binfera.inspector") === "1"; } catch { return false; } });
  const [structs, setStructs] = useState(() => { try { return localStorage.getItem("binfera.structs") !== "0"; } catch { return true; } });
  const toggleStructs = () => setStructs((on) => { try { localStorage.setItem("binfera.structs", on ? "0" : "1"); } catch { /* storage unavailable */ } return !on; });
  const spans = useMemo(() => buildSpans(image.details?.structures ?? []), [image]);
  const toggleInspector = () => setInspecting((on) => { try { localStorage.setItem("binfera.inspector", on ? "0" : "1"); } catch { /* storage unavailable */ } return !on; });
  const rows = Math.ceil(image.bytes.length / WIDTH);
  const cursorOff = cursor === null ? null : image.vaToOff(cursor);
  const selOff = selection ? image.vaToOff(selection.va) : null;
  const sec = cursor === null ? undefined : image.sectionAt(cursor);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => setHeight(el.clientHeight);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Bring the cursor into view unless its row is already showing.
  useEffect(() => {
    const el = box.current, off = selOff ?? cursorOff;
    if (!el || off === null) return;
    const y = Math.floor(off / WIDTH) * ROW;
    if (y < el.scrollTop + ROW || y > el.scrollTop + el.clientHeight - 2 * ROW) { el.scrollTop = Math.max(0, y - el.clientHeight / 3); setTop(el.scrollTop); }
  }, [cursorOff, selOff, selection, tick, WIDTH, ROW]);

  const first = Math.max(0, Math.floor(top / ROW) - 6), last = Math.min(rows, Math.ceil((top + height) / ROW) + 6);
  /** The entropy strip reaches bytes outside every mapping, so it scrolls itself and moves the cursor only where there is an address. */
  const jumpOff = (off: number) => {
    const el = box.current;
    if (el) { el.scrollTop = Math.max(0, Math.floor(off / WIDTH) * ROW - el.clientHeight / 3); setTop(el.scrollTop); }
    const va = image.offToVa(off);
    if (va !== null) onCursor(va);
  };
  const onClick = (e: React.MouseEvent) => {
    const o = (e.target as HTMLElement).dataset.o;
    if (o === undefined) return;
    const va = image.offToVa(Number(o));
    if (va !== null) onCursor(va);
  };
  const onKey = (e: React.KeyboardEvent) => {
    const step = ({ ArrowLeft: -1, ArrowRight: 1, ArrowUp: -WIDTH, ArrowDown: WIDTH } as Record<string, number>)[e.key];
    if (!step) return;
    e.preventDefault();
    const va = image.offToVa(Math.min(image.bytes.length - 1, Math.max(0, (cursorOff ?? 0) + step)));
    if (va !== null) onCursor(va);
  };
  const inSel = (o: number) => selOff !== null && selection !== null && o >= selOff && o < selOff + selection.len;

  const out = [];
  for (let r = first; r < last; r++) {
    const base = r * WIDTH, va = image.offToVa(base);
    const cells = [], chars = [];
    for (let c = 0; c < WIDTH && base + c < image.bytes.length; c++) {
      const o = base + c, b = image.bytes[o];
      const sp = structs ? spanAt(spans, o) : undefined;
      const cls = (o === cursorOff ? " cur" : "") + (inSel(o) ? " sel" : "") + (b === 0 ? " zero" : "") + (sp ? ` fld f${sp.index % 4}${o === sp.start ? " fs" : ""}${o === sp.end - 1 ? " fe" : ""}` : "");
      cells.push(<span key={c} data-o={o} className={"hb" + cls}>{hex(b, 2)}</span>);
      chars.push(<span key={c} data-o={o} className={"hc" + cls}>{b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."}</span>);
    }
    out.push(
      <div className="hrow" key={r} style={{ top: r * ROW, height: ROW }}>
        <code className="ha">{va !== null ? hex(va, 8) : "·· " + hex(base, 6)}</code>
        <code className="hbytes">{cells}</code>
        <code className="hchars">{chars}</code>
      </div>,
    );
  }

  const fn = cursor === null ? undefined : owner(cursor);
  const str = cursor === null ? undefined : strAt(cursor);
  const u32 = cursorOff !== null && cursorOff + 4 <= image.bytes.length ? new DataView(image.bytes.buffer, image.bytes.byteOffset).getUint32(cursorOff, image.littleEndian) : null;
  const sections = useMemo(() => image.sections, [image]);
  const field = structs && cursorOff !== null ? spanAt(spans, cursorOff) : undefined;

  return (
    <div className={"hex" + (compact ? " compact" : "") + (mobile ? " m" : "")}>
      {!compact && <div className="hex-secs">
        <h3>Sections</h3>
        {sections.length === 0 && <p className="fine">No section table.</p>}
        {sections.map((s) => {
          const packed = s.entropy >= 7;
          return (
            <button key={s.name + s.off} className={"hsec section-" + sectionKind(s) + (sec === s ? " on" : "")} disabled={image.vaToOff(s.va) === null} onClick={() => onCursor(s.va)}>
              <b>{s.name || "(unnamed)"}</b>
              <code>{hex(s.va)}</code>
              <small>{hex(Math.max(s.vsize, s.size))} · {s.perms}</small>
              <span className="ent" title={`entropy ${s.entropy.toFixed(2)}`}><i style={{ width: `${(s.entropy / 8) * 100}%` }} className={packed ? "hi" : ""} /></span>
              {packed && <small className="packed-tag">high entropy</small>}
            </button>
          );
        })}
      </div>}
      <div className="hex-main">
        <EntropyStrip image={image} cursorOff={selOff ?? cursorOff} viewOff={Math.min(image.bytes.length, Math.floor(top / ROW) * WIDTH)} onPick={jumpOff} />
        <div className="hex-scroll" ref={box} tabIndex={0} aria-label="File bytes" onKeyDown={onKey} onScroll={(e) => setTop(e.currentTarget.scrollTop)} onClick={onClick}>
          <div style={{ height: rows * ROW, position: "relative" }}>{out}</div>
        </div>
        {inspecting && cursorOff !== null && <DataInspector bytes={image.bytes} off={cursorOff} />}
        <div className="hex-foot">
          {cursor === null ? <span>Click a byte, a string or an address to place the cursor.</span> : (
            <>
              <div className="hf-info">
                <code>{"0x" + hex(cursor)}</code>
                {cursorOff !== null && <span>file offset <code>{"0x" + hex(cursorOff)}</code></span>}
                {sec && <span>section <code>{sec.name}</code></span>}
                {u32 !== null && <span>u32 <code>{"0x" + hex(u32)}</code></span>}
                {field && <span className="hfield"><b>{field.structure.name}</b> › {field.field.name} = <code>{field.field.value}</code>{field.field.note ? ` · ${field.field.note}` : ""}{field.field.target !== undefined && image.vaToOff(field.field.target) !== null && <> <button className="ghost" onClick={() => onCursor(field.field.target!)}>→ {"0x" + hex(field.field.target)}</button></>}</span>}
                {str && <span className="hs">“{str.length > 50 ? str.slice(0, 50) + "…" : str}”</span>}
              </div>
              <div className="hf-actions">
                {xrefCount(cursor) > 0 && <button className="ghost" onClick={() => onXrefs(cursor)}>{xrefCount(cursor)} reference{xrefCount(cursor) === 1 ? "" : "s"}</button>}
                {fn && <button className="ghost" onClick={() => onOpenCode(cursor)}>In {fn.label} · open code</button>}
                {spans.length > 0 && <button className="ghost" aria-pressed={structs} onClick={toggleStructs} title="Colour the bytes of file headers by field">{structs ? "Hide structures" : "Structures"}</button>}
                <button className="ghost" aria-pressed={inspecting} onClick={toggleInspector}>{inspecting ? "Hide inspector" : "Inspector"}</button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
