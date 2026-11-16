import type { Analysis } from "../types";
import { hex, bytes } from "../workspace/labels";
import { sectionKind, SectionLegend } from "./SectionLegend";

/** The section table with its permissions legend and entropy bars; a part of the File page. */
export function SectionsList({ image, cursor, onPick }: { image: NonNullable<Analysis["image"]>; cursor: number | null; onPick: (va: number) => void }) {
  const cur = cursor === null ? undefined : image.sectionAt(cursor);
  return (
    <div className="sec-list">
      <SectionLegend sections={image.sections} />
      {image.sections.length === 0 && <p className="empty">No section table in this file.</p>}
      {image.sections.map((s) => (
        <button key={s.name + s.off} className={"sec-row section-" + sectionKind(s) + (cur === s ? " on" : "")} disabled={image.vaToOff(s.va) === null} title={image.vaToOff(s.va) === null ? "No file bytes mapped at this address" : "Show section bytes"} onClick={() => onPick(s.va)}>
          <b>{s.name || "(unnamed)"}</b>
          <code>{hex(s.va)}</code>
          <span>{bytes(Math.max(s.size, s.vsize))} · {s.perms}{image.vaToOff(s.va) === null ? " · no mapped bytes" : ""}</span>
          <span className="ent"><i style={{ width: `${(s.entropy / 8) * 100}%` }} className={s.entropy >= 7 ? "hi" : ""} /></span>
          <small>{s.entropy.toFixed(2)}{s.entropy >= 7 ? " · high entropy" : ""}</small>
        </button>
      ))}
    </div>
  );
}
