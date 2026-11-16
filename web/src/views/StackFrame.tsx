import { useEffect, useMemo, useState } from "react";
import type { Arch, StackSlot } from "../types";
import { hex } from "../workspace/labels";

const signedHex = (n: number) => (n < 0 ? "-" : "+") + "0x" + Math.abs(n).toString(16);

/** The word a call pushes at the entry stack pointer; other architectures keep it in a register. */
const RETURN_SIZE: Partial<Record<NonNullable<Arch>, number>> = { x86: 4, x64: 8 };

type Row = { kind: "slot"; slot: StackSlot } | { kind: "gap"; offset: number; size: number } | { kind: "return"; size: number };

/** Slots by offset, with the return address and the bytes no symbol covers between them. */
function rowsOf(frame: StackSlot[], arch: Arch): Row[] {
  const size = (arch && RETURN_SIZE[arch]) ?? 0;
  const rows: Row[] = [];
  let end: number | undefined;
  const fill = (to: number) => {
    if (end === undefined || to <= end) return;
    // A byte argument still takes a whole pushed word: its padding is not worth a row.
    const last = rows[rows.length - 1];
    if (last?.kind === "slot" && last.slot.parameter && to - end < (size || 4)) return;
    rows.push({ kind: "gap", offset: end, size: to - end });
  };
  let placed = size === 0;
  const place = () => { fill(0); rows.push({ kind: "return", size }); end = Math.max(end ?? 0, size); placed = true; };
  for (const slot of frame) {
    if (!placed && slot.offset >= 0) place();
    fill(slot.offset);
    rows.push({ kind: "slot", slot });
    end = Math.max(end ?? slot.offset, slot.offset + slot.size);
  }
  if (!placed) place();
  return rows;
}

/** What the decompiler knows about the function's stack, by offset from the stack pointer at entry. */
export function StackFrame({ frame, arch, pending, onWord, onInstruction }: {
  frame?: StackSlot[]; arch: Arch; pending: boolean;
  onWord: (name: string) => void; onInstruction: (ad: number) => void;
}) {
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => setOpen(null), [frame]);
  const stack = useMemo(() => (frame ?? []).filter((s) => !s.register), [frame]);
  const registers = useMemo(() => (frame ?? []).filter((s) => s.register), [frame]);
  const rows = useMemo(() => rowsOf(stack, arch), [stack, arch]);
  if (!frame) return <section className="rail-sec"><h3>Stack frame</h3><p className="fine">{pending ? "Waiting for the decompiler" : "No frame data for this function"}</p></section>;
  const locals = stack.filter((s) => s.offset < 0);
  const lowest = locals.length ? -locals[0].offset : 0;
  const slotRow = (s: StackSlot, place: string) => {
    const key = (s.register ?? s.offset) + s.name, isOpen = open === key;
    const kinds = new Map<number, string>();
    for (const [kind, ads] of [["r", s.reads], ["w", s.writes], ["&", s.references]] as const) for (const ad of ads) kinds.set(ad, (kinds.get(ad) ?? "") + kind);
    const uses = [...kinds].map(([ad, kind]) => [kind, ad] as const).sort((x, y) => x[1] - y[1]);
    return (
      <div key={key} className={"frame-slot" + (isOpen ? " on" : "")}>
        <button aria-expanded={isOpen} title={s.type + " " + s.name} onClick={() => { setOpen(isOpen ? null : key); onWord(s.name); if (uses.length) onInstruction(uses[0][1]); }}>
          <code>{place}</code>
          <span className="frame-name">{s.name}{s.parameter && <em>param</em>}</span>
          <small>{s.size}</small>
          <span className="frame-type">{s.type}</span>
        </button>
        {isOpen && (uses.length === 0 ? <p className="fine">No instruction reaches it directly</p> : (
          <ul>{uses.map(([kind, ad]) => <li key={ad}><button title="r read · w write · & address taken" onClick={() => onInstruction(ad)}><b>{kind}</b> {hex(ad)}</button></li>)}</ul>
        ))}
      </div>
    );
  };
  return (
    <section className="rail-sec frame">
      {registers.length > 0 && <>
        <h3>Register arguments</h3>
        <div className="frame-rows frame-regs">{registers.map((s) => slotRow(s, s.register!))}</div>
      </>}
      <h3>Stack frame {lowest > 0 && <small>{hex(lowest)} bytes below entry</small>}</h3>
      {!stack.length ? <p className="fine">No stack variables</p> : <>
      <p className="fine">Offsets from the stack pointer at entry.</p>
      <div className="frame-rows">
        {rows.map((row) => {
          if (row.kind === "return") return <div key="ret" className="frame-mark"><code>+0x0</code><span>return address</span><small>{row.size}</small></div>;
          if (row.kind === "gap") return <div key={"gap" + row.offset} className="frame-mark" title="No symbol covers these bytes: saved registers, alignment or data the decompiler removed"><code>{signedHex(row.offset)}</code><span>unnamed</span><small>{row.size}</small></div>;
          return slotRow(row.slot, signedHex(row.slot.offset));
        })}
      </div>
      </>}
    </section>
  );
}
