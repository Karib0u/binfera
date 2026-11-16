import { useMemo } from "react";
import { entropyProfile, entropyWord } from "../engine/entropy";
import type { ImageInfo } from "../engine/image";

/** CSS colour for one entropy value: cool and faint when sparse, warm and strong when it looks packed. */
export function heat(e: number): string {
  if (e >= 7) return `color-mix(in srgb, var(--err) ${Math.round(55 + (e - 7) * 45)}%, var(--soft))`;
  return `color-mix(in srgb, var(--c-fn) ${Math.round((e / 7) * 75)}%, var(--soft))`;
}

/** The whole file as one row of entropy blocks, with the cursor and the visible window marked. Click or drag to jump. */
export function EntropyStrip({ image, cursorOff, viewOff, onPick }: { image: ImageInfo; cursorOff: number | null; viewOff?: number | null; onPick: (off: number) => void }) {
  const cells = 160;
  const profile = useMemo(() => entropyProfile(image.bytes, cells), [image]);
  const total = image.bytes.length;
  if (!total) return null;
  const at = (e: React.PointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    onPick(Math.min(total - 1, Math.max(0, Math.floor(((e.clientX - r.left) / r.width) * total))));
  };
  const marker = (off: number | null | undefined, cls: string) => off === null || off === undefined ? null : <i className={cls} style={{ left: `${(off / total) * 100}%` }} aria-hidden />;
  return (
    <div className="entropy-strip" role="img" aria-label="Byte entropy across the file"
      onPointerDown={(e) => { e.currentTarget.setPointerCapture(e.pointerId); at(e); }}
      onPointerMove={(e) => { if (e.buttons & 1) at(e); }}>
      <div className="es-cells">
        {Array.from(profile.values, (v, i) => <i key={i} style={{ background: heat(v) }} title={`${"0x" + (i * profile.block).toString(16)} · entropy ${v.toFixed(2)} · ${entropyWord(v)}`} />)}
      </div>
      {marker(viewOff, "es-view")}
      {marker(cursorOff, "es-cur")}
    </div>
  );
}
