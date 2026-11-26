import { useMemo, useState } from "react";
import { entropyOf, entropyWord } from "../engine/entropy";
import { buildOriginIndex, type FunctionOriginKind } from "../familyOrigin";
import type { Analysis } from "../types";
import { hex } from "../workspace/labels";
import { heat } from "./EntropyStrip";
import { SectionLegend, sectionKind } from "./SectionLegend";

type Image = NonNullable<Analysis["image"]>;
type Layer = "sections" | "entropy" | "functions" | "origin" | "capabilities" | "imports";

const BASE_LAYERS: [Layer, string][] = [["sections", "Sections"], ["entropy", "Entropy"], ["functions", "Functions"], ["capabilities", "Capabilities"], ["imports", "Imports"]];
const ORIGIN_LAYERS: [Layer, string][] = [["sections", "Sections"], ["origin", "Origin"], ["entropy", "Entropy"], ["functions", "Functions"], ["capabilities", "Capabilities"], ["imports", "Imports"]];
const COLS = 64;
const ROWS = 10;

interface Cell { off: number; end: number; section?: string; kind: string; entropy: number; functions: number[]; caps: number; imports: number; origin: Record<FunctionOriginKind, number>; first?: boolean }

/** Every byte of the file as one tile, coloured by what lives there. Click a tile to see its bytes, or its first function. */
export function FeatureMap({ a, image, onPick, onFn }: { a: Analysis; image: Image; onPick: (va: number) => void; onFn: (address: number) => void }) {
  const [layer, setLayer] = useState<Layer>("sections");
  const [hover, setHover] = useState<number | null>(null);
  const total = image.bytes.length, n = COLS * ROWS;
  const originIndex = useMemo(() => (a.family ? buildOriginIndex(a.family, a.capa?.library) : null), [a.family, a.capa]);
  const layers = a.family ? ORIGIN_LAYERS : BASE_LAYERS;

  const cells = useMemo(() => {
    // The file in order as segments: each section, and the gaps between them (headers, overlay). A segment's share of the tiles
    // grows with the logarithm of its size, so a 3 MB resource section does not hide a 4 KB header.
    type Seg = { off: number; end: number; name?: string; kind: string };
    const secs = image.sections.filter((x) => x.size > 0 && x.off < total).map((x) => ({ off: x.off, end: Math.min(total, x.off + x.size), name: x.name, kind: sectionKind(x), exec: x.perms.includes("x") })).sort((p, q) => p.off - q.off);
    const segs: Seg[] = [];
    let pos = 0;
    for (const x of secs) {
      if (x.off > pos) segs.push({ off: pos, end: x.off, kind: "none" });
      if (x.end > Math.max(pos, x.off)) segs.push({ off: Math.max(pos, x.off), end: x.end, name: x.name, kind: x.kind });
      pos = Math.max(pos, x.end);
    }
    if (pos < total) segs.push({ off: pos, end: total, kind: "none" });
    if (!segs.length) segs.push({ off: 0, end: total, kind: "none" });
    const weight = segs.map((x) => Math.log2((x.end - x.off) / 1024 + 2));
    const sum = weight.reduce((p, q) => p + q, 0);
    const tiles = weight.map((w) => Math.max(3, Math.round((n * w) / sum)));
    const out: Cell[] = [];
    const starts: number[] = [];
    segs.forEach((seg, k) => {
      starts.push(out.length);
      const size = (seg.end - seg.off) / tiles[k];
      for (let i = 0; i < tiles[k]; i++) {
        const off = Math.floor(seg.off + i * size), end = Math.min(seg.end, Math.max(off + 1, Math.floor(seg.off + (i + 1) * size)));
        out.push({ off, end, section: seg.name, kind: seg.kind, entropy: entropyOf(image.bytes, off, end, 16384), functions: [], caps: 0, imports: 0, origin: { malware: 0, shared: 0, unique: 0, trusted: 0 }, first: i === 0 });
      }
    });
    const cellOf = (va: number) => {
      const off = image.vaToOff(va);
      if (off === null) return undefined;
      let lo = 0, hi = segs.length - 1;
      while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (segs[mid].off <= off) lo = mid; else hi = mid - 1; }
      const seg = segs[lo];
      if (off < seg.off || off >= seg.end) return undefined;
      return out[starts[lo] + Math.min(tiles[lo] - 1, Math.floor(((off - seg.off) / (seg.end - seg.off)) * tiles[lo]))];
    };
    for (const ad of a.order) {
      const c = cellOf(ad);
      if (!c) continue;
      c.functions.push(ad);
      const kind = originIndex?.byAddress.get(ad)?.kind;
      if (kind) c.origin[kind]++;
    }
    for (const r of a.capa?.rules ?? []) if (!r.lib) for (const va of r.addresses) { const c = cellOf(va); if (c) c.caps++; }
    for (const i of image.imports) if (i.va) { const c = cellOf(i.va); if (c) c.imports++; }
    return out;
  }, [a.order, a.capa, originIndex, image, n, total]);

  const max = useMemo(() => ({
    functions: Math.max(1, ...cells.map((c) => c.functions.length)),
    capabilities: Math.max(1, ...cells.map((c) => c.caps)),
    imports: Math.max(1, ...cells.map((c) => c.imports)),
  }), [cells]);

  if (!total) return null;
  const tone = (count: number, top: number, color: string) => count ? `color-mix(in srgb, var(${color}) ${Math.round(25 + 75 * Math.sqrt(count / top))}%, var(--soft))` : "var(--soft)";
  const paint = (c: Cell): React.CSSProperties => {
    if (layer === "origin") {
      if (c.origin.malware > 0) return { background: "var(--o-family)" };
      if (c.origin.shared > 0) return { background: "var(--o-shared)" };
      if (c.origin.unique > 0) return { background: "var(--o-unique)" };
      if (c.origin.trusted > 0) return { background: "var(--o-trusted)" };
      return { background: "var(--soft)" };
    }
    if (layer === "entropy") return { background: heat(c.entropy) };
    if (layer === "functions") return { background: tone(c.functions.length, max.functions, "--c-fn") };
    if (layer === "capabilities") return { background: tone(c.caps, max.capabilities, "--c-kw") };
    if (layer === "imports") return { background: tone(c.imports, max.imports, "--c-str") };
    return c.kind === "none" ? { background: "var(--soft)" } : { background: `color-mix(in srgb, var(--section-color) 70%, var(--soft))` };
  };
  const click = (c: Cell) => {
    if ((layer === "functions" || layer === "capabilities" || layer === "origin") && c.functions.length) { onFn(c.functions[0]); return; }
    const va = image.offToVa(c.off) ?? image.offToVa(c.end - 1);
    if (va !== null) onPick(va);
  };
  const describe = (c: Cell) => [
    `${hex(c.off)} to ${hex(c.end)}`, c.section ? `section ${c.section}` : c.kind === "none" ? "outside any section" : "",
    `entropy ${c.entropy.toFixed(2)} (${entropyWord(c.entropy)})`,
    c.functions.length ? `${c.functions.length} function${c.functions.length === 1 ? "" : "s"}` : "",
    c.origin.malware ? `${c.origin.malware} family` : "",
    c.origin.shared ? `${c.origin.shared} common malware` : "",
    c.origin.unique ? `${c.origin.unique} unique` : "",
    c.origin.trusted ? `${c.origin.trusted} library` : "",
    c.caps ? `${c.caps} capability match${c.caps === 1 ? "" : "es"}` : "", c.imports ? `${c.imports} import slot${c.imports === 1 ? "" : "s"}` : "",
  ].filter(Boolean).join(" · ");
  const h = hover === null ? null : cells[hover];

  return (
    <section className="ov-card feature-map">
      <header>
        <h2>File map</h2>
        <div className="fm-layers" role="group" aria-label="Map layer">
          {layers.map(([k, name]) => <button key={k} aria-pressed={layer === k} className={layer === k ? "on" : ""} onClick={() => setLayer(k)}>{name}</button>)}
        </div>
      </header>
      <div className="fm-grid" style={{ gridTemplateColumns: `repeat(${COLS}, 1fr)` }} onPointerLeave={() => setHover(null)}>
        {cells.map((c, i) => (
          <button key={i} className={"fm-cell section-" + c.kind + (hover === i ? " hot" : "") + (c.first ? " seg" : "")} style={paint(c)} aria-label={describe(c)}
            onPointerEnter={() => setHover(i)} onFocus={() => setHover(i)} onClick={() => click(c)} />
        ))}
      </div>
      {layer === "sections" && <SectionLegend sections={image.sections} />}
      {layer === "origin" && (
        <div className="fm-sections" aria-label="Code origin legend">
          <span><i className="co-malware" />Family</span>
          <span><i className="co-shared" />Common malware</span>
          <span><i className="co-unique" />Unique</span>
          <span><i className="co-trusted" />Library</span>
        </div>
      )}
      <p className="fm-readout" role="status" aria-live="polite">{h ? describe(h) : layer === "origin" ? "Where each kind of code sits in the file. Dark tiles hold unique code: reverse those first." : layer === "entropy" ? "Warm tiles are compressed or encrypted bytes. Left to right is file order." : "File order, left to right; tile area is scaled by log size so small sections stay visible. Hover a tile; click to open it."}</p>
    </section>
  );
}
