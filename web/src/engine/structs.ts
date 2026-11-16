import type { StructField, Structure } from "./image";

/** One header field as a byte range of the file, for painting over the hex view. */
export interface Span { start: number; end: number; field: StructField; structure: Structure; index: number }

/** Every field of every header as file ranges, in file order. */
export function buildSpans(structures: Structure[]): Span[] {
  const spans: Span[] = [];
  for (const structure of structures) structure.fields.forEach((field) => { if (field.size > 0) spans.push({ start: field.off, end: field.off + field.size, field, structure, index: 0 }); });
  spans.sort((x, y) => x.start - y.start || x.end - y.end);
  // Alternate by position so neighbours never share a colour.
  spans.forEach((s, i) => { s.index = i; });
  return spans;
}

/** The field covering a file offset, preferring the tightest when headers nest. */
export function spanAt(spans: Span[], off: number): Span | undefined {
  let lo = 0, hi = spans.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (spans[mid].start <= off) lo = mid + 1; else hi = mid; }
  let best: Span | undefined;
  for (let i = lo - 1; i >= 0 && i >= lo - 16; i--) {
    const s = spans[i];
    if (s.end > off && (!best || s.end - s.start < best.end - best.start)) best = s;
  }
  return best;
}
