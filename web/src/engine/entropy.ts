/** Byte entropy of a file in fixed blocks, computed on the page from bytes it already holds. */

export interface EntropyProfile {
  /** Bytes covered by each value except possibly the last. */
  block: number;
  /** Bits per byte, 0 to 8. */
  values: Float32Array;
}

/** Shannon entropy of `bytes[start, end)` in bits per byte. Reads at most about `limit` bytes, evenly strided. */
export function entropyOf(bytes: Uint8Array, start: number, end: number, limit = 1 << 20): number {
  end = Math.min(end, bytes.length);
  if (end <= start) return 0;
  const stride = Math.max(1, Math.ceil((end - start) / limit));
  const counts = new Uint32Array(256);
  let n = 0;
  for (let i = start; i < end; i += stride) { counts[bytes[i]]++; n++; }
  let e = 0;
  for (let i = 0; i < 256; i++) if (counts[i]) { const p = counts[i] / n; e -= p * Math.log2(p); }
  return e;
}

const cache = new WeakMap<Uint8Array, Map<number, EntropyProfile>>();

/** `cells` blocks across the whole file. Cached per byte array. */
export function entropyProfile(bytes: Uint8Array, cells: number): EntropyProfile {
  let byCells = cache.get(bytes);
  if (!byCells) cache.set(bytes, byCells = new Map());
  const hit = byCells.get(cells);
  if (hit) return hit;
  const block = Math.max(1, Math.ceil(bytes.length / cells));
  const count = Math.max(1, Math.ceil(bytes.length / block));
  const values = new Float32Array(count);
  for (let i = 0; i < count; i++) values[i] = entropyOf(bytes, i * block, (i + 1) * block, 16384);
  const profile = { block, values };
  byCells.set(cells, profile);
  return profile;
}

/** Above this a block is almost certainly compressed or encrypted. */
export const HIGH_ENTROPY = 7;

export const entropyWord = (e: number) =>
  e >= 7.5 ? "encrypted or compressed" : e >= HIGH_ENTROPY ? "likely compressed" : e >= 5.5 ? "dense code or data" : e >= 3 ? "typical code or data" : e > 0.5 ? "sparse" : "empty or padding";
