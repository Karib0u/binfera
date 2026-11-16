/** What the bytes at an offset mean as numbers, times, a GUID and text, in both byte orders. */

export type Row = { label: string; le: string | null; be: string | null; single?: boolean };

const FILETIME_EPOCH = 11644473600n; // seconds between 1601 and 1970
const iso = (ms: number) => {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().replace(".000Z", "Z").replace("T", " ");
};
const hex2 = (b: number) => b.toString(16).padStart(2, "0");
const num = (v: number | bigint) => (typeof v === "bigint" ? v.toString() : Number.isInteger(v) ? v.toString() : String(v));
const float = (v: number) => (Number.isFinite(v) ? Number(v.toPrecision(9)).toString() : String(v));

function guid(b: Uint8Array, o: number): string | null {
  if (o + 16 > b.length) return null;
  const h = (from: number, to: number, rev: boolean) => {
    const part = Array.from(b.subarray(o + from, o + to), hex2);
    return (rev ? part.reverse() : part).join("");
  };
  return `${h(0, 4, true)}-${h(4, 6, true)}-${h(6, 8, true)}-${h(8, 10, false)}-${h(10, 16, false)}`.toUpperCase();
}

function text(b: Uint8Array, o: number, wide: boolean): string | null {
  const out: string[] = [];
  const step = wide ? 2 : 1;
  for (let i = o; i + step <= b.length && out.length < 40; i += step) {
    const c = wide ? b[i] | (b[i + 1] << 8) : b[i];
    if (c === 0) break;
    if (c < 0x20 || c > 0x7e) { if (!out.length) return null; out.push("·"); continue; }
    out.push(String.fromCharCode(c));
  }
  return out.length >= 2 ? out.join("") : null;
}

export function inspect(bytes: Uint8Array, off: number): Row[] {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const room = bytes.length - off;
  const both = <T,>(size: number, read: (little: boolean) => T, show: (v: T) => string): Pick<Row, "le" | "be"> =>
    room >= size ? { le: show(read(true)), be: show(read(false)) } : { le: null, be: null };
  const rows: Row[] = [
    { label: "uint8", single: true, le: room >= 1 ? num(dv.getUint8(off)) : null, be: null },
    { label: "int8", single: true, le: room >= 1 ? num(dv.getInt8(off)) : null, be: null },
    { label: "uint16", ...both(2, (l) => dv.getUint16(off, l), num) },
    { label: "int16", ...both(2, (l) => dv.getInt16(off, l), num) },
    { label: "uint32", ...both(4, (l) => dv.getUint32(off, l), num) },
    { label: "int32", ...both(4, (l) => dv.getInt32(off, l), num) },
    { label: "uint64", ...both(8, (l) => dv.getBigUint64(off, l), num) },
    { label: "int64", ...both(8, (l) => dv.getBigInt64(off, l), num) },
    { label: "float32", ...both(4, (l) => dv.getFloat32(off, l), float) },
    { label: "float64", ...both(8, (l) => dv.getFloat64(off, l), float) },
    { label: "hex u32", ...both(4, (l) => dv.getUint32(off, l), (v) => "0x" + v.toString(16)) },
  ];
  if (room >= 1) rows.push({ label: "binary", single: true, le: dv.getUint8(off).toString(2).padStart(8, "0"), be: null });
  rows.push({
    label: "Unix time",
    ...both(4, (l) => dv.getUint32(off, l), (v) => (v > 315532800 && v < 4102444800 ? iso(v * 1000) : null) as string),
  });
  rows.push({
    label: "FILETIME",
    ...both(8, (l) => dv.getBigUint64(off, l), (v) => {
      const secs = v / 10000000n - FILETIME_EPOCH;
      return (secs > 315532800n && secs < 4102444800n ? iso(Number(secs) * 1000) : null) as string;
    }),
  });
  rows.push({ label: "GUID", single: true, le: guid(bytes, off), be: null });
  rows.push({ label: "ASCII", single: true, le: text(bytes, off, false), be: null });
  rows.push({ label: "UTF-16", single: true, le: text(bytes, off, true), be: null });
  return rows.filter((r) => r.le !== null || r.be !== null);
}
