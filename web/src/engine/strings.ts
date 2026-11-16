import type { StringEntry } from "../types";
import type { ImageInfo } from "./image";

const MAX_STRINGS = 20000;
const MIN = 5;
const printable = (c: number) => (c >= 0x20 && c < 0x7f) || c === 9;

/** ASCII and UTF-16LE strings (>= 5 chars) mapped to virtual addresses via the PE, ELF or Mach-O load map. */
export function extractStrings(buf: Uint8Array, image: ImageInfo): { strings: StringEntry[]; total: number } {
  const out: StringEntry[] = [];
  const push = (off: number, text: string, w: boolean) => {
    // Drop machine code and padding that happens to be printable: needs mostly alphanumerics and a 3-letter run.
    const alnum = (text.match(/[A-Za-z0-9]/g) ?? []).length;
    if (alnum / text.length < 0.4 || !/[A-Za-z]{3}/.test(text)) return;
    const a = image.offToVa(off);
    if (a !== null) out.push({ a, s: text.length > 400 ? text.slice(0, 400) + "…" : text, w });
  };
  const latin1 = new TextDecoder("latin1"), utf16 = new TextDecoder("utf-16le");

  for (let i = 0; i < buf.length;) {
    let j = i;
    while (j < buf.length && printable(buf[j])) j++;
    if (j - i >= MIN) push(i, latin1.decode(buf.subarray(i, j)), false);
    i = j + 1;
  }
  for (let i = 0; i + 1 < buf.length;) {
    let j = i;
    while (j + 1 < buf.length && buf[j + 1] === 0 && printable(buf[j])) j += 2;
    if ((j - i) / 2 >= MIN) push(i, utf16.decode(buf.subarray(i, j)), true);
    i = j > i ? j : i + 1;
  }
  return { strings: out.sort((x, y) => x.a - y.a).slice(0, MAX_STRINGS), total: out.length };
}

/**
 * The terminated text at an address, for strings the list leaves out as too short or symbolic (`"rb"`, `L"%s\\*"`).
 * Reads one address on demand, so it can accept what would be noise across a whole file. Pointers are refused:
 * with an image base like 0x400000, one in seven has only printable bytes before its terminating zero.
 */
export function textAt(image: ImageInfo, va: number): string | undefined {
  const off = image.vaToOff(va), b = image.bytes;
  if (off === null || off + image.ptrSize > b.length) return undefined;
  const word = new DataView(b.buffer, b.byteOffset + off, image.ptrSize);
  const value = image.ptrSize === 8 ? Number(word.getBigUint64(0, image.littleEndian)) : word.getUint32(0, image.littleEndian);
  if (image.vaToOff(value) !== null) return undefined;
  const wide = b[off + 1] === 0 && b[off + 3] === 0, step = wide ? 2 : 1;
  let end = off;
  while (end + step < b.length && (end - off) / step < 400 && (printable(b[end]) || b[end] === 10 || b[end] === 13) && (!wide || b[end + 1] === 0)) end += step;
  if ((end - off) / step < 2 || b[end] !== 0 || (wide && b[end + 1] !== 0)) return undefined;
  const text = new TextDecoder(wide ? "utf-16le" : "latin1").decode(b.subarray(off, end));
  return /[A-Za-z0-9]/.test(text) ? text : undefined;
}
