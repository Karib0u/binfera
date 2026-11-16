import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypes } from "./strip-types.mjs";

const source = stripTypes(await readFile(new URL("../src/engine/shellcode.ts", import.meta.url), "utf8"));
const { decodeShellcodeInput, shellcodePayload } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
const bytes = s => new TextEncoder().encode(s).buffer;
const expected = [0x31, 0xc0, 0xc3];
for (const text of ["31c0c3", "31 c0\nc3", "0x31, 0xc0, 0xc3", "{0x31,0xc0,0xc3,}", "[0x31, 0xc0, 0xc3]", "unsigned char buf[] = {0x31, 0xc0, 0xc3};"]) {
  const result = decodeShellcodeInput(bytes(text));
  assert.equal(result.encoding, "hex text", text);
  assert.deepEqual([...new Uint8Array(result.bytes)], expected, text);
}
for (const text of [String.raw`\x31\xc0\xc3`, String.raw`b"\x31\xc0\xc3"`, String.raw`unsigned char buf[] = "\x31\xc0" "\xc3";`, String.raw`payload = b'\x31\xc0\xc3'`]) {
  const result = decodeShellcodeInput(bytes(text));
  assert.equal(result.encoding, "escaped hex", text);
  assert.deepEqual([...new Uint8Array(result.bytes)], expected, text);
}
for (const text of ["hello world", "31c0c", "31 c0 zz", "0x31, calc()", String.raw`"\x31\xzz"`, String.raw`b"\x31" + open("secret")`, "0x31,,0xc0"]) {
  assert.equal(decodeShellcodeInput(bytes(text)).encoding, "binary", text);
}
const raw = Uint8Array.from(expected).buffer;
assert.equal(decodeShellcodeInput(raw).bytes, raw);
const payload = shellcodePayload(bytes("00 00 31 c0 c3"), 2);
assert.deepEqual([...new Uint8Array(payload.bytes)], expected);
assert.equal(payload.inputSize, 5);
for (const offset of [-1, 0.5, 5, NaN, Infinity]) assert.throws(() => shellcodePayload(bytes("00 00 31 c0 c3"), offset));
console.log("Binary, hex, escaped literals, skipped prefixes and malformed input handling: passed");
