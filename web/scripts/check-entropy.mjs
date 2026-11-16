// The entropy map and the data inspector tell an analyst what bytes are; their arithmetic is pinned here.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const load = async (name) => {
  const source = await readFile(new URL(`../src/engine/${name}.ts`, import.meta.url), "utf8");
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
  return import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);
};
const { entropyOf, entropyProfile, entropyWord } = await load("entropy");
const { inspect } = await load("inspect");
const { buildSpans, spanAt } = await load("structs");

// Constant bytes carry no information; all 256 values equally often carry eight bits each.
assert.equal(entropyOf(new Uint8Array(4096), 0, 4096), 0);
const uniform = Uint8Array.from({ length: 4096 }, (_, i) => i % 256);
assert.ok(Math.abs(entropyOf(uniform, 0, 4096) - 8) < 1e-9);
assert.ok(Math.abs(entropyOf(Uint8Array.from({ length: 1000 }, (_, i) => i % 2), 0, 1000) - 1) < 1e-9);
assert.equal(entropyOf(uniform, 10, 10), 0);
assert.equal(entropyOf(uniform, 4000, 9999), entropyOf(uniform, 4000, 4096)); // an end past the file is clamped

// A file that is zeros then random-looking data shows the change at the right block.
const mixed = new Uint8Array(8192);
mixed.set(uniform, 4096);
mixed.set(uniform, 0 + 0);
mixed.fill(0, 0, 4096);
const profile = entropyProfile(mixed, 8);
assert.equal(profile.values.length, 8);
assert.ok(profile.values[0] === 0 && profile.values[3] === 0);
assert.ok(profile.values[4] > 7.9 && profile.values[7] > 7.9);
assert.equal(entropyProfile(mixed, 8), profile, "a profile is cached per byte array");
assert.equal(entropyWord(7.9), "encrypted or compressed");
assert.equal(entropyWord(0), "empty or padding");

// Inspector: the same bytes in both orders, a GUID, times and text.
const row = (rows, label) => rows.find((r) => r.label === label);
const bytes = Uint8Array.from([0x78, 0x56, 0x34, 0x12, 0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0, 0, 0, 0, 0]);
const rows = inspect(bytes, 0);
assert.equal(row(rows, "uint32").le, "305419896");
assert.equal(row(rows, "uint32").be, "2018915346");
assert.equal(row(rows, "uint16").le, "22136");
assert.equal(row(rows, "int8").le, "120");
assert.equal(row(rows, "hex u32").le, "0x12345678");
assert.equal(inspect(Uint8Array.from([0xff]), 0).find((r) => r.label === "int8").le, "-1");
// Past the end, the wider types disappear instead of reading garbage.
const tail = inspect(bytes, 14);
assert.ok(row(tail, "uint16") && !row(tail, "uint32") && !row(tail, "uint64"));
// 2021-01-01T00:00:00Z as a Unix time and as a FILETIME.
const unix = new Uint8Array(8); new DataView(unix.buffer).setUint32(0, 1609459200, true);
assert.equal(row(inspect(unix, 0), "Unix time").le, "2021-01-01 00:00:00Z");
const ft = new Uint8Array(8); new DataView(ft.buffer).setBigUint64(0, (1609459200n + 11644473600n) * 10000000n, true);
assert.equal(row(inspect(ft, 0), "FILETIME").le, "2021-01-01 00:00:00Z");
// A GUID is stored with its first three fields little-endian.
const g = Uint8Array.from([0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
assert.equal(row(inspect(g, 0), "GUID").le, "00112233-4455-6677-8899-AABBCCDDEEFF");
assert.equal(row(inspect(Uint8Array.from([0x68, 0x69, 0x21, 0]), 0), "ASCII").le, "hi!");
assert.equal(row(inspect(Uint8Array.from([0x68, 0, 0x69, 0, 0, 0]), 0), "UTF-16").le, "hi");
// Header fields as byte ranges: lookups land on the right field, and a nested header wins over the one around it.
const field = (name, off, size) => ({ name, off, size, value: "0" });
const spans = buildSpans([
  { name: "Outer", off: 0, size: 64, fields: [field("a", 0, 4), field("whole", 4, 40), field("empty", 50, 0)] },
  { name: "Inner", off: 8, size: 8, fields: [field("b", 8, 4)] },
]);
assert.equal(spans.length, 3, "zero-size fields are skipped");
assert.equal(spanAt(spans, 0).field.name, "a");
assert.equal(spanAt(spans, 3).field.name, "a");
assert.equal(spanAt(spans, 5).field.name, "whole");
assert.equal(spanAt(spans, 9).field.name, "b");
assert.equal(spanAt(spans, 12).field.name, "whole");
assert.equal(spanAt(spans, 44), undefined);
assert.equal(spanAt([], 0), undefined);
console.log("entropy, inspector and structure checks passed");
