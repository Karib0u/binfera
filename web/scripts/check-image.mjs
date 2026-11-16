// Presentation helpers must use engine metadata and recovered edges without reparsing binaries.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypes } from "./strip-types.mjs";

async function load(path) {
  const source = await readFile(new URL(path, import.meta.url), "utf8");
  const js = stripTypes(source);
  return import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);
}

const { createImage } = await load("../src/engine/image.ts");
const { extractStrings, textAt } = await load("../src/engine/strings.ts");
const { buildCfg, linesWithSetup, operandNote } = await load("../src/graph.ts");

// Header-free input proves these helpers depend on supplied mappings, including slice offsets.
const bytes = new Uint8Array(256);
bytes.set(new TextEncoder().encode("mapped string"), 128);
bytes.set(new TextEncoder().encode("unmapped string"), 16);
const image = createImage(bytes, {
  format: "macho", arch: "x64", fidArch: null, ptrSize: 8, littleEndian: true, warnings: [],
  entry: 0x100000000, imports: [], exports: [],
  regions: [{ off: 128, size: 32, va: 0x100000000 }],
  sections: [{ name: "__TEXT,__cstring", off: 128, size: 32, va: 0x100000000, vsize: 64, perms: "r--", entropy: 0 }],
});
assert.equal(image.vaToOff(0x100000004), 132);
assert.equal(image.offToVa(132), 0x100000004);
assert.equal(image.offToVa(16), null);
assert.equal(image.vaToOff(0x100000020), null); // virtual zero-fill has no file bytes
assert.equal(image.sectionAt(0x100000020)?.name, "__TEXT,__cstring");
assert.deepEqual(extractStrings(bytes, image), { strings: [{ a: 0x100000000, s: "mapped string", w: false }], total: 1 });
const many = new TextEncoder().encode("hello\0".repeat(20005));
const capped = extractStrings(many, { offToVa: off => many.length - off });
assert.equal(capped.total, 20005);
assert.equal(capped.strings.length, 20000);
assert.equal(capped.strings[0].a, 6);
assert.equal(capped.strings.at(-1).a, 120000);

// The decoder identified an indirect edge that cannot be recovered from this listing text.
const rows = [[10, "90", "nop"], [20, "ff20", "jmp qword ptr [rax]"], [30, "c3", "ret"]];
const recovered = {
  blocks: [{ address: 10, instructions: [10, 20] }, { address: 30, instructions: [30] }],
  edges: [{ from: 10, to: 30, kind: "jump" }],
};
const cfg = buildCfg(rows, "x64", recovered);
assert.equal(cfg.blocks.length, 2);
assert.deepEqual(cfg.edges, [{ from: 0, to: 1, kind: "jump" }]);

// Text too short for the strings list, at addresses read one at a time.
const data = new Uint8Array(64);
const put = (at, ...values) => data.set(values, at);
put(0, 0x72, 0x62, 0);                   // "rb"
put(8, 0x25, 0, 0x73, 0, 0, 0);          // L"%s"
put(16, 0x34, 0x12, 0x40, 0);            // the pointer 0x401234, printable up to its zero
put(24, 0x41, 0);                        // one character
put(32, 0x72, 0x62, 0x80, 0);            // not text to its end
put(40, 0x25, 0x25, 0);                  // no letter or digit
const dataImage = createImage(data, {
  format: "pe", arch: "x86", fidArch: null, ptrSize: 4, littleEndian: true, warnings: [],
  entry: 0x401000, imports: [], exports: [],
  regions: [{ off: 0, size: 64, va: 0x401000 }],
  sections: [{ name: ".data", off: 0, size: 64, va: 0x401000, vsize: 64, perms: "rw-", entropy: 0 }],
});
const text = (at) => textAt(dataImage, 0x401000 + at);
assert.equal(text(0), "rb");
assert.equal(text(8), "%s");
for (const at of [16, 24, 32, 40]) assert.equal(text(at), undefined);

// That text is noted for an address the instruction takes, not for one it loads from.
const never = () => undefined, always = () => "rb", note = (line) => operandNote(line, line.indexOf("41EA50h"), 0x41ea50, never, always);
assert.equal(note("push 41EA50h"), "rb");
assert.equal(note("lea eax,[41EA50h]"), "rb");
assert.equal(note("mov eax,ds:[41EA50h]"), undefined);
assert.equal(operandNote("mov eax,ds:[41EA50h]", 11, 0x41ea50, always, never), "rb"); // a listed string is one either way

// A call's line takes its pushes, past an unrelated statement between them; the rest join the next statement.
const setup = [
  [1, "", "push ebx"], [2, "", "mov eax,[esp+4]"], [3, "", "lea edi,[esp+8]"], [4, "", "push eax"],
  [5, "", "mov ecx,edi"], [6, "", "call 00401000h"], [7, "", "add esp,4"], [8, "", "jmp short 0000000Ah"], [10, "", "ret"],
];
const blocks = {
  blocks: [{ address: 1, instructions: [1, 2, 3, 4, 5, 6, 7, 8] }, { address: 10, instructions: [10] }],
  edges: [{ from: 1, to: 10, kind: "jump" }],
};
assert.deepEqual(linesWithSetup([[], [3], [6], [10]], setup, "x86", blocks), [[], [2, 3], [1, 4, 5, 6, 7, 8], [10]]);
assert.deepEqual(linesWithSetup([[], []], setup, "x86", blocks), [[], []]); // nothing known, nothing guessed
console.log("Engine mappings, mapped strings, operand text, C line instructions and recovered indirect edges: passed");
