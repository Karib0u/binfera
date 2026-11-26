// The Emulate tab's request building and result decoding (src/engine/emulate.ts), then a string
// decryption helper run through the wasm engine with the arguments engine.worker.ts passes.
import assert from "node:assert/strict";
import fs from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { stripTypes } from "./strip-types.mjs";

const source = await readFile(new URL("../src/engine/emulate.ts", import.meta.url), "utf8");
const emu = await import(`data:text/javascript;base64,${Buffer.from(stripTypes(source)).toString("base64")}`);

// Integers: decimal, hex, and negative values as two's complement at the pointer width.
assert.equal(emu.parseWord("0x10", 8), 16n);
assert.equal(emu.parseWord(" 42 ", 4), 42n);
assert.equal(emu.parseWord("", 8), 0n);
assert.equal(emu.parseWord("-1", 4), 0xffffffffn);
assert.equal(emu.parseWord("-1", 8), 0xffffffffffffffffn);
assert.throws(() => emu.parseWord("0x100000000", 4), emu.InputError);
assert.throws(() => emu.parseWord("ten", 8), emu.InputError);

// Buffers: hex pairs, text with byte escapes, UTF-16LE.
assert.deepEqual([...emu.bufferBytes("hex", "32 3f,0x36")], [0x32, 0x3f, 0x36]);
assert.throws(() => emu.bufferBytes("hex", "3"), emu.InputError);
assert.deepEqual([...emu.bufferBytes("utf8", "a\\x00\\xff")], [0x61, 0, 0xff]);
assert.deepEqual([...emu.bufferBytes("utf8", "é€")], [0xc3, 0xa9, 0xe2, 0x82, 0xac]);
assert.deepEqual([...emu.bufferBytes("utf16", "hi")], [0x68, 0, 0x69, 0]);

// Requests: buffers are mapped clear of the image, captured, and their addresses passed; words stay exact.
const sections = [{ va: 0x2000_0000, vsize: 0x1000, size: 0x1000 }];
const built = emu.buildRequest(0x401000, [{ kind: "hex", text: "32 3f" }, { kind: "int", text: "-1" }, { kind: "utf8", text: "ab", size: "4" }], 8, sections);
assert.match(built.json, /"args":\[\d+,18446744073709551615,\d+\]/, "64-bit words are written exactly");
const request = JSON.parse(built.json);
const [first, third] = [built.buffers.get(0), built.buffers.get(2)];
assert.equal(request.address, 0x401000);
assert.equal(request.args[0], first.address);
assert.equal(request.args[2], third.address);
assert.ok(first.address + first.size <= 0x2000_0000 || first.address >= 0x2000_1000, "clear of the section");
assert.deepEqual(request.memory[0].data.slice(0, 3), [0x32, 0x3f, 0]);
assert.equal(request.memory[0].data.length, 2 + 256, "a blank size leaves room for output");
assert.deepEqual(request.memory[1].data, [0x61, 0x62, 0, 0]);
assert.deepEqual(request.capture, [{ address: first.address, size: first.size }, { address: third.address, size: 4 }]);
assert.equal(request.max_steps, emu.LIMITS.max_steps);
assert.throws(() => emu.buildRequest(0, [{ kind: "hex", text: "00 01", size: "1" }], 8, []), /smaller than its input/);
assert.throws(() => emu.buildRequest(0, [{ kind: "hex", text: "", size: String(emu.MAX_BUFFER + 1) }], 8, []), /limited/);
assert.throws(() => emu.buildRequest(0, [{ kind: "int", text: "0x1ffffffff" }], 4, []), /32 bits/);

// Engine JSON: integers past 2^53 survive as digits, strings are left alone.
const parsed = emu.parseExact('{"a":18446744073709551615,"b":12,"s":"x 18446744073709551615 \\" y","n":[-1,2.5]}');
assert.equal(parsed.a, "18446744073709551615");
assert.equal(emu.hexWord(parsed.a), "0xffffffffffffffff");
assert.equal(parsed.b, 12);
assert.equal(parsed.s, 'x 18446744073709551615 " y');
assert.deepEqual(parsed.n, [-1, 2.5]);
assert.equal(emu.addressOf(parsed.a), null);
assert.equal(emu.addressOf("68"), 68);

// Decoding: ASCII to its terminator, UTF-16LE, and bytes that are not text.
assert.deepEqual(emu.decodeText([104, 105, 33, 0, 7]), { encoding: "ASCII", text: "hi!" });
assert.deepEqual(emu.decodeText([104, 0, 105, 0, 0, 0]), { encoding: "UTF-16LE", text: "hi" });
assert.deepEqual(emu.decodeText([0xc3, 0xa9, 0x74, 0xc3, 0xa9]), { encoding: "UTF-8", text: "été" });
assert.equal(emu.decodeText([1, 2, 3, 4, 0xfe]), null);
assert.equal(emu.decodeText([]), null);

// Prototypes: blank arguments that remember which are pointers.
assert.deepEqual(emu.argsFromPrototype("\nchar * decrypt(char *param_1,int param_2)\n\n{"),
  [{ kind: "auto", text: "", decl: "char *param_1", pointer: true }, { kind: "auto", text: "", decl: "int param_2" }]);

// One field per argument: numbers, quoted text, wide text, byte pairs, else plain text.
const auto = (text, pointer) => emu.resolveArg({ kind: "auto", text, pointer });
assert.deepEqual(auto("0x44"), { kind: "int", text: "0x44" });
assert.deepEqual(auto("-1"), { kind: "int", text: "-1" });
assert.deepEqual(auto("", false), { kind: "int", text: "0" });
assert.deepEqual(auto("", true), { kind: "hex", text: "" });
assert.deepEqual(auto("32 3f 36"), { kind: "hex", text: "32 3f 36" });
assert.deepEqual(auto("3f"), { kind: "hex", text: "3f" });
assert.deepEqual(auto('"10\\x00"'), { kind: "utf8", text: "10\\x00" });
assert.deepEqual(auto('L"hi"'), { kind: "utf16", text: "hi" });
assert.deepEqual(auto("hello world"), { kind: "utf8", text: "hello world" });
assert.deepEqual(emu.describeArg({ kind: "auto", text: "32 3f 36" }, 8), { text: "3 bytes" });
assert.deepEqual(emu.describeArg({ kind: "auto", text: '"hi"' }, 8), { text: "Text, 2 bytes" });
assert.deepEqual(emu.describeArg({ kind: "auto", text: "", pointer: true }, 8), { text: "Empty buffer" });
assert.equal(emu.describeArg({ kind: "auto", text: "0x1ffffffff" }, 4).error, true);
const autoReq = JSON.parse(emu.buildRequest(0, [{ kind: "auto", text: '"ab"' }, { kind: "auto", text: "7" }], 8, []).json);
assert.deepEqual(autoReq.memory[0].data.slice(0, 3), [0x61, 0x62, 0]);
assert.equal(autoReq.args[1], 7);
assert.deepEqual(emu.argsFromPrototype("void f(void)\n{"), []);
assert.deepEqual(emu.argsFromPrototype(undefined), []);
assert.deepEqual(emu.emulateArgs("/s", 0x2f, 500), ["/s", "--emulate", "0x2f", "--emulate-request", "--emulate-call-sites", "--emulate-max-sites", "128"]);
assert.deepEqual(emu.emulateArgs("{sample}", 16), ["{sample}", "--emulate", "0x10", "--emulate-request"]);
console.log("Emulation requests, exact words, prototypes and text decoding: passed");

// The real engine: decrypt(buffer, length) at 0x2f, called twice by main (binfera/tests/emulate.rs XOR_STRINGS).
const assets = new URL("../src/wasm/", import.meta.url);
if (!fs.existsSync(new URL("binfera.js", assets))) {
  if (process.env.CI) throw new Error("src/wasm/binfera.js is missing: run build:wasm first");
  console.log("Emulation through WASM: skipped (no src/wasm build; run build:wasm)");
  process.exit(0);
}
const { default: createBinfera } = await import("../src/wasm/binfera.js");
const XOR = Uint8Array.from([
  0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d, 0x39, 0, 0, 0, 0xba, 5, 0, 0, 0, 0xe8, 0x1a, 0, 0, 0,
  0x48, 0x8d, 0x0d, 0x2e, 0, 0, 0, 0xba, 7, 0, 0, 0, 0xe8, 9, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28,
  0x31, 0xc0, 0xc3, 0xcc, 0xcc, 0x48, 0x89, 0xc8, 0x85, 0xd2, 0x74, 0x0a, 0x80, 0x31, 0x5a, 0x48,
  0xff, 0xc1, 0xff, 0xca, 0x75, 0xf6, 0xc3, 0xcc, 0xcc, 0xcc, 0x32, 0x3f, 0x36, 0x36, 0x35, 0,
  0x3f, 0x22, 0x3b, 0x37, 0x2a, 0x36, 0x3f, 0,
]);
async function emulate(json, callSites) {
  const out = [], err = [], input = new TextEncoder().encode(json);
  let read = 0;
  const engine = await createBinfera({
    locateFile: (name) => fileURLToPath(new URL(name, assets)), noInitialRun: true,
    print: (line) => out.push(line), printErr: (line) => err.push(line), stdin: () => (read < input.length ? input[read++] : null),
  });
  engine.FS.writeFile("/sample.bin", XOR);
  let code = 0;
  try { code = engine.callMain([...emu.emulateArgs("/sample.bin", 0x2f, callSites), "--format", "sc64", "--os", "windows"]) ?? 0; } catch (e) { code = e.status; }
  assert.equal(code, 0, err.join("\n"));
  return emu.parseExact(out.join(""));
}
const sc = [{ va: 0, vsize: XOR.length, size: XOR.length }];
const direct = emu.buildRequest(0x2f, [{ kind: "hex", text: "3f 22 3b 37 2a 36 3f" }, { kind: "int", text: "7" }], 8, sc);
const run = await emulate(direct.json);
assert.equal(run.stop.kind, "returned");
assert.equal(emu.stopText(run.stop.kind), "Finished");
assert.equal(emu.addressOf(run.return_value), direct.buffers.get(0).address);
const written = emu.outputs(run.writes, emu.stackPointer(run)).filter((w) => !w.stack);
assert.deepEqual(written.map((w) => w.text), [{ encoding: "ASCII", text: "example" }]);
const sites = await emulate(emu.buildRequest(0x2f, [], 8, sc, emu.SITE_LIMITS).json, emu.MAX_SITES);
assert.equal(sites.total_sites, 2);
assert.deepEqual(sites.sites.map((s) => [s.caller, s.site]), [[0, 0x10], [0, 0x21]]);
assert.deepEqual(sites.sites.map((s) => emu.siteOutput(s)?.text?.text), ["hello", "example"]);
console.log("String decryption helper through WASM, directly and at each call site: passed");
