// Harmless raw functions exercise the actual browser engine without executing their instructions.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import { stripTypes } from "./strip-types.mjs";
import createBinfera from "../src/wasm/binfera.js";

async function run(bytes, args) {
  const output = [], errors = [];
  const engine = await createBinfera({
    locateFile: name => fileURLToPath(new URL(`../src/wasm/${name}`, import.meta.url)),
    print: line => output.push(line), printErr: line => errors.push(line),
  });
  engine.FS.writeFile("/sample", bytes);
  engine.FS.mkdir("/rules");
  engine.FS.writeFile("/rules/test.yml", "rule:\n  meta:\n    name: returns from raw function\n    authors: [test]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - mnemonic: ret\n");
  const exitCode = process.exitCode;
  let code;
  try { code = engine.callMain(["/sample", ...args]) ?? 0; }
  catch (e) { if (typeof e.status !== "number") throw e; code = e.status; }
  finally { process.exitCode = exitCode; }
  assert.equal(code, 0, errors.join("\n"));
  return output.join("\n");
}

const compiled = stripTypes(await readFile(new URL("../src/engine/capa.ts", import.meta.url), "utf8"));
const { summarizeCapa } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);
const inputModule = stripTypes(await readFile(new URL("../src/engine/shellcode.ts", import.meta.url), "utf8"));
const { shellcodePayload } = await import(`data:text/javascript;base64,${Buffer.from(inputModule).toString("base64")}`);

for (const [format, bytes] of [
  ["sc32", [0x55, 0x89, 0xe5, 0x8b, 0x45, 8, 0x03, 0x45, 12, 0x5d, 0xc3]],
  ["sc64", [0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3]],
]) {
  const input = Uint8Array.from(bytes);
  const info = JSON.parse(await run(input, ["--image-info", "--guess-shellcode"]));
  assert.equal(info.format, format);
  assert.equal(info.entry, 0);
  assert.equal(info.regions[0].va, 0);
  const events = (await run(input, ["-f", format, "--decompile-all"])).split("\n").map(JSON.parse);
  const fn = events.find(e => e.type === "function" && e.address === 0);
  assert.ok(fn?.text?.includes("return"), JSON.stringify(events));
  assert.ok(fn.asm.length >= 3);
  const doc = JSON.parse(await run(input, ["-f", format, "--json", "-r", "/rules", "--os", "windows"]));
  const capa = summarizeCapa(doc, 0);
  assert.equal(capa.baseAddress, 0);
  assert.ok(capa.rules.find(r => r.name === "returns from raw function")?.addresses.includes(0));
  const alternate = format === "sc64" ? "sc32" : "sc64";
  const forced = JSON.parse(await run(input, ["--image-info", "-f", alternate, "--os", "linux"]));
  assert.equal(forced.format, alternate);
  console.log(`${format}: automatic guess, C, assembly, address-aligned capabilities and override passed`);
}

const ambiguous = JSON.parse(await run(Uint8Array.from([0x31, 0xc0, 0xc3]), ["--image-info", "--guess-shellcode"]));
assert.ok(ambiguous.warnings.some(w => w.includes("ambiguous")));
console.log("Ambiguous raw decoding is reported: passed");

for (const [name, hex, format, os] of [
  ["prefixed REX", "66 48 89 c8 48 01 d0 c3", "sc64", null],
  ["RIP relative", "48 8d 05 00 00 00 00 c3", "sc64", null],
  ["branch over data", "eb 02 ff ff 48 89 c8 c3", "sc64", null],
  ["Linux interrupt", "31 c0 40 cd 80", "sc32", "linux"],
  ["Windows PEB", "65 48 8b 04 25 60 00 00 00 c3", "sc64", "windows"],
  ["syscall with unknown OS", "b8 3c 00 00 00 0f 05", "sc64", null],
  ["ambiguous get-PC", "e8 00 00 00 00 5b 31 c0 c3", "sc32", null],
]) {
  const payload = shellcodePayload(new TextEncoder().encode(hex).buffer);
  const info = JSON.parse(await run(new Uint8Array(payload.bytes), ["--image-info", "--guess-shellcode"]));
  assert.equal(info.format, format, name);
  assert.equal(info.shellcode.os, os, name);
  console.log(`${name}: decoded text, architecture and OS hint passed`);
}

// The same sliced payload goes to inspection and decompilation, retaining relative branch targets.
const prefixed = shellcodePayload(new TextEncoder().encode("ff ff ff ff 48 89 c8 48 01 d0 c3").buffer, 4);
const sliced = new Uint8Array(prefixed.bytes);
const info = JSON.parse(await run(sliced, ["--image-info", "--guess-shellcode"]));
assert.equal(info.format, "sc64");
const fn = (await run(sliced, ["-f", "sc64", "--decompile-all"])).split("\n").map(JSON.parse).find(e => e.type === "function" && e.address === 0);
assert.ok(fn.text.includes("param_1 + param_2"), fn.text);
assert.equal(fn.asm[0][0], 0);
console.log("Hex input with skipped prefix produces expected C at offset zero: passed");

for (const [path, format] of [
  ["risc/windows.exe", "pe"], ["risc/arm.elf", "elf"], ["macho/thin-x86_64-exe", "macho"],
]) {
  const bytes = await readFile(new URL(`../../binfera/tests/fixtures/${path}`, import.meta.url));
  const info = JSON.parse(await run(bytes, ["--image-info", "--guess-shellcode"]));
  assert.equal(info.format, format);
  assert.ok(!info.warnings.some(w => w.includes("Possible shellcode")));
}
await assert.rejects(run(Uint8Array.from([0x4d, 0x5a, 0x31, 0xc0, 0xc3]), ["--image-info", "--guess-shellcode"]));
console.log("PE, ELF and Mach-O keep their loaders, including corrupt executable headers: passed");
