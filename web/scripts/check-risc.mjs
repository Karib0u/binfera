// Run after npm run build:wasm. Use only the source-controlled, freestanding fixtures.
import fs from "node:fs";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import createBinfera from "../src/wasm/binfera.js";

const fixtures = new URL("../../binfera/tests/fixtures/risc/", import.meta.url);
const assets = new URL("../src/wasm/", import.meta.url);

function symbol(bytes, name, wantSize = false) {
  const little = bytes[5] === 1, wide = bytes[4] === 2;
  const u16 = at => little ? bytes.readUInt16LE(at) : bytes.readUInt16BE(at);
  const u32 = at => little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  const u64 = at => Number(little ? bytes.readBigUInt64LE(at) : bytes.readBigUInt64BE(at));
  const sections = wide ? u64(40) : u32(32), stride = u16(wide ? 58 : 46), count = u16(wide ? 60 : 48);
  const sectionOffset = at => wide ? u64(at + 24) : u32(at + 16);
  for (let i = 0; i < count; i++) {
    const section = sections + i * stride;
    if (u32(section + 4) !== 2) continue;
    const offset = sectionOffset(section), size = wide ? u64(section + 32) : u32(section + 20);
    const entry = wide ? u64(section + 56) : u32(section + 36);
    const strings = sectionOffset(sections + u32(section + (wide ? 40 : 24)) * stride);
    for (let at = offset; at < offset + size; at += entry) {
      const start = strings + u32(at);
      if (bytes.toString("utf8", start, bytes.indexOf(0, start)) === name) {
        if (wantSize) return wide ? u64(at + 16) : u32(at + 8);
        const value = wide ? u64(at + 8) : u32(at + 4);
        return value - value % 2;
      }
    }
  }
  throw new Error(`missing fixture symbol ${name}`);
}

async function run(bytes, args, extra = {}) {
  const output = [], errors = [];
  const engine = await createBinfera({
    locateFile: name => fileURLToPath(new URL(name, assets)), noInitialRun: true,
    print: text => output.push(text), printErr: text => errors.push(text),
  });
  engine.FS.writeFile("/sample", bytes);
  for (const [name, contents] of Object.entries(extra)) engine.FS.writeFile(`/${name}`, contents);
  engine.FS.mkdir("/rules");
  engine.FS.writeFile("/rules/library.yml", "rule:\n  meta:\n    name: scoped library call fixture\n    authors: [test]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: fixture_library_mix\n");
  engine.FS.writeFile("/rules/arch.yml", "rule:\n  meta:\n    name: risc architecture fixture\n    authors: [test]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - or:\n      - arch: arm\n      - arch: mips\n");
  engine.FS.writeFile("/rules/import.yml", "rule:\n  meta:\n    name: risc imported API fixture\n    authors: [test]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: imported\n");
  engine.FS.writeFile("/rules/risc.yml", "rule:\n  meta:\n    name: risc code fixture\n    authors: [test]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - or:\n      - mnemonic: bl\n      - mnemonic: blx\n      - mnemonic: jal\n");
  try {
    const status = engine.callMain(["/sample", ...args]);
    if (status) throw new Error(`exit ${status}`);
  }
  catch (error) { if (error.status !== 0) throw new Error(`${error}\n${errors.join("\n")}`); }
  return output.join("\n");
}

for (const [name, arch] of [["arm", "arm"], ["thumb", "arm"], ["interwork", "arm"], ["mips", "mips"], ["mipsel", "mipsel"]]) {
  const bytes = fs.readFileSync(new URL(`${name}.elf`, fixtures));
  const info = JSON.parse(await run(bytes, ["--image-info"]));
  assert.equal(info.arch, arch);
  assert.equal(info.ptrSize, 4);
  assert.equal(info.littleEndian, name !== "mips");
  const method = name === "interwork" ? "thumb_callee" : "mix";
  const result = JSON.parse(await run(bytes, ["--decompile-function", `0x${symbol(bytes, method).toString(16)}`, "--json"]));
  assert.ok(result.text.includes("param_1"), result.text);
  assert.ok(result.text.includes("return"), result.text);
  assert.equal(result.incomplete, false, JSON.stringify(result.warnings));
  const capabilities = await run(bytes, ["-r", "/rules", "--json"]);
  assert.ok(capabilities.includes("risc code fixture"), capabilities);
  assert.ok(capabilities.includes("risc architecture fixture"), capabilities);
  console.log(`${name}: browser metadata, decompilation and capability extraction passed`);
}

for (const name of ["arm", "thumb", "mips", "mipsel"]) {
  const bytes = fs.readFileSync(new URL(`${name}-dynamic.elf`, fixtures));
  const result = await run(bytes, ["-r", "/rules", "--json"]);
  assert.ok(result.includes("risc imported API fixture"), `${name}: ${result}`);
  const decompiled = JSON.parse(await run(bytes, ["--decompile-function", `0x${(symbol(bytes, "call_import") + 0x02000000).toString(16)}`, "--json"]));
  assert.ok(decompiled.text.includes("imported("), `${name}: ${decompiled.text}`);
  console.log(`${name}: browser GOT/PLT API rule and named decompiled call passed`);
}
const pe = fs.readFileSync(new URL("windows.exe", fixtures));
assert.equal(JSON.parse(await run(pe, ["--image-info"])).arch, "arm");
assert.ok((await run(pe, ["-r", "/rules", "--json"])).includes("risc code fixture"));
console.log("Windows ARMNT: browser metadata and capability extraction passed");

for (const name of ["arm", "thumb", "aarch64", "mips", "mipsel"]) {
  const object = fs.readFileSync(new URL(`${name}-rel.elf`, fixtures));
  const info = JSON.parse(await run(object, ["--image-info"]));
  const entry = info.sections.find(section => section.name === ".text").va;
  const decompiled = JSON.parse(await run(object, ["--decompile-function", `0x${entry.toString(16)}`, "--json"]));
  assert.ok(decompiled.text.includes("strlen("), `${name}: ${decompiled.text}`);
  assert.ok(!(decompiled.warnings ?? []).some(warning => warning.includes("unsupported ET_REL")), `${name}: ${JSON.stringify(decompiled.warnings)}`);
  console.log(`${name}: browser relocatable object and external call passed`);

  const bytes = fs.readFileSync(new URL(`${name}.elf`, fixtures));
  const metadata = JSON.parse(await run(bytes, ["--image-info"]));
  const address = symbol(bytes, "mix"), size = symbol(bytes, "mix", true);
  const region = metadata.regions.find(region => region.va <= address && address < region.va + region.size);
  const offset = region.off + address - region.va;
  const length = Math.min(size, 32);
  const head = bytes.subarray(offset, offset + length).toString("hex").toUpperCase() + "..".repeat(32 - length);
  const pattern = `${head} 00 0000 ${size.toString(16).padStart(4, "0")} :0000 fixture_library_mix\n---`;
  const manifest = JSON.stringify({ architecture: name === "thumb" ? "arm" : name, signatures: ["fixture.pat"] });
  const result = await run(bytes, ["-r", "/rules", "--signatures", "/pack.json", "--json"], { "pack.json": manifest, "fixture.pat": pattern });
  assert.ok(result.includes("scoped library call fixture"), `${name}: ${result}`);
  console.log(`${name}: browser scoped FLIRT pack and library API rule passed`);
}
