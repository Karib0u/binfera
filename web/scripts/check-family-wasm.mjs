// Run after build:wasm. Layered family matching through the browser engine, with the arguments
// engine.worker.ts builds: each pack at /packs/<i>/<its name>, base first.
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const assets = new URL("../src/wasm/", import.meta.url);
if (!fs.existsSync(new URL("binfera.js", assets))) {
  if (process.env.CI) throw new Error("src/wasm/binfera.js is missing: run build:wasm first");
  console.log("Family WASM check: skipped (no src/wasm build; run build:wasm)");
  process.exit(0);
}
const { default: createBinfera } = await import("../src/wasm/binfera.js");
const sample = fs.readFileSync(new URL("../public/demo.exe", import.meta.url));
const pack = (name) => fs.readFileSync(new URL(`family/${name}`, import.meta.url));

async function match(packs) {
  const output = [], errors = [];
  const engine = await createBinfera({
    locateFile: (name) => fileURLToPath(new URL(name, assets)),
    noInitialRun: true,
    print: (line) => output.push(line),
    printErr: (line) => errors.push(line),
  });
  engine.FS.writeFile("/sample.bin", sample);
  const args = ["family", "match"];
  engine.FS.mkdir("/packs");
  packs.forEach((name, i) => {
    engine.FS.mkdir(`/packs/${i}`);
    engine.FS.writeFile(`/packs/${i}/${name}`, pack(name));
    args.push("--pack", `/packs/${i}/${name}`);
  });
  args.push("/sample.bin", "--json");
  try { engine.callMain(args); } catch (e) { if (e.status !== 0) throw new Error(errors.join("\n") || String(e)); }
  return JSON.parse(output.join("\n"));
}

// BXFAM002: code attribution only; no string or symbol fields, so the UI hides them.
const v2 = await match(["demo-v2.bxfam"]);
assert.equal(v2.families[0]?.family, "win.synthetic");
assert.equal(v2.strings, undefined);
assert.equal(v2.trusted_symbols, undefined);
console.log("BXFAM002 pack through WASM: passed");

// BXFAM003 base: code names the family and strings corroborate it.
const base = await match(["demo-base.bxfam"]);
assert.equal(base.families[0]?.family, "win.synthetic");
assert.equal(base.families[0].functions[0].pack_name, "demo-base.bxfam");
assert.equal(base.strings.malware_strings, 3);
assert.equal(base.strings.trusted_strings, 1);
assert.equal(base.strings.families[0].corroborates_code, true);
assert.equal(base.strings.string_only_hint, undefined);
assert.ok(base.strings.entries.some((e) => e.kind === "malware" && e.value === "binfera-demo-report.txt"));
console.log("BXFAM003 base pack through WASM: passed");

// Overlay: the organization trusts one family function, so code abstains; strings give only a
// labeled hint, and Trusted functions carry the overlay's symbols.
const layered = await match(["demo-base.bxfam", "demo-org-trusted.bxfam"]);
assert.deepEqual(layered.families, []);
assert.equal(layered.strings.string_only_hint?.family, "win.synthetic");
const symbols = Object.fromEntries(layered.trusted_symbols.map((s) => [s.trusted_symbol, s]));
assert.equal(symbols.EVP_DecryptUpdate?.address, 0x1400011c0);
assert.equal(symbols.EVP_DecryptUpdate?.source, "openssl");
assert.equal(symbols.EVP_DecryptUpdate?.pack_name, "demo-org-trusted.bxfam");
assert.equal(symbols.OrgTrustedHelper?.address, 0x140001ae0);
assert.ok(layered.trusted_sources.some((s) => s.source === "openssl" && s.addresses.includes(0x1400011c0)));
console.log("Layered BXFAM003 overlay through WASM: passed");
