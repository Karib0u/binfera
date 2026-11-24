// Run after prepare-assets and pack-demos. Samples are only read by the WebAssembly engine.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import createBinfera from "../src/wasm/binfera.js";

const web = new URL("../", import.meta.url);
const index = JSON.parse(readFileSync(new URL("public/demos/index.json", web)));
const key = Buffer.from("binfera-demo-sample");
const id = process.argv[2];
const shard = process.argv[3] ?? "0/1";

if (!id) {
  assert.equal(new Set(index.map(s => s.id)).size, index.length, "duplicate demo IDs");
  for (const sample of index) {
    // Large demos use parallel decompiler shards, as in the app. Processes release wasm memory.
    const shards = sample.size > 1 << 20 ? 4 : 1;
    console.log(`Checking ${sample.id} (${shards} decompiler workers)`);
    const results = await Promise.all(Array.from({ length: shards }, async (_, i) => {
      const result = await promisify(execFile)(process.execPath,
        [fileURLToPath(import.meta.url), sample.id, `${i}/${shards}`],
        { encoding: "utf8", timeout: 600_000, maxBuffer: 4 << 20 });
      return JSON.parse(result.stdout);
    }));
    const { addresses, ...first } = results[0];
    console.log(JSON.stringify({ ...first, shards,
      functions: new Set(results.flatMap(r => r.addresses)).size,
      failed: results.reduce((n, r) => n + r.failed, 0),
      decompileSeconds: Math.max(...results.map(r => r.decompileSeconds)) }));
  }
} else {
  const sample = index.find(s => s.id === id);
  assert.ok(sample, `unknown demo: ${id}`);
  const bytes = readFileSync(new URL(`public/demos/${id}.bin`, web));
  for (let i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
  assert.equal(bytes.length, sample.size);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), sample.sha256);

  const signatures = ["1_flare_msvc_rtf_32_64.sig", "2_flare_msvc_atlmfc_32_64.sig", "3_flare_common_libs.sig"];
  async function run(args, print, kind) {
    const errors = [];
    const engine = await createBinfera({
      locateFile: name => fileURLToPath(new URL(`src/wasm/${name}`, web)),
      noInitialRun: true, print,
      printErr: line => { if (errors.length < 50) errors.push(line); },
    });
    engine.FS.writeFile("/sample", bytes);
    if (kind) {
      engine.FS.mkdir("/sigs");
      const files = [...signatures];
      if (kind === "decompile" && info.fidArch) files.push(`fid-${info.fidArch}.pack`);
      for (const file of files) {
        const packed = file.endsWith(".pack");
        const data = readFileSync(new URL(`public/sigs/${file}${packed ? "z" : ""}`, web));
        engine.FS.writeFile(`/sigs/${file}`, packed ? gunzipSync(data) : data);
      }
    }
    if (kind === "capa") {
      const rules = JSON.parse(readFileSync(new URL("public/rules.json", web)));
      engine.FS.mkdir("/rules");
      for (const [path, text] of Object.entries(rules)) {
        const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
        if (dir) engine.FS.mkdirTree(`/rules/${dir}`);
        engine.FS.writeFile(`/rules/${path}`, text);
      }
    }
    let code = 0;
    try { code = engine.callMain(["/sample", ...args]) ?? 0; }
    catch (error) { if (typeof error.status !== "number") throw error; code = error.status; }
    assert.equal(code, 0, `${id}: ${args.join(" ")}: ${errors.join("\n")}`);
  }

  let output = "";
  await run(["--image-info"], line => { output += line; });
  const info = JSON.parse(output);
  const arch = sample.tags.includes("AArch64") ? "aarch64" : sample.tags.includes("x64") ? "x64" : "x86";
  // Cards have qualitative tags only. Validate their engine-derived fields, including file size,
  // and refuse hand-written numeric counters in the source manifest.
  const declared = JSON.parse(readFileSync(new URL("demo/samples.json", web))).find(s => s.id === id);
  for (const [field, value] of Object.entries(declared)) {
    assert.ok(["id", "name", "kind", "tags", "note", "path", "slice"].includes(field), `${id}: unchecked card field ${field}`);
    assert.notEqual(typeof value, "number", `${id}: card numbers must come from engine output`);
  }
  assert.equal(info.arch, arch, `${id}: demo architecture label`);
  assert.equal(info.format.toLowerCase().replace("-", ""), sample.tags[1].toLowerCase().replace("-", ""), `${id}: demo format label`);
  assert.ok(info.sections.length);
  assert.ok(info.regions.every(r => r.off + r.size <= bytes.length));
  output = "";
  const start = performance.now();
  let capabilities = 0;
  if (shard.startsWith("0/")) {
    await run(["--json", "--jobs", "1", "--rules", "/rules"], line => { output += line; }, "capa");
    const capa = JSON.parse(output);
    assert.equal(capa.meta.sample.sha256, sample.sha256);
    capabilities = Object.keys(capa.rules).length;
  }
  const packUrl = new URL("public/sigs/family.bxfam", web);
  let matchedFamily = null;
  if (shard.startsWith("0/") && existsSync(packUrl)) {
    const errors = [];
    let famOut = "";
    const engine = await createBinfera({
      locateFile: name => fileURLToPath(new URL(`src/wasm/${name}`, web)),
      noInitialRun: true,
      print: line => { famOut += line; },
      printErr: line => { if (errors.length < 50) errors.push(line); },
    });
    engine.FS.mkdir("/sigs");
    if (sample.tags.includes("PE")) {
      for (const file of signatures) engine.FS.writeFile(`/sigs/${file}`, readFileSync(new URL(`public/sigs/${file}`, web)));
    }
    engine.FS.writeFile("/family.bxfam", readFileSync(packUrl));
    engine.FS.writeFile("/sample", bytes);
    let code = 0;
    try { code = engine.callMain(["family", "match", "--pack", "/family.bxfam", "/sample", "--json"]) ?? 0; }
    catch (error) { if (typeof error.status !== "number") throw error; code = error.status; }
    assert.equal(code, 0, `${id}: family match: ${errors.join("\n")}`);
    const report = JSON.parse(famOut);
    matchedFamily = report.families[0]?.family ?? null;
    assert.equal(matchedFamily, sample.family, `${id}: expected family ${sample.family}, got ${matchedFamily}`);
  }
  const capabilitySeconds = (performance.now() - start) / 1000;
  const addresses = new Set();
  let failed = 0, complete = false, settled = false;
  const decompileStart = performance.now();
  await run(["--decompile-all", "--no-resource-retry", "--shard", shard, "--max-instructions", "3500000"], line => {
    if (!line.trim()) return;
    const event = JSON.parse(line);
    if (event.type === "start") assert.equal(event.arch, arch);
    if (event.type === "function") {
      if (event.text?.trim()) addresses.add(event.address);
      if (event.error) failed++;
    }
    if (event.type === "settled") settled = true;
    if (event.type === "done") complete = true;
  }, "decompile");
  assert.ok(settled, `${id}: decompilation did not settle`);
  assert.ok(complete, `${id}: decompilation did not finish`);
  assert.ok(addresses.size > 0, `${id}: no decompiled functions`);
  console.log(JSON.stringify({ id, arch, bytes: bytes.length, capabilities, ...(matchedFamily ? { family: matchedFamily } : {}),
    addresses: [...addresses], functions: addresses.size, failed, capabilitySeconds: +capabilitySeconds.toFixed(2),
    decompileSeconds: +((performance.now() - decompileStart) / 1000).toFixed(2) }));
}
