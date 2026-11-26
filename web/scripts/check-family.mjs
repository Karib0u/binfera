// Verify code-origin indexing, pack magic validation, analysis integration, and report formatting.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { setImmediate } from "node:timers/promises";
import { stripTypes } from "./strip-types.mjs";

const moduleUrl = (source) => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const compile = async (path) => stripTypes(await readFile(new URL(path, import.meta.url), "utf8"));

// 1. Origin indexing & priority (malware > shared > trusted > unique + capa.library fallback)
const { buildOriginIndex, formatMatchKind, formatSourceName } = await import(
  moduleUrl(await compile("../src/familyOrigin.ts")),
);

const sampleReport = {
  total_functions: 10,
  eligible_functions: 6,
  trusted_functions: 2,
  shared_malware_functions: 1,
  family_matched_functions: 2,
  unique_functions: 1,
  breakdown: { trusted_pct: 33.33, malware_pct: 33.33, shared_pct: 16.67, unique_pct: 16.67 },
  trusted_sources: [
    { source: "windows-msvc-runtime", functions: 1, instructions: 45, addresses: [0x1000] },
    { source: "runtime-stdlib", functions: 1, instructions: 30, addresses: [0x1100] },
  ],
  shared_addresses: [0x2000],
  unique_addresses: [0x3000],
  families: [
    {
      family: "win.wannacryptor",
      score: 42.5,
      exclusive_functions: 2,
      exact_content_hits: 1,
      exact_shape_hits: 1,
      fuzzy_hits: 0,
      matched_instructions: 180,
      coverage: 0.667,
      functions: [
        { address: 0x4000, instructions: 100, kind: "exact_content", exclusivity: 1, sample_count: 8, contribution: 2.1 },
        { address: 0x4100, instructions: 80, kind: { fuzzy_band: { bands: 6 } }, exclusivity: 2, sample_count: 4, contribution: 0.9 },
      ],
    },
  ],
};

const idx = buildOriginIndex(sampleReport, [0x1200]);
assert.equal(idx.byAddress.get(0x1000)?.kind, "trusted");
assert.equal(idx.byAddress.get(0x1000)?.label, "Windows msvc runtime");
assert.equal(idx.byAddress.get(0x1100)?.label, "Runtime / FLIRT");
assert.equal(idx.byAddress.get(0x1200)?.kind, "trusted");
assert.equal(idx.trustedSet.size, 3);
assert.equal(idx.byAddress.get(0x2000)?.kind, "shared");
assert.equal(idx.byAddress.get(0x3000)?.kind, "unique");
assert.equal(idx.byAddress.get(0x4000)?.kind, "malware");
assert.equal(idx.byAddress.get(0x4000)?.label, "win.wannacryptor");
assert.equal(idx.byAddress.get(0x4000)?.exclusive, true);
assert.equal(formatMatchKind("exact_content"), "exact content");
assert.equal(formatMatchKind("exact_shape"), "exact shape");
assert.equal(formatMatchKind({ fuzzy_band: { bands: 5 } }), "fuzzy (5/8 bands)");
assert.equal(formatSourceName("linux-debian"), "Linux debian");
console.log("Origin index and formatters: passed");

// 2. Pack magic validation in assets.ts (SPA HTML 200 responses must be rejected cleanly)
const resultCache = await compile("../src/engine/resultCache.ts");
const assetsSource = (await readFile(new URL("../src/engine/assets.ts", import.meta.url), "utf8"))
  .replace('from "./resultCache"', `from "${moduleUrl(resultCache)}"`)
  .replace(/import wasmUrl from [^;]+;/, 'const wasmUrl = "/engine.wasm";')
  .replaceAll("import.meta.env.BASE_URL", '"/"');
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  if (url === "/sigs/family.bxfam") return new Response("<!doctype html><html>spa fallback</html>", { status: 200 });
  return new Response(new Uint8Array(0), { status: 404 });
};
const assetsMod = await import(moduleUrl(stripTypes(assetsSource)));
assert.equal(await assetsMod.loadFamilyPack(), null, "HTML SPA fallback must not be treated as a BXFAM002 pack");
assert.throws(() => assetsMod.setCustomFamilyPack(new Uint8Array(10).buffer, "bad.bxfam"));
const fakePack = new Uint8Array(48);
fakePack.set(new TextEncoder().encode("BXFAM002"), 0);
assetsMod.setCustomFamilyPack(fakePack.buffer, "pro.bxfam");
assert.equal(assetsMod.getFamilyPackName(), "pro.bxfam");
const loaded = await assetsMod.loadFamilyPack();
assert.ok(loaded && loaded.byteLength === 48);
const v3Pack = new Uint8Array(56);
v3Pack.set(new TextEncoder().encode("BXFAM003"), 0);
assert.equal(assetsMod.familyPackFormat(v3Pack), "BXFAM003");
assert.equal(assetsMod.familyPackFormat(fakePack), "BXFAM002");
assert.throws(() => assetsMod.addFamilyOverlay(new TextEncoder().encode("BXFAM004" + " ".repeat(40)).buffer, "future.bxfam"), /not a valid/);
assetsMod.addFamilyOverlay(v3Pack.buffer, "my-org-trusted.bxfam");
assetsMod.addFamilyOverlay(v3Pack.slice(0, 48).buffer, "team.bxfam");
let layered = await assetsMod.loadFamilyPacks();
assert.deepEqual(layered.map((p) => [p.name, p.format, p.size]), [["pro.bxfam", "BXFAM002", 48], ["my-org-trusted.bxfam", "BXFAM003", 56], ["team.bxfam", "BXFAM003", 48]]);
assert.notEqual(layered[1].bytes, layered[2].bytes, "each run gets its own transferable copy");
assetsMod.removeFamilyOverlay(0);
layered = await assetsMod.loadFamilyPacks();
assert.deepEqual(layered.map((p) => p.name), ["pro.bxfam", "team.bxfam"]);
globalThis.fetch = originalFetch;
console.log("Family pack magic validation, BXFAM003 and overlay loading: passed");

// 3. analyze.ts runs family worker when a pack is available and populates Analysis.family
const shellcodeUrl = moduleUrl(await compile("../src/engine/shellcode.ts"));
const mocksUrl = moduleUrl(`
  export const requests = [];
  export const NATIVE = false;
  export const digest = async () => null;
  export const loadEngineId = async () => null;
  export const winApiFor = () => null;
  export const readResults = async () => null;
  export const writeResults = async () => {};
  export const forgetResults = async () => {};
  export class EngineError extends Error {}
  export const TOO_LARGE = 14;
  export const loadEngine = async () => ({});
  export const familyRuns = [];
  export const overlays = [];
  export let refuseOverlays = false;
  export const setRefuseOverlays = (v) => { refuseOverlays = v; };
  export const loadFamilyPacks = async () => [
    { name: "Starter pack", size: 48, format: "BXFAM002", bytes: new Uint8Array(48).buffer },
    ...overlays.map((name) => ({ name, size: 56, format: "BXFAM003", bytes: new Uint8Array(56).buffer })),
  ];
  export const pickNativeFamilyPack = async () => null;
  export const pickNativeFamilyOverlay = async () => false;
  export const removeNativeFamilyOverlay = async () => {};
  export const setCustomFamilyPack = () => {};
  export const addFamilyOverlay = (_bytes, name) => { overlays.push(name); };
  export const removeFamilyOverlay = (i) => { overlays.splice(i, 1); };
  export const extractStrings = () => ({ strings: [], total: 0 });
  export const summarizeCapa = (json) => json;
  export const createImage = () => null;
  export const loadAssets = async () => ({ module: {}, data: () => ({}), rules: {} });
  export async function runEngine(req, onLine) {
    requests.push(req.kind);
    if (req.kind === "inspect") onLine(JSON.stringify({ format: "pe", entry: 0x1000, arch: "x86", fidArch: "x86" }));
    else if (req.kind === "capa") onLine(JSON.stringify({ sample: { sha256: "abc" }, rules: [], library: [] }));
    else if (req.kind === "family") {
      familyRuns.push({ packs: req.packs?.length, overlays: req.overlays });
      if (refuseOverlays && req.packs?.length > 1) throw new EngineError("corrupt BXFAM003 section");
      onLine(${JSON.stringify(JSON.stringify(sampleReport))});
    }
    else if (req.kind === "decompile") {
      onLine(JSON.stringify({ type: "start", functions: [0x1000, 0x4000] }));
      onLine(JSON.stringify({ type: "settled" }));
      onLine(JSON.stringify({ type: "done" }));
    }
  }
`);
const analyzeCompiled = (await compile("../src/analyze.ts"))
  .replace('from "./engine/shellcode"', `from "${shellcodeUrl}"`)
  .replace(/from "\.\/engine\/[^"]+"/g, `from "${mocksUrl}"`);
const { analyze } = await import(moduleUrl(analyzeCompiled));
const { requests } = await import(mocksUrl);
Object.defineProperty(globalThis, "navigator", { value: { hardwareConcurrency: 4, userAgent: "test" }, configurable: true });
const updates = [];
await analyze(new File([new Uint8Array(16)], "wannacry.exe"), (a) => updates.push(a), new AbortController().signal);
await setImmediate();
const final = updates.at(-1);
assert.ok(requests.includes("family"), "family worker must be invoked when a pack is available");
assert.equal(final.family.families[0].family, "win.wannacryptor");
assert.equal(final.family.trusted_functions, 2);
assert.equal(typeof final.runFamilyPack, "function");
assert.deepEqual(final.familyPacks, [{ name: "Starter pack", size: 48, format: "BXFAM002", role: "base" }]);
console.log("Analysis pipeline family matching: passed");

// 3b. Overlays re-run matching with every pack, base first, and a refused overlay is taken off again
const mocks = await import(mocksUrl);
// analyze() publishes changes 80 ms after the last one.
const published = () => new Promise((resolve) => setTimeout(resolve, 150));
await final.addFamilyOverlay(new File([new Uint8Array(56)], "my-org-trusted.bxfam"));
await published();
let latest = updates.at(-1);
assert.deepEqual(mocks.familyRuns.at(-1), { packs: 2, overlays: 1 });
assert.deepEqual(latest.familyPacks.map((p) => [p.name, p.role]), [["Starter pack", "base"], ["my-org-trusted.bxfam", "overlay"]]);
mocks.setRefuseOverlays(true);
await latest.addFamilyOverlay(new File([new Uint8Array(56)], "broken.bxfam"));
await published();
latest = updates.at(-1);
assert.match(latest.familyError, /corrupt BXFAM003/);
assert.deepEqual(mocks.overlays, ["my-org-trusted.bxfam"], "a pack the engine refused must not stay layered");
mocks.setRefuseOverlays(false);
await latest.removeFamilyOverlay(0);
await published();
latest = updates.at(-1);
assert.deepEqual(mocks.familyRuns.at(-1), { packs: 1, overlays: 0 });
assert.deepEqual(latest.familyPacks.map((p) => p.name), ["Starter pack"]);
assert.equal(latest.familyError, null);
console.log("Overlay packs add, refuse and remove: passed");

// 4. Report Markdown/HTML includes Code origin cleanly and escapes family names
const { reportMarkdown, reportHtml } = await import(moduleUrl(await compile("../src/report.ts")));
const reportInput = {
  fileName: "sample.exe",
  size: 4096,
  toolchains: [],
  findings: [],
  signatures: [],
  capabilities: [],
  indicators: [],
  sections: [],
  starred: [],
  codeOrigin: {
    breakdown: sampleReport.breakdown,
    families: [{ family: "win.wannacryptor", score: 42.5, exclusive: 2, coverage: 0.667 }],
    trustedSources: [{ source: "windows-msvc-runtime", functions: 1 }],
  },
};
const md = reportMarkdown(reportInput);
const html = reportHtml(reportInput);
assert.ok(md.includes("## Code origin") && md.includes("win.wannacryptor"));
assert.ok(html.includes("<h2>Code origin</h2>") && html.includes("win.wannacryptor"));
assert.ok(!md.includes("score 42.5"), "report prose should not print the raw engine score");
assert.ok(!md.includes("String reuse") && !md.includes("Trusted symbols"), "BXFAM002 reports have no string or symbol lines");
const v3Md = reportMarkdown({
  ...reportInput,
  codeOrigin: {
    ...reportInput.codeOrigin,
    families: [],
    packs: ["Starter pack (BXFAM002)", "my-org-trusted.bxfam (BXFAM003)"],
    trustedSymbols: [{ address: "0x1000", name: "EVP_DecryptUpdate", source: "OpenSSL" }],
    strings: { total: 10, trusted: 4, malware: 3, shared: 1, unique: 2, families: [{ family: "win.lumma", exclusive: 3, corroboratesCode: false }], exclusive: [{ value: "LummaC2 Build", families: ["win.lumma"] }], hint: { family: "win.lumma", strings: 3 } },
  },
});
assert.ok(v3Md.includes("0x1000 EVP\\_DecryptUpdate (OpenSSL)"), "Markdown escapes the underscore");
assert.ok(v3Md.includes("String reuse (supporting evidence, not part of the verdict): 10 strings, 30.0% malware family"));
assert.ok(v3Md.includes("LummaC2 Build (win.lumma)"));
assert.ok(v3Md.includes("Low-confidence string-only hint: win.lumma"));
assert.ok(v3Md.includes("Packs (base first): Starter pack (BXFAM002), my-org-trusted.bxfam (BXFAM003)"));
console.log("Code origin report export: passed");

// 5. Match strength rests on exclusive functions, coverage and exactness, not the raw score
const { matchStrength, describeMatchKinds } = await import(moduleUrl(await compile("../src/familyOrigin.ts")));
const fam = (exclusive_functions, coverage, exact_content_hits, exact_shape_hits, fuzzy_hits = 0) => ({ exclusive_functions, coverage, exact_content_hits, exact_shape_hits, fuzzy_hits });
assert.equal(matchStrength(fam(38, 1, 0, 38)), "strong");
assert.equal(matchStrength(fam(5, 0.4, 2, 3)), "likely");
assert.equal(matchStrength(fam(2, 0.9, 2, 0)), "weak");
assert.equal(matchStrength(fam(38, 1, 0, 0, 38)), "likely", "fuzzy-only matches never read as strong");
assert.equal(matchStrength(fam(5, 0.4, 0, 0, 5)), "weak");
assert.equal(describeMatchKinds(fam(0, 0, 36, 2, 1)), "36 identical, 2 same control flow, 1 similar");
console.log("Code origin match strength: passed");

// 6. BXFAM003 Trusted symbols: pack names fill only what nothing else names
const origin = await compile("../src/familyOrigin.ts");
const originUrl = moduleUrl(origin);
const { trustedNames, isAutoName, buildStringOriginIndex, stringOriginKey, stringOriginOf, stringOriginBadge, buildOriginIndex: buildIndex } = await import(originUrl);
const v3Report = {
  ...sampleReport,
  trusted_symbols: [
    { address: 0x1000, trusted_symbol: "EVP_DecryptUpdate", source: "openssl", pack_name: "my-org-trusted.bxfam" },
    { address: 0x1100, trusted_symbol: "memcpy", source: "windows-msvc-runtime" },
    { address: 0x1300, trusted_symbol: "exported_name_wins" },
    { address: 0x1400, trusted_symbol: "renamed_wins" },
  ],
  strings: {
    total_strings: 5, trusted_strings: 2, malware_strings: 1, shared_strings: 1, unique_strings: 1,
    breakdown: { trusted_pct: 40, malware_pct: 20, shared_pct: 20, unique_pct: 20 },
    families: [{ family: "win.lumma", exclusive_strings: 1, shared_strings: 1, corroborates_code: false }],
    entries: [
      { value: "LummaC2 Build 2024", hash: "01", kind: "malware", families: ["win.lumma"], encoding: "ascii", offset: 10 },
      { value: "shared marker string", hash: "02", kind: "shared", families: ["win.lumma", "win.stealc"], encoding: "utf16le", offset: 20 },
      { value: "Microsoft Visual C++ Runtime Library", hash: "03", kind: "trusted", encoding: "ascii", offset: 30 },
    ],
    entries_truncated: false,
  },
};
assert.ok(isAutoName("FUN_00401000") && isAutoName("thunk_FUN_00401000") && isAutoName(undefined) && isAutoName("sub_401000"));
assert.ok(!isAutoName("memcpy") && !isAutoName("FUN_handler"));
const names = trustedNames(v3Report);
assert.equal(names.get(0x1000).name, "EVP_DecryptUpdate");
assert.equal(names.get(0x1000).source, "openssl");
assert.match(names.get(0x1000).detail, /Library name from pack · openssl · EVP_DecryptUpdate \(my-org-trusted\.bxfam\)/);
assert.equal(trustedNames(sampleReport).size, 0, "BXFAM002 reports carry no Trusted symbols");
assert.equal(buildIndex(v3Report).byAddress.get(0x1000).symbol, "EVP_DecryptUpdate");

const notesSource = (await readFile(new URL("../src/names.ts", import.meta.url), "utf8"))
  .replace('import { createContext, useContext } from "react";', "const createContext = (v) => v, useContext = (v) => v;")
  .replace('import { project } from "./project/client";', "const project = null;")
  .replace('from "./familyOrigin"', `from "${originUrl}"`);
Object.defineProperty(globalThis, "localStorage", { value: { getItem: () => null, setItem() {}, removeItem() {} }, configurable: true });
const { Notes } = await import(moduleUrl(stripTypes(notesSource)));
const notes = new Notes();
notes.load("sha");
notes.setTrustedNames(names);
notes.setExportNames(new Map([[0x1300, "ExportedName"]]));
notes.renames.set(0x1400, "my_decrypt");
// precedence: user rename > binary symbol > FLIRT > pack trusted_symbol > FUN_<addr>
assert.equal(notes.label(0x1000, null), "EVP_DecryptUpdate");
assert.equal(notes.label(0x1000, "FUN_00001000"), "EVP_DecryptUpdate");
assert.ok(notes.trustedLabel(0x1000, "FUN_00001000"));
assert.equal(notes.label(0x1100, "_memcpy_flirt"), "_memcpy_flirt", "a FLIRT or file symbol beats the pack");
assert.equal(notes.trustedLabel(0x1100, "_memcpy_flirt"), undefined);
assert.equal(notes.label(0x1300, null), "ExportedName");
assert.equal(notes.trustedLabel(0x1300, null), undefined);
assert.equal(notes.label(0x1400, null), "my_decrypt");
assert.equal(notes.trustedLabel(0x1400, null), undefined);
assert.equal(notes.label(0x9000, null), "FUN_00009000");
assert.equal(notes.trustedOf(0x1400).name, "renamed_wins", "the pack symbol stays available under a rename");
console.log("Trusted symbol name precedence: passed");

// 7. String Reuse lookup for the Strings view
assert.equal(stringOriginKey("  LummaC2\t Build\n2024 "), "LummaC2 Build 2024");
assert.equal(Array.from(stringOriginKey("x".repeat(300))).length, 200);
const strIndex = buildStringOriginIndex(v3Report);
assert.equal(stringOriginOf(strIndex, "LummaC2   Build 2024"), "malware");
assert.equal(stringOriginOf(strIndex, "shared marker string"), "shared");
assert.equal(stringOriginOf(strIndex, "Microsoft Visual C++ Runtime Library"), "trusted");
assert.equal(stringOriginOf(strIndex, "never seen anywhere"), "unique");
assert.equal(buildStringOriginIndex(sampleReport), null, "BXFAM002 reports hide all string-origin UI");
assert.equal(stringOriginOf(null, "anything"), null);
assert.deepEqual(stringOriginBadge(v3Report.strings.entries[0]).text, "win.lumma");
assert.deepEqual(stringOriginBadge(v3Report.strings.entries[1]).text, "Common malware");
assert.deepEqual(stringOriginBadge(v3Report.strings.entries[2]).text, "Library");
console.log("String Reuse lookup: passed");
