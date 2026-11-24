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
globalThis.fetch = originalFetch;
console.log("Family pack magic validation and custom pack loading: passed");

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
  export const loadFamilyPack = async () => new Uint8Array(48).buffer;
  export const setCustomFamilyPack = () => {};
  export const extractStrings = () => ({ strings: [], total: 0 });
  export const summarizeCapa = (json) => json;
  export const createImage = () => null;
  export const loadAssets = async () => ({ module: {}, data: () => ({}), rules: {} });
  export async function runEngine(req, onLine) {
    requests.push(req.kind);
    if (req.kind === "inspect") onLine(JSON.stringify({ format: "pe", entry: 0x1000, arch: "x86", fidArch: "x86" }));
    else if (req.kind === "capa") onLine(JSON.stringify({ sample: { sha256: "abc" }, rules: [], library: [] }));
    else if (req.kind === "family") onLine(${JSON.stringify(JSON.stringify(sampleReport))});
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
console.log("Analysis pipeline family matching: passed");

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
