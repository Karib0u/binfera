// A comparison leaves the app as Markdown, one HTML page or JSON, and pairs made by hand are kept per pair of files.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { fileURLToPath } from "node:url";

const bundle = async (entry) => {
  const out = await build({ entryPoints: [fileURLToPath(new URL(entry, import.meta.url))], bundle: true, format: "esm", write: false, logLevel: "error" });
  return await import(`data:text/javascript;base64,${Buffer.from(out.outputFiles[0].text).toString("base64")}`);
};
const { compareMarkdown, compareHtml, compareJson, compareFileStem } = await bundle("../src/compareReport.ts");
const { loadPairs, savePairs } = await bundle("../src/comparePairs.ts");
const { manualPair } = await bundle("../src/compareModel.ts");

const input = (name, sha) => ({ name, size: 4096, sha256: sha, format: "pe", arch: "x86", image_base: 0x400000, entry: null, functions: 12, instructions: 900, packed: false, source: "file" });
const match = (a, b, extra = {}) => ({ a_addr: a, b_addr: b, a_name: null, b_name: null, method: "fuzzy", confidence: 1, similarity: 0.7, changed: true, reasons: [], a_instructions: 20, b_instructions: 24, evidence: { same_instructions: false, same_cfg: true, blocks: [1, 1], edges: [0, 0], imports_only_b: ["CreateFileW"] }, ...extra });
const doc = {
  verdict: "changed", inputs: [input("old<script>.exe", "a".repeat(64)), input("new|build.exe", "b".repeat(64))], warnings: ["Different image bases"], functions_compared: true,
  file_delta: { sections: { added: [".new"], removed: [], changed: [{ name: ".text", changes: ["size 1 → 2"] }] }, imports: { added: ["kernel32!CreateFileW"], removed: [], changed: [] }, exports: { added: [], removed: [], changed: [] }, resources: { added: [], removed: [], changed: [] }, overlay: [], imphash: ["x", "y"] },
  matches: [match(0x10, 0x20, { a_name: "main" })],
  unmatched_a: [{ address: 0x40, name: null, instructions: 7 }],
  unmatched_b: [{ address: 0x90, name: "payload", instructions: 30, rules: ["encode data using XOR"] }],
  capability_delta: { added: [{ name: "encode data using XOR", attack: ["T1027"], namespace: null, scope: "function", mbc: [], addresses: [], functions: [] }], removed: [], retargeted: [], unchanged: 3, unmapped: 0, attack_added: [], attack_removed: [], similarity: 0.5 },
  similarity: { overall: 0.62, code: 0.7, imports: 0.5, strings: null, capabilities: 0.5 },
};

const md = compareMarkdown(doc);
assert.match(md, /^# Comparison of old\\<script\\>\.exe and new\\\|build\.exe/, "names are escaped in Markdown");
for (const heading of ["Summary", "Files", "Similarity", "Warnings", "Capabilities", "File contents", "Changed functions (3)"]) assert.ok(md.includes(`## ${heading}`), heading);
assert.ok(md.includes("Overall 62%") && md.includes("Strings n/a"));
assert.ok(md.includes("Only in B (1)") && md.includes("encode data using XOR \\[T1027\\]"));
assert.ok(md.includes("Added: .new") && md.includes("Changed: .text (size 1 → 2)") && md.includes("Import hash: x → y"));
assert.ok(md.includes("| changed | main (0x10) | 0x20 | Now calls CreateFileW |"), "the matched pair is listed with its name and reason");
assert.ok(!md.includes("Pairs made by hand"));

const html = compareHtml(doc);
assert.ok(html.startsWith("<!doctype html>") && html.includes("prefers-color-scheme"));
assert.ok(!html.includes("<script>"), "file names cannot inject markup");
assert.ok(html.includes("old&lt;script&gt;.exe"));

const hand = manualPair({ address: 0x40, name: null, instructions: 7 }, { address: 0x90, name: "payload", instructions: 30 });
assert.ok(compareMarkdown(doc, [hand]).includes("## Pairs made by hand"));
const json = JSON.parse(compareJson(doc, [hand]));
assert.deepEqual(json.manual_pairs, [{ a: 0x40, b: 0x90 }]);
assert.equal(json.inputs[0].name, "old<script>.exe");
assert.equal(json.changes[0].reason, "Paired by hand");
assert.equal(compareFileStem(doc), "old_script_.exe-vs-new_build.exe");

// Pairs: kept per pair of files, and bad data is ignored.
const store = new Map();
globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) };
assert.deepEqual(loadPairs("a", "b"), []);
savePairs("a", "b", [[1, 2], [3, 4]]);
assert.deepEqual(loadPairs("a", "b"), [[1, 2], [3, 4]]);
assert.deepEqual(loadPairs("b", "a"), [], "another pair of files has its own");
store.set("binfera:pairs:a:c", JSON.stringify([[1, 2], "x", [1.5, 2], [1]]));
assert.deepEqual(loadPairs("a", "c"), [[1, 2]]);
store.set("binfera:pairs:a:d", "not json");
assert.deepEqual(loadPairs("a", "d"), []);
savePairs("a", "b", []);
assert.equal(store.has("binfera:pairs:a:b"), false, "no pairs leaves nothing behind");
console.log("Comparison report (Markdown, HTML, JSON) and persisted manual pairs: passed");
