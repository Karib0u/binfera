// What a comparison says first decides what a reader looks at, so its wording and order are pinned here.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("../src/compareModel.ts", import.meta.url), "utf8");
const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const m = await import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);

const evidence = (extra = {}) => ({ same_instructions: false, same_cfg: true, blocks: [1, 1], edges: [0, 0], ...extra });
const match = (a, b, extra = {}, ev = {}) => ({ a_addr: a, b_addr: b, a_name: null, b_name: null, method: "fuzzy", confidence: 1, similarity: 0.7, changed: true, reasons: [], a_instructions: 20, b_instructions: 20, evidence: evidence(ev), ...extra });
const doc = {
  verdict: "changed", inputs: [{}, {}], warnings: [], functions_compared: true,
  file_delta: { sections: { added: [], removed: [], changed: [] }, imports: { added: ["advapi32!GetUserNameW"], removed: ["kernel32!IsDebuggerPresent"], changed: [] }, exports: { added: [], removed: [], changed: [] }, resources: { added: [], removed: [], changed: [] }, overlay: [], imphash: null },
  matches: [
    match(0x10, 0x10, {}, { imports_only_a: ["IsDebuggerPresent"] }),
    match(0x20, 0x28, { a_instructions: 200, b_instructions: 260 }, { callees_only_b: [{ address: 0x90, name: null, instructions: 9 }] }),
    match(0x30, 0x38, {}, { strings_only_a: ["report.txt"], strings_only_b: ["report-v2.dat"] }),
    match(0x40, 0x48, { changed: false }),
    match(0x50, 0x58, { a_instructions: 5, b_instructions: 7 }, { same_cfg: false }),
  ],
  unmatched_a: [],
  unmatched_b: [{ address: 0x80, name: null, instructions: 38, rules: ["encode data using XOR"] }, { address: 0x90, name: null, instructions: 48 }, { address: 0xa0, name: null, instructions: 15, rules: ["get session user name"], imports: ["GetUserName"] }],
  capability_delta: { added: [{ name: "get session user name" }], removed: [], retargeted: [], unchanged: 6, unmapped: 0, attack_added: [], attack_removed: [], similarity: 0.8 },
  similarity: { overall: 0.8, code: 0.8, imports: 0.8, strings: 0.4, capabilities: 0.8 },
};

// What matters first: capabilities, then imports, then new callees and strings, then plain code.
const changes = m.changesOf(doc);
assert.deepEqual(changes.map((c) => m.addressOf(c.target, "b") ?? m.addressOf(c.target, "a")), [0xa0, 0x80, 0x10, 0x28, 0x38, 0x90, 0x58]);
const said = Object.fromEntries(changes.map((c) => [c.key, c.reason]));
assert.equal(said["m:16:16"], "No longer calls IsDebuggerPresent");
assert.equal(said["m:32:40"], "Now calls 1 new function");
assert.equal(said["m:48:56"], 'String "report.txt" is now "report-v2.dat"');
assert.equal(said["m:80:88"], "Control flow changed, 5 → 7 instructions");
assert.equal(said["b:160"], "get session user name. Calls GetUserName");
assert.ok(!changes.some((c) => c.key === "m:64:72"), "an unchanged pair is not a change");

// The headline says what happened; a rule that also matches elsewhere is not lost from view.
const s = m.summaryOf(doc);
assert.equal(s.headline, "B adds 1 capability and 3 functions and changes 4 functions.");
assert.ok(s.details.includes("Imports: +GetUserNameW, −IsDebuggerPresent"));
assert.ok(s.details.includes("New code also matches: encode data using XOR"));
assert.equal(m.summaryOf({ ...doc, verdict: "identical" }).headline, "The two files are byte for byte the same.");
assert.match(m.summaryOf({ ...doc, functions_compared: false }).headline, /different architectures/);

// Each function finds its other half, and one with none says so.
assert.equal(m.counterpart(doc, "a", 0x20), 0x28);
assert.equal(m.counterpart(doc, "b", 0x28), 0x20);
assert.equal(m.counterpart(doc, "b", 0x80), null);
assert.equal(m.marksOf(doc, "b").get(0x80), "added");
assert.equal(m.marksOf(doc, "a").get(0x40), "same");

// A pair made by hand replaces what the engine said about both of its functions.
const hand = m.manualPair({ address: 0x10, name: null, instructions: 20 }, { address: 0x80, name: null, instructions: 38 });
assert.equal(m.counterpart(doc, "a", 0x10, [hand]), 0x80);
assert.equal(m.counterpart(doc, "b", 0x10, [hand]), null);
assert.equal(m.marksOf(doc, "b", [hand]).get(0x10), "added", "its old partner now has none");
assert.equal(m.marksOf(doc, "b", [hand]).get(0x80), "changed");
assert.ok(!m.changesOf(doc, [hand]).some((c) => c.key === "b:128" || c.key === "m:16:16"));
assert.equal(m.changesOf(doc, [hand])[0].reason, "Paired by hand");

// The strings list is what the strings score was made from.
const facts = (...strings) => ['{"record":"header"}', JSON.stringify({ record: "function", refs: strings.map((v) => ({ k: "str", v })).concat({ k: "api", v: "Sleep" }) })].join("\n");
assert.deepEqual(m.stringsDelta(m.referencedStrings(facts("x", "gone")), m.referencedStrings(facts("x", "new"))), { removed: ["gone"], added: ["new"], same: 1 });

console.log("Comparison wording, order and pairing: passed");
