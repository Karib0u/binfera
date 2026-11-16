// A report is shared with other people and its text comes from an untrusted file, so escaping and the summary's shape are pinned here.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("../src/report.ts", import.meta.url), "utf8");
const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { csv, reportHtml, reportMarkdown } = await import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);

const input = {
  fileName: "evil<script>.exe", size: 8192, sha256: "ab".repeat(32), format: "pe", os: "windows", arch: "amd64",
  toolchains: ["Go"], packed: "UPX",
  findings: [{ severity: "info", text: "note" }, { severity: "warn", text: "Section .text is writable" }],
  signatures: [],
  capabilities: [
    { name: "encode data using XOR", attack: ["T1027"], tactic: "Defense Evasion", matches: 2, functions: ["FUN_1", "FUN_2"] },
    { name: "get hostname", attack: [], tactic: "Discovery", matches: 1, functions: [] },
    { name: "query registry", attack: [], tactic: "Discovery", matches: 1, functions: [] },
  ],
  indicators: [{ kind: "URLs", values: ["http://x.test/<b>"] }],
  sections: [{ name: ".text", address: "0x1000", size: 4096, perms: "r-x", entropy: 6.1 }],
  starred: ["main"], stringsShown: 20000, stringsTotal: 24567,
  comments: [{ address: "0x1000", source: "human", text: "checks <script> & config" }],
};

const md = reportMarkdown(input);
assert.ok(md.includes("## Comments") && md.includes("0x1000 (You): checks "), "analyst comments are in the Markdown report");
assert.ok(md.includes("## Findings") && md.includes("## Capabilities (3)") && md.includes("| .text |"));
assert.ok(md.indexOf("Review: Section .text") < md.indexOf("- note"), "warnings come before notes");
assert.ok(md.indexOf("Discovery (2)") < md.indexOf("Defense Evasion (1)"), "tactics with more capabilities come first");
assert.ok(md.includes("\\[T1027\\] in FUN\\_1, FUN\\_2"), "ATT&CK ids and function names are listed with the capability");
assert.ok(!md.includes("<script>"), "markdown escapes angle brackets from the file name");

const page = reportHtml(input);
for (const report of [md, page]) assert.ok(report.includes("Showing the first 20,000 of 24,567 strings, by address"));
assert.ok(page.includes("0x1000 (You): checks &lt;script&gt; &amp; config"), "analyst comments are escaped in HTML reports");
assert.ok(!page.includes("<script>") && page.includes("evil&lt;script&gt;.exe"), "the file name cannot inject markup");
assert.ok(page.includes("http://x.test/&lt;b&gt;"), "indicator values are escaped");
assert.ok(!/src=|href=|https?:\/\/(?!x\.test)/.test(page), "the page loads nothing from outside");

assert.equal(csv(["a", "b"], [["x,y", 'he said "hi"'], ["=SUM(A1)", 3]]), 'a,b\r\n"x,y","he said ""hi"""\r\n\'=SUM(A1),3\r\n');
console.log("report checks passed");
