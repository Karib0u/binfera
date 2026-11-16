// The text diff decides what a reader believes changed, so what must and must not read as a change is pinned here.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("../src/textdiff.ts", import.meta.url), "utf8");
const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { cKey, diffLines, diffWords, folded, localNames, withLocals } = await import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);

const statuses = (rows) => rows.map((r) => r.status);

assert.deepEqual(statuses(diffLines(["a", "b"], ["a", "b"])), ["same", "same"]);
assert.deepEqual(statuses(diffLines(["a"], ["a", "added line"])), ["same", "added"]);
assert.deepEqual(statuses(diffLines(["gone", "a"], ["a"])), ["removed", "same"]);

// A line with a new value is one changed line, not a removal and an unrelated addition.
const changed = diffLines(["return x ^ 0x13c6ef37;"], ["return x ^ 0x5a17c3e1;"]);
assert.deepEqual(statuses(changed), ["changed"]);
assert.equal(changed[0].aLine, 1);
assert.equal(changed[0].bLine, 1);
// Unrelated lines stay apart.
assert.deepEqual(statuses(diffLines(["int total = 0;"], ["while (node != NULL) {"])), ["removed", "added"]);

const [left, right] = diffWords("return x ^ 0x13c6ef37;", "return x ^ 0x5a17c3e1;");
assert.deepEqual(left.filter((p) => p.changed).map((p) => p.text), ["0x13c6ef37"]);
assert.deepEqual(right.filter((p) => p.changed).map((p) => p.text), ["0x5a17c3e1"]);

// A moved function reads as the same; a redirected call must not, or the C view would hide it.
const forward = new Map([[0x1000, 0x2000], [0x1100, 0x2100]]);
assert.equal(cKey("FUN_00001000(x);", "a", forward), cKey("FUN_00002000(x);", "b", forward));
assert.notEqual(cKey("FUN_00001000(x);", "a", forward), cKey("FUN_00002100(x);", "b", forward));
// A callee with no counterpart differs from anything in B.
assert.notEqual(cKey("FUN_00003000(x);", "a", forward), cKey("FUN_00003000(x);", "b", forward));
// Data that only moved reads as the same.
assert.equal(cKey("x = DAT_00404000;", "a", forward), cKey("x = DAT_00505000;", "b", forward));
// A constant is not an address.
assert.notEqual(cKey("x = 0x10;", "a", forward), cKey("x = 0x11;", "b", forward));

const same = (r) => r === "=";
const rows = [...Array(20).fill("="), "x", ...Array(20).fill("=")];
const items = folded(rows, same, new Set());
assert.deepEqual(items.filter((i) => "fold" in i).map((i) => i.fold), [17, 17]);
assert.equal(items.filter((i) => "row" in i && i.row === "x").length, 1);
// Opening a fold shows every line it held.
const opened = folded(rows, same, new Set([0]));
assert.deepEqual(opened.filter((i) => "fold" in i).map((i) => i.fold), [17]);
// Everything shown or folded adds back up to the input.
const total = (list) => list.reduce((n, i) => n + ("fold" in i ? i.fold : 1), 0);
assert.equal(total(items), rows.length);
assert.equal(total(opened), rows.length);
// Short unchanged runs are not worth folding.
assert.equal(folded(["=", "=", "x"], same, new Set()).every((i) => "row" in i), true);

console.log("Text diff, callee keys and folding: passed");

// The same code with other variable numbers is the same; the operands swapped is not.
const localKeys = (lines) => { const names = localNames(lines); return (l) => withLocals(l, names); };
const before = ["{", "  DWORD DVar1;", "  DWORD DVar2;", "", "  DVar1 = f();", "  DVar2 = g();", "  return DVar2 - DVar1;", "}"];
const renumbered = ["{", "  DWORD DVar3;", "  DWORD DVar5;", "", "  DVar3 = f();", "  DVar5 = g();", "  return DVar5 - DVar3;", "}"];
const swapped = ["{", "  DWORD DVar1;", "  DWORD DVar2;", "", "  DVar1 = f();", "  DVar2 = g();", "  return DVar1 - DVar2;", "}"];
assert.ok(diffLines(before, renumbered, localKeys(before), localKeys(renumbered)).every((r) => r.status === "same"));
assert.ok(diffLines(before, swapped, localKeys(before), localKeys(swapped)).some((r) => r.status !== "same"));
// Word marks follow the same keys: only what differs once names are set aside is marked.
const wordNames = [localNames(["", "DVar2 = Sleep(500);"]), localNames(["", "DVar7 = Sleep(2000);"])];
const [wa] = diffWords("DVar2 = Sleep(500);", "DVar7 = Sleep(2000);", (t) => wordNames[0].get(t) ?? t, (t) => wordNames[1].get(t) ?? t);
assert.deepEqual(wa.filter((p) => p.changed).map((p) => p.text), ["500"]);
