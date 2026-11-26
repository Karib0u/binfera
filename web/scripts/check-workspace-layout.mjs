import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypes } from "./strip-types.mjs";

const source = await readFile(new URL("../src/workspace/location.ts", import.meta.url), "utf8");
const js = stripTypes(source);
const { panesOf, parseHash, hashOf, locOf } = await import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);

for (const layout of ["c+asm", "c+asm+graph", "c+asm+graph+hex", "c+asm+graph+hex+calls", "c+asm+graph+hex+calls+listing+strings+imports", "c+c+hex"]) {
  const target = parseHash(hashOf("sample", locOf(0x401000), layout, 0x402000));
  assert.equal(target.layout, layout);
  assert.equal(target.sel, 0x401000);
  assert.equal(target.at, 0x402000);
  assert.deepEqual(panesOf(layout), layout.split("+"));
}
assert.deepEqual(panesOf("split"), ["c", "asm"]);
assert.deepEqual(panesOf("unknown"), ["c", "asm"]);
assert.deepEqual(panesOf("c+unknown+hex"), ["c", "hex"]);
assert.deepEqual(panesOf("__proto__+constructor"), ["c", "asm"]);
assert.equal(parseHash("#fn=0x401000&view=c%2Bhex%2Bstrings").layout, "c+hex+strings");
console.log("Multiple panes, duplicate views, shared links, and legacy layouts: passed");

const treeSource = await readFile(new URL("../src/workspace/paneTree.ts", import.meta.url), "utf8");
const treeJs = stripTypes(treeSource);
const { treeOf, panesIn, splitPane, movePane, withoutPane, dropSideAt, applyLayout, peekTree } = await import(`data:text/javascript;base64,${Buffer.from(treeJs).toString("base64")}`);
const leaves = ["c", "asm", "graph", "hex", "strings"].map((view, id) => ({ id, view, place: id === 1 ? { address: 0x401000, cursor: 0x401004 } : null }));
const tree = treeOf(leaves);
for (const source of leaves) for (const target of leaves) for (const side of ["left", "right", "top", "bottom", "center"]) {
  const moved = panesIn(movePane(tree, source.id, target.id, side));
  assert.equal(moved.length, leaves.length);
  assert.deepEqual(moved.map((p) => p.id).sort(), leaves.map((p) => p.id));
  assert.equal(moved.find((p) => p.id === 1).place, leaves[1].place);
}
assert.deepEqual(panesIn(movePane(tree, 0, 1, "center")).map((p) => p.id), [1, 0, 2, 3, 4]);
for (const axis of ["vertical", "horizontal"]) {
  const split = splitPane(leaves[0], 0, { id: 5, view: "c", place: null }, axis);
  assert.equal(split.axis, axis);
  assert.deepEqual(panesIn(split).map((p) => p.id), [0, 5]);
  assert.deepEqual(withoutPane(split, 5), leaves[0]);
}
assert.equal(withoutPane(leaves[0], 0), null);
console.log("Horizontal/vertical splits, edge docking, swapping, independent positions, and closing: passed");

assert.equal(dropSideAt(.5, .5), "center");
assert.equal(dropSideAt(.05, .5), "left");
assert.equal(dropSideAt(.95, .6), "right");
assert.equal(dropSideAt(.5, .05), "top");
assert.equal(dropSideAt(.4, .95), "bottom");
assert.equal(dropSideAt(.1, .2), "left");
console.log("Drop zones: passed");

// Panes the app opens never rearrange the analyst's: a peek is a column around the whole tree, a
// later peek reuses it, and closing it gives back the same tree, ratios included.
{
  let id = 100;
  const newId = () => id++;
  const arranged = { axis: "vertical", ratio: .37, first: { axis: "horizontal", ratio: .62, first: { id: 1, view: "c", place: null }, second: { id: 2, view: "asm", place: null } }, second: { id: 3, view: "listing", place: null } };
  assert.equal(peekTree(arranged, "listing", newId), null, "a view already open needs no pane");
  const hexed = peekTree(arranged, "hex", newId);
  assert.equal(hexed.reused, false);
  assert.deepEqual(hexed.tree.first, arranged, "the arrangement is kept whole inside the new split");
  assert.equal(hexed.tree.second.view, "hex");
  assert.equal(hexed.tree.second.peek, true);
  const stringed = peekTree(hexed.tree, "strings", newId);
  assert.equal(stringed.reused, true, "a second lookup reuses the peek pane");
  assert.deepEqual(panesIn(stringed.tree).map((p) => p.view), ["c", "asm", "listing", "strings"]);
  assert.deepEqual(withoutPane(stringed.tree, stringed.tree.second.id), arranged, "closing the peek pane restores the tree exactly");
  // The analyst's own Strings pane is never taken over: with no peek pane, a new one is added.
  const own = { axis: "vertical", ratio: .5, first: { id: 1, view: "c", place: null }, second: { id: 2, view: "strings", place: null } };
  assert.deepEqual(panesIn(peekTree(own, "hex", newId).tree).map((p) => p.view), ["c", "strings", "hex"]);
  // A layout from outside changes only what differs.
  assert.equal(applyLayout(arranged, ["c", "asm", "listing"], newId), arranged);
  const swapped = applyLayout(arranged, ["c", "asm", "graph"], newId);
  assert.equal(swapped.ratio, .37);
  assert.equal(swapped.first.ratio, .62);
  assert.deepEqual(panesIn(swapped).map((p) => p.view), ["c", "asm", "graph"]);
  const added = applyLayout({ id: 1, view: "c", place: null }, ["c", "asm"], newId);
  assert.deepEqual(panesIn(added).map((p) => p.view), ["c", "asm"]);
  assert.equal(added.axis, "vertical");
  assert.deepEqual(applyLayout(added, ["c"], newId), { id: 1, view: "c", place: null });
}
console.log("Peek panes and minimal layout changes: passed");
