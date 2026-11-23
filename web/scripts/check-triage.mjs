// The function list's triage order: importance, bottom-up depth and the examined / documented progress.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { fileURLToPath } from "node:url";

const bundle = async (entry) => {
  const out = await build({ entryPoints: [fileURLToPath(new URL(entry, import.meta.url))], bundle: true, format: "esm", write: false, logLevel: "error" });
  return await import(`data:text/javascript;base64,${Buffer.from(out.outputFiles[0].text).toString("base64")}`);
};
const { importance, callDepths, progress, triageFunctions } = await bundle("../src/triage.ts");

// main -> payload -> (crypt, send) ; crypt -> helper ; helper <-> loop (a cycle) ; lib is library code.
const fns = [
  { address: 1, lines: 10, calls: [2] },
  { address: 2, lines: 400, calls: [3, 4] },
  { address: 3, lines: 20, calls: [5] },
  { address: 4, lines: 5, calls: [] },
  { address: 5, lines: 5, calls: [6] },
  { address: 6, lines: 5, calls: [5] },
  { address: 7, lines: 5, calls: [] },
];
const depth = callDepths(fns);
assert.equal(depth.get(4), 0, "a leaf is depth 0");
assert.ok(depth.get(3) > depth.get(5), "a caller sits above its callee");
assert.equal(depth.get(2), 1 + Math.max(depth.get(3), depth.get(4)));
assert.equal(depth.get(1), 1 + depth.get(2));
assert.equal(depth.size, fns.length, "a cycle terminates and every function gets a depth");
const chain = Array.from({ length: 50000 }, (_, i) => ({ address: i, lines: 0, calls: i ? [i - 1] : [] }));
assert.equal(callDepths(chain).get(49999), 49999, "a very deep chain does not overflow the stack");

const scores = importance({
  functions: fns,
  capabilities: new Map([[2, 3]]),
  strings: new Map([[3, 4]]),
  imports: new Map([[4, 2]]),
  callers: new Map([[4, [2, 3, 5]]]),
});
const ranked = [...scores].sort((x, y) => y[1].score - x[1].score).map(([ad]) => ad);
assert.equal(ranked[0], 2, "capability matches outweigh everything else");
assert.deepEqual(scores.get(2), { capabilities: 3, strings: 0, imports: 0, callers: 0, score: 30 + 5 });
assert.equal(scores.get(4).score, 2 * 2 + 3, "imports weigh double, callers once");
assert.equal(scores.get(7).score, 0);

const hidden = triageFunctions({ order: [1, 2], functions: new Map([[1, { text: "a\nb" }], [2, { calls: [9] }]]) }, new Map([[1, [2]]]));
assert.deepEqual(hidden, [{ address: 1, lines: 2, calls: [2] }, { address: 2, lines: 0, calls: [9] }]);

const p = progress([1, 2, 3, 4], new Set([4]), (ad) => ad <= 2, (ad) => ad === 2 || ad === 4);
assert.deepEqual(p, { total: 3, examined: 2, documented: 1 }, "library functions are not counted");
console.log("Triage: importance, bottom-up depth and progress: passed");
