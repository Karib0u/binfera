// The analysis progress bar: stages own fixed shares, so the bar never restarts, and desktop
// (no downloads) uses the whole bar for the work.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypes } from "./strip-types.mjs";

const js = stripTypes(await readFile(new URL("../src/analysisProgress.ts", import.meta.url), "utf8"));
const { overallProgress, downloadProgress } = await import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);

const base = { ready: false, loading: null, image: null, capa: null, capaError: null, capaTooLarge: null, family: null, familyError: null };
// A first visit in the browser, in the order the states arrive.
const timeline = [
  [base, 0],
  [{ ...base, loading: { label: "", fraction: 0, stage: "engine" } }, 0],
  [{ ...base, loading: { label: "", fraction: 1, stage: "engine" } }, 0],
  [{ ...base, image: {} }, 0],
  [{ ...base, image: {}, loading: { label: "", fraction: 0, stage: "data" } }, 0],
  [{ ...base, image: {}, loading: { label: "", fraction: .5, stage: "data" } }, 0],
  [{ ...base, image: {}, loading: { label: "", fraction: 1, stage: "data" } }, 0],
  [{ ...base, image: {}, ready: true }, 0],
  [{ ...base, image: {}, ready: true }, .5],
  [{ ...base, image: {}, ready: true, capa: {} }, 1],
  [{ ...base, image: {}, ready: true, capa: {}, family: {} }, 1],
];
let last = -1;
for (const [a, decompiled] of timeline) {
  const v = overallProgress(a, decompiled, false);
  assert.ok(v >= last, `progress went back from ${last} to ${v}`);
  last = v;
}
assert.equal(last, 1);
// Desktop downloads nothing: the work starts at 0 and fills the bar.
assert.equal(overallProgress({ ...base, ready: true }, 0, true), 0);
assert.equal(overallProgress({ ...base, ready: true }, .5, true), .425);
assert.equal(overallProgress({ ...base, ready: true, capa: {}, family: {} }, 1, true), 1);
// The download step alone also only moves forward across its two parts.
assert.equal(downloadProgress({ ...base, loading: { label: "", fraction: 1, stage: "engine" } }), .3);
assert.equal(downloadProgress({ ...base, image: {} }), .3);
assert.equal(downloadProgress({ ...base, loading: { label: "", fraction: 0, stage: "data" } }), .3);
assert.equal(downloadProgress({ ...base, loading: { label: "", fraction: 1, stage: "data" } }), 1);
console.log("Progress: one forward-only bar across downloads and work; desktop uses the whole bar: passed");
