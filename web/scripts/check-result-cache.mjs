// IndexedDB persistence and the real analysis replay path, without a wasm build.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { performance } from "node:perf_hooks";
import { indexedDB, IDBKeyRange, IDBObjectStore } from "fake-indexeddb";
import { stripTypes } from "./strip-types.mjs";

Object.assign(globalThis, { indexedDB, IDBKeyRange });
Object.defineProperty(globalThis, "navigator", { value: { hardwareConcurrency: 4, userAgent: "test" }, configurable: true });
const moduleUrl = source => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const compile = async path => stripTypes(await readFile(new URL(path, import.meta.url), "utf8"));
const cacheUrl = moduleUrl(await compile("../src/engine/resultCache.ts"));
const { digest, readResults, writeResults, forgetResults } = await import(cacheUrl);
// Exercise the real engine identity helper: one rules fetch and digest per page load.
const originalFetch = globalThis.fetch;
let rulesFetches = 0;
const rulesBytes = new TextEncoder().encode('{"rule.yml":"fixture rule"}');
globalThis.fetch = async () => { rulesFetches++; return new Response(rulesBytes); };
const assetsSource = (await compile("../src/engine/assets.ts"))
  .replace('from "./resultCache"', `from "${cacheUrl}"`)
  .replace(/^import wasmUrl.*$/m, 'const wasmUrl = "/assets/engine-hash.wasm";')
  .replaceAll("import.meta.env.BASE_URL", '"/"');
const assets = await import(moduleUrl(assetsSource));
const identity = `/assets/engine-hash.wasm:${await digest(rulesBytes.buffer)}`;
assert.equal(await assets.loadEngineId(), identity);
assert.equal(await assets.loadEngineId(), identity);
assert.equal(rulesFetches, 1);
globalThis.fetch = originalFetch;
const blobs = text => Object.fromEntries(["image", "capa", "decomp"].map(kind => [kind, new Blob([text])]));

const inspectDb = async fn => {
  const db = await new Promise((resolve, reject) => {
    const req = indexedDB.open("binfera-results", 1);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  try {
    const tx = db.transaction(["runs", "meta"], "readwrite");
    const done = new Promise((resolve, reject) => { tx.oncomplete = resolve; tx.onabort = () => reject(tx.error); });
    const result = fn(tx);
    await done;
    return result?.result;
  } finally { db.close(); }
};

assert.equal(await digest(new TextEncoder().encode("abc").buffer), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
await writeResults("a", "engine1", blobs("aaa"), 18);
await writeResults("b", "engine1", blobs("bbb"), 18);
await inspectDb(tx => {
  for (const [sha256, lastUsed] of [["a", 1], ["b", 2]]) {
    tx.objectStore("meta").put({ sha256, engineId: "engine1", size: 9, lastUsed });
  }
});
assert.equal(await (await readResults("a", "engine1")).image.text(), "aaa");
await writeResults("c", "engine1", blobs("ccc"), 18);
assert.equal(await readResults("b", "engine1"), null);
assert.ok(await readResults("a", "engine1"));
assert.ok(await readResults("c", "engine1"));
// A quota failure during the write rolls back both eviction and the new output.
const originalPut = IDBObjectStore.prototype.put;
IDBObjectStore.prototype.put = function(value, key) {
  if (this.name === "runs" && String(key).endsWith(":capa")) throw new DOMException("quota", "QuotaExceededError");
  return originalPut.call(this, value, key);
};
await writeResults("quota", "engine1", blobs("new"), 18);
IDBObjectStore.prototype.put = originalPut;
assert.equal(await readResults("quota", "engine1"), null);
assert.ok(await readResults("a", "engine1"));
assert.ok(await readResults("c", "engine1"));
assert.equal(await readResults("a", "engine2"), null);
await writeResults("a", "engine2", blobs("new"), 18);
assert.equal(await readResults("a", "engine1"), null);
assert.equal((await inspectDb(tx => tx.objectStore("runs").getAllKeys())).filter(key => key.startsWith("a:")).length, 3);
await writeResults("oversize", "engine1", blobs("1234567"), 18);
assert.equal(await readResults("oversize", "engine1"), null);
// Missing blobs and output without the commit record are never a full hit.
await inspectDb(tx => {
  tx.objectStore("runs").delete("a:engine2:capa");
  tx.objectStore("runs").put(new Blob(["partial"]), "orphan:engine1:image");
});
assert.equal(await readResults("a", "engine2"), null);
assert.equal(await readResults("orphan", "engine1"), null);
await forgetResults("a");
assert.equal(await readResults("a", "engine2"), null);
console.log("IndexedDB: bounded LRU, touched samples, version replacement, incomplete entries and deletion passed");

const mocksUrl = moduleUrl(`
  export let NATIVE = false;
  export const setNative = value => { NATIVE = value; };
  export const requests = [];
  export let engineId = "wasm1:rules1";
  export const setEngineId = value => { engineId = value; };
  export const loadEngineId = async () => engineId;
  export const winApiFor = () => null;
  export let abortAfterFunction = null;
  export const setAbortAfterFunction = controller => { abortAfterFunction = controller; };
  export let fail = null;
  export const setFailure = value => { fail = value; };
  export class EngineError extends Error {}
  export const TOO_LARGE = 14;
  export const loadEngine = async () => ({});
  export const loadFamilyPack = async () => null;
  export const setCustomFamilyPack = () => {};
  export const loadAssets = async () => ({ module: {}, data: () => ({}), rules: {} });
  export const extractStrings = () => ({ strings: [{ a: 10, s: "example", w: false }], total: 24567 });
  export const summarizeCapa = json => json;
  export const createImage = () => null;
  export async function runEngine(req, onLine, signal) {
    requests.push(req.kind);
    if (signal.aborted) throw new Error("aborted");
    if (req.kind === fail) throw new Error("fixture failure");
    if (req.kind === "inspect") onLine(JSON.stringify({ format: "pe", entry: 10, arch: "x64", fidArch: "x64", warnings: ["image warning"] }));
    else if (req.kind === "capa") onLine(JSON.stringify({ sample: { sha256: "fixture" }, rules: [] }));
    else if (req.kind === "decompileOne") {
      onLine(JSON.stringify({ address: req.address, text: "void retried() {}" }));
    } else {
      onLine(JSON.stringify({ type: "start", functions: [10, 20], names: { "10": "named.first", "20": "large.init" }, arch: "x64" }));
      onLine(JSON.stringify(req.shard[0]
        ? { type: "function", address: 20, retry_pending: true, error: "limit", asm: [[20, "c3", "ret"]] }
        : { type: "function", address: 10, name: "example", text: "void example() {}" }));
      onLine(JSON.stringify({ type: "settled" }));
      onLine(JSON.stringify({ type: "done", warnings: ["stream warning"] }));
      abortAfterFunction?.abort();
    }
  }
`);
const shellcodeUrl = moduleUrl(await compile("../src/engine/shellcode.ts"));
const analysisUrl = moduleUrl((await compile("../src/analyze.ts"))
  .replace('from "./engine/resultCache"', `from "${cacheUrl}"`)
  .replace('from "./engine/shellcode"', `from "${shellcodeUrl}"`)
  .replace(/from "\.\/engine\/[^\"]+"/g, `from "${mocksUrl}"`));
const { analyze } = await import(analysisUrl);
const mocks = await import(mocksUrl);
const file = new File([new Uint8Array(16)], "fixture.exe");
const sampleHash = await digest(await file.arrayBuffer());
const run = async (file, raw, again) => {
  const updates = [];
  await analyze(file, a => updates.push(a), new AbortController().signal, raw, again);
  return updates.at(-1);
};
const first = await run(file);
assert.equal(first.done, true);
assert.equal(first.functions.size, 2);
assert.equal(first.stringsTotal, 24567);
const count = mocks.requests.length;
const replay = await run(new File([await file.arrayBuffer()], "renamed.exe"));
assert.equal(mocks.requests.length, count, "a complete hit must start no worker");
assert.equal(replay.fileName, "renamed.exe");
assert.deepEqual(replay.functions, first.functions);
assert.deepEqual(replay.fileWarnings, ["image warning", "stream warning"]);
assert.deepEqual(replay.capa, first.capa);
assert.deepEqual(replay.strings, first.strings);
assert.equal(replay.stringsTotal, first.stringsTotal, "cache replay retains the full string count");
assert.equal(first.settled, true);
assert.equal(replay.settled, true);
assert.deepEqual(replay.names, first.names);
assert.equal(replay.names.get(20), "large.init");
// Cache hits retain the browser's manual retry, loading engine assets only when requested.
const retryUpdates = [];
await analyze(file, a => retryUpdates.push(a), new AbortController().signal);
assert.equal(mocks.requests.length, count);
await retryUpdates.at(-1).retryFunction(20);
await delay(100);
const retried = retryUpdates.at(-1).functions.get(20);
assert.equal(mocks.requests.at(-1), "decompileOne");
assert.equal(retried.retry_pending, false);
assert.equal(retried.error, undefined);
assert.equal(retried.text, "void retried() {}");
assert.deepEqual(retried.asm, [[20, "c3", "ret"]]);

// Rules and wasm changes independently invalidate results.
for (const engineId of ["wasm1:rules2", "wasm2:rules2"]) {
  const count = mocks.requests.length;
  mocks.setEngineId(engineId);
  await run(file);
  assert.ok(mocks.requests.length > count);
}
let before = mocks.requests.length;
await run(file, undefined, true);
assert.ok(mocks.requests.length > before, "Analyze again bypasses storage");
// Even if deletion is blocked, reanalysis bypasses the old result.
const storage = globalThis.indexedDB;
Object.defineProperty(globalThis, "indexedDB", { configurable: true, get() { throw new Error("storage blocked"); } });
assert.equal(await readResults(sampleHash, mocks.engineId), null);
await writeResults("blocked", mocks.engineId, blobs("data"));
await forgetResults(sampleHash);
before = mocks.requests.length;
assert.equal((await run(file, undefined, true)).done, true);
assert.ok(mocks.requests.length > before);
Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: storage, writable: true });
// Forced formats and native runs skip both reads and writes.
for (const [native, raw] of [[false, { format: "sc32", os: "linux" }], [true, undefined]]) {
  mocks.setNative(native);
  before = mocks.requests.length;
  await run(file, raw);
  assert.ok(mocks.requests.length > before);
}
mocks.setNative(false);
const originalCrypto = globalThis.crypto;
Object.defineProperty(globalThis, "crypto", { configurable: true, value: undefined });
assert.equal(await digest(new ArrayBuffer(0)), null);
before = mocks.requests.length;
assert.equal((await run(file)).done, true);
assert.ok(mocks.requests.length > before);
Object.defineProperty(globalThis, "crypto", { configurable: true, value: originalCrypto });
// Failed kinds must not become reusable.
for (const kind of ["capa", "decompile"]) {
  await forgetResults(sampleHash);
  mocks.setFailure(kind);
  const result = await run(file);
  assert.ok(result[kind === "capa" ? "capaError" : "decompileError"]);
  assert.equal(await readResults(sampleHash, mocks.engineId), null);
  mocks.setFailure(null);
}
await forgetResults(sampleHash);
const cancelled = new AbortController();
mocks.setAbortAfterFunction(cancelled);
await analyze(file, () => assert.fail("an aborted live run published an update"), cancelled.signal);
mocks.setAbortAfterFunction(null);
assert.equal(await readResults(sampleHash, mocks.engineId), null);
await run(file);
// Corrupt NDJSON falls back to workers with no stale functions left behind.
await inspectDb(tx => tx.objectStore("runs").put(new Blob([
  '{"type":"function","address":999,"name":"stale"}\ninvalid json',
]), `${sampleHash}:${mocks.engineId}:decomp`));
before = mocks.requests.length;
const repaired = await run(file);
assert.ok(mocks.requests.length > before);
assert.equal(repaired.functions.has(999), false);
assert.equal(repaired.stringsTotal, 24567);
// Replay yields and checks cancellation between slices.
const large = Array.from({ length: 1000 }, (_, address) => JSON.stringify({ type: "function", address, name: "fn" })).join("\n");
await inspectDb(tx => tx.objectStore("runs").put(new Blob([large]), `${sampleHash}:${mocks.engineId}:decomp`));
const controller = new AbortController(), updates = [];
const replaying = analyze(file, a => updates.push(a), controller.signal);
setTimeout(() => controller.abort(), 1);
await replaying;
await delay(100);
assert.equal(updates.length, 0);
console.log("Analysis: worker-free replay, warnings, invalidation, reanalysis, failure/corruption fallback and cancellation passed");
// Hive-sized replay workload, using the real onLine batching path.
await writeResults(sampleHash, mocks.engineId, {
  image: new Blob([JSON.stringify({ format: "pe", arch: "x64", fidArch: "x64", entry: 0 })]),
  capa: new Blob(['{"rules":[]}']),
  decomp: new Blob([Array.from({ length: 2324 }, (_, address) => JSON.stringify({
    type: "function", address, name: "function_" + address, text: "/* decompiled */\n".repeat(500),
  })).join("\n")]),
});
before = mocks.requests.length;
const start = performance.now();
assert.equal((await run(file)).functions.size, 2324);
assert.equal(mocks.requests.length, before);
console.log(`2324-function cached replay: ${Math.round(performance.now() - start)} ms (synthetic, no engine or UI)`);
