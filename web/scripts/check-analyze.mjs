// Exercise worker event ordering without downloading or instantiating the engine.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { setImmediate, setTimeout as delay } from "node:timers/promises";
import { stripTypes } from "./strip-types.mjs";

const moduleUrl = (source) => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const shellcodeModule = moduleUrl(stripTypes(await readFile(new URL("../src/engine/shellcode.ts", import.meta.url), "utf8")));
const { summarizeCapa } = await import(moduleUrl(stripTypes(await readFile(new URL("../src/engine/capa.ts", import.meta.url), "utf8"))));
const absolute = (value) => ({ type: "absolute", value });
const feature = (type, value, children = [], success = true) => ({
  success, node: { type: "feature", feature: { type } }, children, locations: [absolute(value)],
});
const [rule] = summarizeCapa({
  meta: { sample: {}, analysis: { base_address: absolute(0x1000) } },
  rules: { fixture: { meta: { name: "fixture", scopes: { static: "function" } }, matches: [
    [absolute(0x1010), feature("match", 0x1010, [feature("api", 0x1018), feature("api", 0x101e, [], false)])],
    [absolute(0x1040), feature("api", 0x104c)],
  ] } },
}, 0).rules;
assert.deepEqual(rule.addresses, [0x10, 0x40]);
assert.deepEqual([...rule.evidence], [[0x10, [0x18]], [0x40, [0x4c]]]);
console.log("Capability evidence follows nested matches and uses rebased instruction addresses: passed");

const mocks = moduleUrl(`
  export const workers = [];
  export const requests = [];
  export const metadata = { entry: null, fidArch: null };
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
  export const loadFamilyPack = async () => null;
  export const setCustomFamilyPack = () => {};
  export const extractStrings = () => ({ strings: [], total: 0 });
  export const summarizeCapa = json => json;
  export const createImage = () => null;
  export const loadAssets = async () => ({ module: {}, data: () => ({}), rules: {} });
  export function runEngine(req, onLine) {
    requests.push(req);
    if (req.kind === "inspect") { onLine(JSON.stringify({ ...metadata, format: req.raw?.format ?? metadata.format })); return Promise.resolve(); }
    if (req.kind === "capa") { onLine("{}"); return Promise.resolve(); }
    return new Promise(resolve => workers.push({
      emit: event => onLine(JSON.stringify(event)), resolve,
    }));
  }
`);
const source = await readFile(new URL("../src/analyze.ts", import.meta.url), "utf8");
const compiled = stripTypes(source).replace('from "./engine/shellcode"', `from "${shellcodeModule}"`).replace(/from "\.\/engine\/[^\"]+"/g, `from "${mocks}"`);
const { analyze } = await import(moduleUrl(compiled));
const { workers, requests, metadata } = await import(mocks);
Object.defineProperty(globalThis, "navigator", { value: { hardwareConcurrency: 4 }, configurable: true });

const updates = [];
const run = analyze(new File([new Uint8Array(16)], "fixture"), a => updates.push(a), new AbortController().signal);
await setImmediate();
assert.equal(workers.length, 2);
workers[0].emit({ type: "start", functions: [10, 20] });
workers[0].emit({ type: "function", address: 30, name: "extra" });
// This shard starts after an extra callee has already arrived.
workers[1].emit({ type: "start", functions: [10, 20] });
workers[1].emit({ type: "function", address: 30, name: "duplicate" });
workers[1].emit({ type: "function", address: 10, name: "listed" });
for (const worker of workers) worker.resolve();
await run;
const result = updates.at(-1);
assert.equal(result.done, true);
assert.deepEqual(result.order, [10, 20, 30]);
assert.equal(result.functions.size, 2);
assert.equal(result.functions.get(30).name, "extra");
console.log("Function membership and interleaved worker starts: passed");

// Globals filled by GetProcAddress with a literal name arrive on the start record, once per shard,
// and read like import slots with no library.
const { resolvedSlots, slotSource } = await import(moduleUrl(stripTypes(await readFile(new URL("../src/resolved.ts", import.meta.url), "utf8"))));
const resolvedUpdates = [];
const resolvedRun = analyze(new File([new Uint8Array(16)], "resolved"), a => resolvedUpdates.push(a), new AbortController().signal);
await setImmediate();
const resolvedFirst = workers.length - 2;
workers[resolvedFirst].emit({ type: "start", functions: [10], resolved: { "4259968": "ReadFile", "4259972": "WriteFile" } });
workers[resolvedFirst + 1].emit({ type: "start", functions: [10], resolved: { "4259968": "ReadFile", "4259972": "WriteFile" } });
for (const worker of workers.slice(resolvedFirst)) worker.resolve();
await resolvedRun;
const resolvedResult = resolvedUpdates.at(-1);
assert.deepEqual([...resolvedResult.resolved], [[4259968, "ReadFile"], [4259972, "WriteFile"]]);
assert.deepEqual(resolvedSlots(resolvedResult.resolved), [{ dll: "", name: "ReadFile", va: 4259968 }, { dll: "", name: "WriteFile", va: 4259972 }]);
assert.deepEqual(resolvedSlots(undefined), []);
assert.equal(slotSource({ dll: "" }), "resolved at run time");
assert.equal(slotSource({ dll: "KERNEL32.dll" }), "KERNEL32.dll");
console.log("Resolved API slots reach the analysis and read like imports: passed");

// Cancelling while a throttled update is pending must not reopen the previous analysis.
const cancelledUpdates = [];
const controller = new AbortController();
const firstWorker = workers.length;
const cancelledRun = analyze(new File([new Uint8Array(16)], "cancelled"),
  a => cancelledUpdates.push(a), controller.signal);
await setImmediate();
controller.abort();
for (const worker of workers.slice(firstWorker)) worker.resolve();
await cancelledRun;
await delay(100);
assert.equal(cancelledUpdates.length, 0);
console.log("Cancelled analysis discards queued progress updates: passed");

// A guessed raw format must reach both capability recovery and every decompiler shard.
metadata.format = "sc64";
for (const override of [undefined, { format: "sc32", os: "linux" }, { format: "sc64", os: "windows", offset: 4 }]) {
  const start = workers.length, requestStart = requests.length, updates = [];
  const input = Uint8Array.from({ length: 16 }, (_, i) => i);
  const run = analyze(new File([input], "raw.bin"), a => updates.push(a), new AbortController().signal, override);
  await setImmediate();
  for (const worker of workers.slice(start)) worker.resolve();
  await run;
  const expected = override ?? { format: "sc64", os: "windows" };
  const result = updates.at(-1);
  assert.equal(result.shellcode.format, expected.format);
  assert.equal(result.shellcode.os, expected.os);
  assert.equal(result.shellcode.guessed, !override);
  assert.equal(result.shellcode.offset, override?.offset);
  assert.equal(workers.length - start, 1);
  for (const request of requests.slice(requestStart).filter(r => r.kind !== "inspect")) {
    assert.deepEqual(request.raw, { format: expected.format, os: expected.os });
    assert.equal(request.sample.byteLength, 16 - (override?.offset ?? 0));
    assert.deepEqual([...new Uint8Array(request.sample)], [...input.slice(override?.offset ?? 0)]);
  }
}
console.log("Guessed shellcode and explicit architecture/OS reach all analysis workers: passed");

metadata.shellcode = { os: "linux", ambiguous: true, evidence: ["Linux int 0x80"] };
const requestStart = requests.length, start = workers.length, decodedUpdates = [];
const decodedRun = analyze(new File(["31 c0 cd 80"], "shellcode.txt"), a => decodedUpdates.push(a), new AbortController().signal);
await setImmediate();
for (const worker of workers.slice(start)) worker.resolve();
await decodedRun;
assert.equal(decodedUpdates.at(-1).shellcode.os, "linux");
assert.equal(decodedUpdates.at(-1).shellcode.osDetected, true);
assert.equal(decodedUpdates.at(-1).shellcode.encoding, "hex text");
for (const request of requests.slice(requestStart)) assert.deepEqual([...new Uint8Array(request.sample)], [0x31, 0xc0, 0xcd, 0x80]);
console.log("Hex input is decoded for every worker; inferred Linux convention is applied: passed");

// All shards must settle; a done record from an older engine also settles its shard.
metadata.format = "pe";
const stageStart = workers.length, stagedUpdates = [];
const stagedRun = analyze(new File([new Uint8Array(16)], "staged.bin"),
  a => stagedUpdates.push(a), new AbortController().signal);
await setImmediate();
const [left, right] = workers.slice(stageStart);
left.emit({ type: "start", functions: [10, 20], names: { "10": "named.before.decompilation", "20": "large.init" } });
left.emit({ type: "function", address: 20, error: "native work limit exceeded", retry_pending: true, asm: [[20, "c3", "ret"]], calls: [10] });
left.emit({ type: "settled" });
await delay(100);
assert.equal(stagedUpdates.at(-1).settled, false);
assert.equal(stagedUpdates.at(-1).names.get(10), "named.before.decompilation");
const beforeSettled = stagedUpdates.at(-1);
right.emit({ type: "done" });
await delay(100);
assert.equal(stagedUpdates.at(-1).settled, true);
assert.equal(stagedUpdates.at(-1).done, false);
assert.equal(stagedUpdates.at(-1).functions, beforeSettled.functions);
assert.equal(stagedUpdates.at(-1).names, beforeSettled.names);
// A longer attempt replaces the pending record. Later shard duplicates cannot replace it.
left.emit({ type: "function", address: 20, text: "void large_init(void) {}" });
right.emit({ type: "function", address: 20, error: "duplicate" });
left.emit({ type: "function", address: 10, error: "native work limit exceeded", retry_pending: true, asm: [[10, "c3", "ret"]], calls: [20] });
left.resolve(); right.resolve();
await stagedRun;
assert.equal(stagedUpdates.at(-1).functions.get(20).text, "void large_init(void) {}");
assert.equal(beforeSettled.functions.get(20).retry_pending, true);
const retry = stagedUpdates.at(-1).retryFunction(10);
await setImmediate();
assert.equal(requests.at(-1).resourceRetry, true);
workers.at(-1).emit({ address: 10, text: "void named_init(void) {}", lines: [[10]], frame: [] });
workers.at(-1).resolve();
await retry;
await delay(100);
const retried = stagedUpdates.at(-1).functions.get(10);
assert.equal(retried.retry_pending, false);
assert.equal(retried.error, undefined);
assert.equal(retried.text, "void named_init(void) {}");
assert.deepEqual(retried.asm, [[10, "c3", "ret"]]);
assert.deepEqual(retried.calls, [20]);
assert.deepEqual(retried.lines, [[10]]);
console.log("Names, shard settlement, replacement records and explicit resource retry: passed");
