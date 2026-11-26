import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { pathToFileURL } from "node:url";
import { transformSync } from "esbuild";

const temp = mkdtempSync(join(tmpdir(), "binfera-family-native-"));
after(() => rmSync(temp, { recursive: true, force: true }));
let modules = 0;
function moduleUrl(source) {
  const path = join(temp, `module-${modules++}.mjs`);
  writeFileSync(path, source);
  return pathToFileURL(path).href;
}
async function compile(path, rewrite = (source) => source) {
  const source = await readFile(new URL(path, import.meta.url), "utf8");
  return moduleUrl(rewrite(transformSync(source, { loader: "ts", format: "esm" }).code));
}

// Exercise the real desktop asset and engine adapters. The mock only replaces IPC.
const tauri = moduleUrl(`
  export const calls = [];
  let defaultPack = null;
  let pickedPack = null;
  let pickedOverlay = null;
  export const overlays = [];
  export function pickNext(pack) { pickedPack = pack; }
  export function pickOverlayNext(pack) { pickedOverlay = pack; }
  export class Channel {}
  export async function invoke(command, args) {
    calls.push({ command, args });
    switch (command) {
      case "family_pack_status":
        return defaultPack ?? { available: false };
      case "select_family_pack":
        if (pickedPack) defaultPack = pickedPack;
        return pickedPack;
      case "family_overlays_status":
        return overlays.slice();
      case "add_family_overlay": {
        const picked = pickedOverlay;
        pickedOverlay = null;
        if (picked) overlays.push(picked);
        return picked;
      }
      case "remove_family_overlay":
        overlays.splice(args.index, 1);
        return;
      case "stage_sample":
        return 1;
      case "release_sample":
        return;
      case "run_engine": {
        const { request, onLine } = args;
        const argv = request.args;
        const lines = argv.includes("--image-info")
          ? [{ format: "pe", entry: 4096, arch: "x86" }]
          : argv.includes("--decompile-all")
          ? [{ type: "start", functions: [4096] }, { type: "settled" }, { type: "done" }]
          : argv[0] === "family"
          ? [{ total_functions: 1, trusted_functions: 1, families: [] }]
          : [{ rules: [], library: [] }];
        for (const line of lines) onLine.onmessage(JSON.stringify(line));
        return { code: 0, stderr: "", lines: lines.length };
      }
      default:
        throw new Error("unexpected IPC command: " + command);
    }
  }
`);
const ipc = (source) => source.replaceAll('"@tauri-apps/api/core"', JSON.stringify(tauri));
const assets = await compile("../src/engine/assets.native.ts", ipc);
const emulate = await compile("../src/engine/emulate.ts");
const run = await compile("../src/engine/run.native.ts", (source) => ipc(source).replaceAll('"./emulate"', JSON.stringify(emulate)));
const shellcode = await compile("../src/engine/shellcode.ts");
const other = moduleUrl(`
  export const digest = async () => null;
  export const readResults = async () => null;
  export const writeResults = async () => {};
  export const forgetResults = async () => {};
  export const extractStrings = () => ({ strings: [], total: 0 });
  export const summarizeCapa = (json) => json;
  export const createImage = () => null;
`);
const analyze = await compile("../src/analyze.ts", (source) => source.replace(
  /from "\.\/engine\/([^"]+)"/g,
  (_, name) => `from "${{ assets, run, shellcode }[name] ?? other}"`,
));
const { calls, pickNext, pickOverlayNext, overlays } = await import(tauri);
const { analyze: analyzeFile } = await import(analyze);
const file = new File([new Uint8Array(16)], "demo.exe");
const familyRuns = () => calls.filter(({ command, args }) =>
  command === "run_engine" && args.request.args[0] === "family",
);

test("Desktop picks and autoloads a local pack through metadata-only IPC", { timeout: 5000 }, async () => {
  if (!globalThis.navigator) {
    Object.defineProperty(globalThis, "navigator", { value: { hardwareConcurrency: 4, userAgent: "test" } });
  }
  const controller = new AbortController();
  let analysis;
  let matched;
  const update = (value) => {
    analysis = value;
    if (value.family) matched?.();
  };
  await analyzeFile(file, update, controller.signal);
  assert.equal(analysis.family, null);
  assert.equal(analysis.runFamilyPack, undefined);
  assert.equal(familyRuns().length, 0);

  await analysis.pickFamilyPack();
  assert.equal(familyRuns().length, 0, "cancelling the dialog must leave the analysis alone");

  pickNext({ available: true, name: "local pack.bxfam", size: 75 * 1024 * 1024, path: "/packs/local pack.bxfam" });
  const updated = new Promise((resolve) => { matched = resolve; });
  await analysis.pickFamilyPack();
  await updated;
  assert.equal(analysis.family.trusted_functions, 1);
  assert.equal(analysis.familyPackName, "local pack.bxfam");
  assert.equal(familyRuns().length, 1);

  controller.abort();
  await analyzeFile(file, update, new AbortController().signal);
  assert.equal(analysis.family.total_functions, 1);
  assert.equal(analysis.familyPackName, "local pack.bxfam");
  assert.equal(familyRuns().length, 2);

  for (const { args } of familyRuns()) {
    assert.deepEqual(args.request.args, ["family", "match", "--pack", "{family_pack}", "{sample}", "--json"]);
    assert.deepEqual(args.request.files, {});
  }
  for (const { args } of calls.filter(({ command }) => command === "stage_sample")) {
    assert.equal(args.byteLength, file.size, "only the sample bytes should cross IPC");
  }
  assert.ok(calls.filter(({ command }) => command === "select_family_pack").every(({ args }) => args === undefined));
});

test("Desktop layers overlay packs by index and never sends their paths", { timeout: 5000 }, async () => {
  let analysis;
  let resolveMatch;
  const update = (value) => {
    analysis = value;
    if (value.family) resolveMatch?.();
  };
  const matched = () => new Promise((resolve) => { resolveMatch = resolve; });
  // The pack picked by the previous test stays the base pack.
  let next = matched();
  await analyzeFile(file, update, new AbortController().signal);
  await next;
  const before = familyRuns().length;

  await analysis.addFamilyOverlay();
  assert.equal(familyRuns().length, before, "cancelling the overlay dialog must not re-run matching");

  pickOverlayNext({ available: true, name: "my-org-trusted.bxfam", size: 4096, path: "/packs/my-org-trusted.bxfam", format: "BXFAM003" });
  next = matched();
  await analysis.addFamilyOverlay();
  await next;
  await new Promise((resolve) => setTimeout(resolve, 150));
  const run = familyRuns().at(-1).args.request.args;
  assert.deepEqual(run, ["family", "match", "--pack", "{family_pack}", "--pack", "{family_overlay:0}", "{sample}", "--json"]);
  assert.ok(!run.some((a) => a.includes("/packs/")), "overlay paths stay on the native side");
  assert.deepEqual(analysis.familyPacks.map((p) => [p.name, p.role, p.format]), [["local pack.bxfam", "base", undefined], ["my-org-trusted.bxfam", "overlay", "BXFAM003"]]);

  next = matched();
  await analysis.removeFamilyOverlay(0);
  await next;
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(overlays.length, 0);
  assert.deepEqual(familyRuns().at(-1).args.request.args, ["family", "match", "--pack", "{family_pack}", "{sample}", "--json"]);
  assert.deepEqual(analysis.familyPacks.map((p) => p.name), ["local pack.bxfam"]);
});
