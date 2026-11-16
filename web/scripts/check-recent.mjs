// Exercise the native reopen flow without launching a webview or touching the user's history.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const moduleUrl = (source) => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const mocks = moduleUrl(`
  import { createHash } from "node:crypto";
  export const calls = [];
  let path = null, bytes = new Uint8Array();
  export function input(nextPath, nextBytes) { path = nextPath; bytes = nextBytes; calls.length = 0; }
  export async function invoke(command, args) {
    calls.push({ command, args });
    if (command === "project_path") return path;
    if (command === "file_read") return bytes.slice().buffer;
    throw new Error("Unexpected command: " + command);
  }
  export const listen = () => {};
  export const getCurrentWebview = () => ({});
  export const sha256 = async bytes => createHash("sha256").update(bytes).digest("hex");
`);
const source = await readFile(new URL("../src/project/client.native.ts", import.meta.url), "utf8");
const js = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText.replace(/from "(?:@tauri-apps\/api\/[^"]+|\.\.\/names)"/g, `from "${mocks}"`);
const { desktop } = await import(moduleUrl(js));
const { calls, input } = await import(mocks);
const bytes = new TextEncoder().encode("retained extracted binary");
const sha256 = createHash("sha256").update(bytes).digest("hex");
const entry = { sha256, name: "inside.exe", path: null, missing: false, retained: true };

input("/binfera/samples/" + sha256, bytes);
const file = await desktop.open(entry);
assert.equal(file.name, "inside.exe");
assert.deepEqual(new Uint8Array(await file.arrayBuffer()), bytes);
assert.deepEqual(calls, [
  { command: "project_path", args: { sha256 } },
  { command: "file_read", args: { path: "/binfera/samples/" + sha256 } },
]);
console.log("Extracted binaries reopen from their saved input with their original name: passed");

// Resolve again on click: the original may have disappeared since Recent was loaded.
input("/binfera/samples/" + sha256, bytes);
await desktop.open({ ...entry, path: "/old/inside.exe", missing: false });
assert.equal(calls[1].args.path, "/binfera/samples/" + sha256);
input("/original/inside.exe", bytes);
await desktop.open({ ...entry, path: "/original/inside.exe" });
assert.equal(calls[1].args.path, "/original/inside.exe");
console.log("Reopening resolves the currently available original or saved input: passed");

input(null, bytes);
await assert.rejects(desktop.open(entry), /Locate it to reopen/);
assert.equal(calls.length, 1);
input("/binfera/samples/" + sha256, new Uint8Array([0]));
await assert.rejects(desktop.open(entry), /has changed since it was analysed/);
console.log("Missing inputs request locating, and changed contents are rejected: passed");
