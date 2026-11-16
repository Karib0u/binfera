// Verify asset selection and ownership without downloading the real engine or databases.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypes } from "./strip-types.mjs";
import { gzipSync } from "node:zlib";

const moduleUrl = source => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const resultCache = stripTypes(await readFile(new URL("../src/engine/resultCache.ts", import.meta.url), "utf8"));
const source = (await readFile(new URL("../src/engine/assets.ts", import.meta.url), "utf8"))
  .replace('from "./resultCache"', `from "${moduleUrl(resultCache)}"`)
  .replace(/import wasmUrl from [^;]+;/, 'const wasmUrl = "/engine.wasm";')
  .replace("import.meta.env.BASE_URL", '"/"');
const compiled = stripTypes(source);
const requested = [];
globalThis.fetch = async url => {
  requested.push(url);
  const bytes = url === "/engine.wasm" ? new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0])
    : url === "/rules.json" ? new TextEncoder().encode("{}")
    : url.endsWith(".packz") ? gzipSync(new Uint8Array([4, 5, 6])) : new Uint8Array([1, 2, 3]);
  return new Response(bytes, { headers: { "content-length": String(bytes.length) } });
};
const { loadAssets } = await import(moduleUrl(compiled));
const other = await loadAssets(null, () => {}, false);
assert.deepEqual(requested.sort(), ["/engine.wasm", "/rules.json"]);
assert.deepEqual(other.data("capa"), {});
assert.deepEqual(other.data("decompile"), {});

const pe = await loadAssets("x86", () => {}, true);
const capability = pe.data("capa");
const decompile = pe.data("decompile");
assert.equal(Object.keys(capability).length, 3);
assert.deepEqual(Object.keys(decompile).sort(), [...Object.keys(capability), "fid-x86.pack"].sort());
assert.equal(requested.filter(url => url === "/engine.wasm").length, 1);
assert.equal(requested.filter(url => url === "/rules.json").length, 1);
assert.ok(requested.includes("/sigs/fid-x86.packz"));
assert.ok(!requested.some(url => url.endsWith(".pack")));
assert.deepEqual([...new Uint8Array(decompile["fid-x86.pack"])], [4, 5, 6]);
const signature = Object.keys(capability)[0];
new Uint8Array(capability[signature])[0] = 9;
assert.equal(new Uint8Array(decompile[signature])[0], 1);
assert.equal(new Uint8Array(pe.data("capa")[signature])[0], 1);
console.log("Format-specific assets, download reuse and independent worker buffers: passed");
