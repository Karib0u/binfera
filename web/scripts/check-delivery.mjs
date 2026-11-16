// Cache failures must never inherit the immutable policy for successful hashed assets.
import assert from "node:assert/strict";
import worker from "../worker.js";

for (const status of [200, 206, 304, 404, 500]) {
  const source = new Response(status === 304 ? null : "asset", {
    status, headers: { "Cache-Control": "public, max-age=31536000, immutable", ETag: '"test"' },
  });
  const request = new Request("https://example.test/assets/chunk.js");
  const result = await worker.fetch(request, { ASSETS: { fetch: async r => { assert.equal(r, request); return source; } } });
  assert.equal(result.status, status);
  assert.equal(result.headers.get("ETag"), '"test"');
  assert.equal(result.headers.get("Cache-Control"), status === 404 || status >= 400
    ? "no-store" : "public, max-age=31536000, immutable");
  assert.equal(await result.text(), status === 304 ? "" : "asset");
}
const source = new Response("page", { headers: { "Cache-Control": "max-age=0" } });
assert.equal(await worker.fetch(new Request("https://example.test/"), { ASSETS: { fetch: async () => source } }), source);
console.log("Hashed assets stay immutable; missing assets and errors are not cached: passed");
