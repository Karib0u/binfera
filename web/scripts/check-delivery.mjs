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

// The star count: GitHub's number when it answers, the last good one when it doesn't, and never an asset lookup.
{
  const store = new Map();
  globalThis.caches = { default: {
    match: async (k) => store.get(k)?.clone() ?? undefined,
    put: async (k, r) => { store.set(k, r); },
  } };
  const realFetch = globalThis.fetch;
  const noAssets = { ASSETS: { fetch: async () => { throw new Error("api must not hit assets"); } } };
  const ask = async () => (await worker.fetch(new Request("https://example.test/api/github-meta"), noAssets)).json();

  globalThis.fetch = async () => new Response(JSON.stringify({ stargazers_count: 42 }));
  assert.deepEqual(await ask(), { stars: 42 });
  globalThis.fetch = async () => { throw new Error("cached answers must not reach GitHub"); };
  assert.deepEqual(await ask(), { stars: 42 });

  store.delete("https://binfera.internal/api/github-meta");
  globalThis.fetch = async () => new Response("rate limited", { status: 403 });
  assert.deepEqual(await ask(), { stars: 42 });
  store.clear();
  assert.deepEqual(await ask(), { stars: null });
  globalThis.fetch = realFetch;
  delete globalThis.caches;
  console.log("GitHub star count is cached and survives GitHub failures: passed");
}
