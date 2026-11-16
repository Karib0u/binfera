import assert from "node:assert/strict";
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const hosts = ["https://binfera.io"];
const results = await Promise.all(hosts.map(async host => {
  const page = await fetch(host, { signal: AbortSignal.timeout(20_000) });
  assert.equal(page.status, 200, `${host}: landing page`);
  const html = await page.text();
  const asset = html.match(/(?:src|href)="([^" ]*\/assets\/[^" ]+)"/)?.[1];
  assert.ok(asset, `${host}: hashed asset in landing page`);
  const urls = [new URL(asset, host), new URL(`/assets/release-check-missing-${Date.now()}.js`, host)];
  const responses = await Promise.all(urls.map(async url => {
    const response = await fetch(url, { method: "HEAD", signal: AbortSignal.timeout(20_000) });
    return { url: url.href, status: response.status, cacheControl: response.headers.get("cache-control") };
  }));
  assert.equal(responses[0].status, 200);
  assert.match(responses[0].cacheControl, /immutable/);
  assert.equal(responses[1].status, 404);
  assert.match(responses[1].cacheControl, /no-store/);
  return { host, responses };
}));
console.log(JSON.stringify(results, null, 2));
if (process.argv[2]) {
  const output = resolve(process.argv[2]);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify({ date: new Date().toISOString(), results }, null, 2) + "\n");
}
