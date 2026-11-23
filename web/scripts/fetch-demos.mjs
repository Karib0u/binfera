// Fills public/demos/ from the live site instead of a malpedia checkout, for the deploy workflow:
// the samples are never committed, so a CI deploy reuses the packed files binfera.io already serves.
// Each file is decoded and checked against its SHA-256, and the index is rebuilt from
// demo/samples.json, so edited names, notes and removals still ship. A sample that is new or points
// at a different file fails here: pack it locally with `npm run pack-demos` and deploy by hand once.
import { readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, resolve, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const origin = process.env.DEMOS_ORIGIN ?? "https://binfera.io";
// Must match src/demos.ts and scripts/pack-demos.mjs.
const KEY = new TextEncoder().encode("binfera-demo-sample");

async function get(path) {
  const response = await fetch(new URL(path, origin), { signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`${origin}${path}: HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

function fail(message) {
  console.error(`error: ${message}`);
  console.error("Pack the demos locally (MALPEDIA_DIR=... npm run pack-demos) and deploy by hand once; later deploys reuse them.");
  process.exit(1);
}

const samples = JSON.parse(await readFile(join(web, "demo/samples.json"), "utf8"));
const live = new Map(JSON.parse(await get("/demos/index.json")).map(s => [s.id, s]));
const out = join(web, "public/demos");
await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

const index = [];
for (const { path, slice, ...sample } of samples) {
  const deployed = live.get(sample.id);
  if (!deployed) fail(`${sample.id} is not on ${origin}`);
  const family = path.split("/")[0];
  if (deployed.family !== family) fail(`${sample.id}: ${origin} serves a ${deployed.family} sample, samples.json names ${family}`);
  if (Boolean(slice) !== Boolean(deployed.sourceSha256)) fail(`${sample.id}: the slice setting changed`);
  // A bare-hash malpedia file name is the sample's SHA-256, which pins the exact file. An
  // `_unpacked` name is the packed original's hash, so it pins nothing here.
  const named = basename(path).match(/^[0-9a-f]{64}$/)?.[0];
  if (named && named !== (deployed.sourceSha256 ?? deployed.sha256)) fail(`${sample.id}: ${origin} serves a different file than ${path}`);

  const encoded = await get(`/demos/${sample.id}.bin`);
  const bytes = Buffer.from(encoded.map((b, i) => b ^ KEY[i % KEY.length]));
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (bytes.length !== deployed.size || sha256 !== deployed.sha256) fail(`${sample.id}: downloaded file does not match its index entry`);

  await writeFile(join(out, `${sample.id}.bin`), encoded);
  index.push({ ...sample, family, sha256, size: bytes.length, ...(slice ? { sourceSha256: deployed.sourceSha256 } : {}) });
  console.log(`${sample.id.padEnd(14)} ${String(bytes.length).padStart(9)}  ${sha256}`);
}
await writeFile(join(out, "index.json"), JSON.stringify(index));
