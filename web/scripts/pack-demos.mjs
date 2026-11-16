// Packs the demo samples listed in demo/samples.json into public/demos/: each file XOR-encoded
// (the key is in src/demos.ts) so the site never serves a runnable binary, plus index.json for
// the picker. The samples are real malware from a local malpedia checkout (MALPEDIA_DIR, required); they are never committed.
import { readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const malpedia = process.env.MALPEDIA_DIR;
if (!malpedia) {
  console.error("set MALPEDIA_DIR to a local malpedia checkout");
  process.exit(1);
}
const KEY = new TextEncoder().encode("binfera-demo-sample");

// A thin Apple silicon demo keeps inspection, capabilities and decompilation on ARM64.
function arm64Slice(bytes) {
  if (bytes.length < 8 || bytes.readUInt32BE(0) !== 0xcafebabe) throw new Error("expected a universal Mach-O");
  const count = bytes.readUInt32BE(4);
  if (8 + count * 20 > bytes.length) throw new Error("truncated Mach-O architecture table");
  for (let i = 0; i < count; i++) {
    const at = 8 + i * 20;
    if (bytes.readUInt32BE(at) !== 0x0100000c) continue;
    const offset = bytes.readUInt32BE(at + 8), size = bytes.readUInt32BE(at + 12);
    if (size < 32 || offset < 8 + count * 20 || offset + size > bytes.length) throw new Error("invalid ARM64 slice bounds");
    const slice = bytes.subarray(offset, offset + size);
    if (slice.readUInt32LE(0) !== 0xfeedfacf || slice.readUInt32LE(4) !== 0x0100000c) throw new Error("invalid ARM64 Mach-O header");
    return slice;
  }
  throw new Error("universal Mach-O has no ARM64 slice");
}

const samples = JSON.parse(await readFile(join(web, "demo/samples.json"), "utf8"));
const out = join(web, "public/demos");
await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });
const index = [];
for (const { path, slice, ...sample } of samples) {
  let bytes;
  try {
    bytes = await readFile(join(malpedia, path));
  } catch (e) {
    console.error(`${sample.id}: ${e.message} (set MALPEDIA_DIR)`);
    process.exit(1);
  }
  const sourceSha256 = createHash("sha256").update(bytes).digest("hex");
  if (slice) {
    if (slice !== "arm64") throw new Error(`unsupported demo slice: ${slice}`);
    bytes = arm64Slice(bytes);
  }
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const encoded = Buffer.from(bytes.map((b, i) => b ^ KEY[i % KEY.length]));
  await writeFile(join(out, `${sample.id}.bin`), encoded);
  index.push({ ...sample, family: path.split("/")[0], sha256, size: bytes.length, ...(slice ? { sourceSha256 } : {}) });
  console.log(`${sample.id.padEnd(14)} ${String(bytes.length).padStart(9)}  ${sha256}`);
}
await writeFile(join(out, "index.json"), JSON.stringify(index));
