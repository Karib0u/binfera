// Writes one landing-page demo sample out as a plain file, for recordings and manual checks.
//   node web/scripts/decode-demo.mjs wannacry /tmp/binfera-demo/wannacry.exe
// The samples are real malware: keep the output away from anything that would run it.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

const [id, out] = process.argv.slice(2);
if (!id || !out) {
  console.error("usage: node scripts/decode-demo.mjs <demo id> <output file>");
  process.exit(2);
}
const bytes = new Uint8Array(await readFile(new URL(`../public/demos/${id}.bin`, import.meta.url)));
const key = new TextEncoder().encode("binfera-demo-sample");
for (let i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
await mkdir(dirname(out), { recursive: true });
await writeFile(out, bytes);
