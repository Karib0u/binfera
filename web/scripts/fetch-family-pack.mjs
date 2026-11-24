// Optionally fetches the hosted starter BXFAM002 family pack from the live site into
// public/sigs/family.bxfam so CI deploys preserve it without committing private pack data.
// Exits cleanly when the live site does not serve one yet.
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const origin = process.env.DEMOS_ORIGIN ?? "https://binfera.io";
const url = new URL("/sigs/family.bxfam", origin);

try {
  const res = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) {
    console.log(`No hosted family pack at ${url} (HTTP ${res.status}); skipping.`);
    process.exit(0);
  }
  const bytes = Buffer.from(await res.arrayBuffer());
  if (bytes.length < 40 || bytes.subarray(0, 8).toString("ascii") !== "BXFAM002") {
    console.log(`Response at ${url} is not a BXFAM002 pack; skipping.`);
    process.exit(0);
  }
  const out = join(web, "public/sigs/family.bxfam");
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, bytes);
  console.log(`Fetched family pack (${(bytes.length / 1048576).toFixed(2)} MB) -> ${out}`);
} catch (err) {
  console.log(`Could not fetch family pack from ${url} (${err?.message ?? err}); skipping.`);
}
