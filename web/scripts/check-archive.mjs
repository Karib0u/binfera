// Exercise the actual archive readers with harmless files, including encrypted 7z headers.
import assert from "node:assert/strict";
import { readFile, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import SevenZip from "7z-wasm";
import { Worker as NodeWorker } from "node:worker_threads";
import { stripTypes } from "./strip-types.mjs";
import { ZipWriter, Uint8ArrayReader, Uint8ArrayWriter } from "@zip.js/zip.js";

const temp = await mkdtemp(join(tmpdir(), "binfera-archive-"));
// Run the production worker in Node, preserving its separate thread and termination behavior.
globalThis.Worker = class {
  constructor(url) {
    this.worker = new NodeWorker(url);
    this.worker.on("message", data => this.onmessage?.({ data }));
    this.worker.on("error", error => this.onerror?.(error));
  }
  postMessage(data) { this.worker.postMessage(data); }
  terminate() { this.worker.terminate(); }
};
const source = await readFile(new URL("../src/archive.ts", import.meta.url), "utf8");
const compiled = stripTypes(source)
  .replace('"./archive.worker.ts"', '"./archive.worker.mjs"')
  .replace('import("./archive.zip")', 'import("./archive.zip.mjs")')
  .replaceAll('"7z-wasm"', JSON.stringify(import.meta.resolve("7z-wasm")))
  .replace('import("7z-wasm/7zz.wasm?url")',
    `Promise.resolve(${JSON.stringify({ default: fileURLToPath(import.meta.resolve("7z-wasm/7zz.wasm")) })})`);
const zip = stripTypes(await readFile(new URL("../src/archive.zip.ts", import.meta.url), "utf8")).replaceAll('"@zip.js/zip.js"', JSON.stringify(import.meta.resolve("@zip.js/zip.js")))
  .replace('from "./archive"', 'from "./archive.mjs"');
await writeFile(join(temp, "archive.mjs"), compiled);
await writeFile(join(temp, "archive.zip.mjs"), zip);
const worker = stripTypes(await readFile(new URL("../src/archive.worker.ts", import.meta.url), "utf8")).replace('"7z-wasm"', JSON.stringify(import.meta.resolve("7z-wasm")))
  .replace('import wasm from "7z-wasm/7zz.wasm?url";', `const wasm = ${JSON.stringify(fileURLToPath(import.meta.resolve("7z-wasm/7zz.wasm")))};`);
await writeFile(join(temp, "archive.worker.mjs"), `import { parentPort } from "node:worker_threads";
globalThis.self = { postMessage: (data, transfer) => parentPort.postMessage(data, transfer) };
parentPort.on("message", data => self.onmessage({ data }));\n` + worker);
const { archiveKind, openArchive, guessPassword, PasswordError, ArchiveLimitError } = await import(pathToFileURL(join(temp, "archive.mjs")));

const payload = new TextEncoder().encode("Harmless archive regression fixture.\n");
async function fixture(password, headers = false) {
  const sz = await SevenZip({ print: () => {}, printErr: () => {} });
  sz.FS.writeFile("/sample.bin", payload);
  const args = ["a", "-y", "/fixture.7z", "/sample.bin"];
  if (password) args.push("-p" + password, "-mhe=" + (headers ? "on" : "off"));
  assert.equal(sz.callMain(args), 0);
  return new File([sz.FS.readFile("/fixture.7z").slice()], "fixture.7z");
}

async function checkContents(archive, password) {
  assert.equal(archive.entries.length, 1);
  assert.equal(archive.entries[0].name, "sample.bin");
  const extracted = await archive.extract(archive.entries[0], password);
  assert.deepEqual(new Uint8Array(await extracted.arrayBuffer()), payload);
  await archive.close();
}

const encryptedHeaders = await fixture("infected", true);
assert.equal(await archiveKind(encryptedHeaders), "7z");
await assert.rejects(openArchive(encryptedHeaders, "7z"), PasswordError);
await assert.rejects(openArchive(encryptedHeaders, "7z", "wrong"), PasswordError);
await checkContents(await openArchive(encryptedHeaders, "7z", "infected"), "infected");
console.log("Encrypted file list: password failures are recognized and the correct password extracts it");

const customPassword = "fixture-custom-password";
const custom = await fixture(customPassword, true);
await assert.rejects(openArchive(custom, "7z", "infected"), PasswordError);
await checkContents(await openArchive(custom, "7z", customPassword), customPassword);
console.log("Custom password: a failed common password does not prevent a manual retry");

const visibleHeaders = await fixture("malware");
const visible = await openArchive(visibleHeaders, "7z");
assert.equal(visible.encrypted, true);
assert.equal(await visible.check("wrong"), false);
await assert.rejects(visible.extract(visible.entries[0], "wrong"), PasswordError);
assert.equal(await guessPassword(visible), "malware");
await checkContents(visible, "malware");
console.log("Visible file list: common passwords are tried through extraction failures");

const plain = await openArchive(await fixture(), "7z");
assert.equal(plain.encrypted, false);
await checkContents(plain);
await assert.rejects(openArchive(new File(["not an archive"], "broken.7z"), "7z"),
  /damaged or uses a format the browser cannot read/);
console.log("Unencrypted archives extract and invalid archives report a readable error");

for (const password of [undefined, "infected"]) {
  const writer = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
  await writer.add("sample.bin", new Uint8ArrayReader(payload), { password });
  const file = new File([await writer.close()], "fixture.zip");
  assert.equal(await archiveKind(file), "zip");
  const archive = await openArchive(file, "zip");
  assert.equal(archive.encrypted, !!password);
  if (password) {
    assert.equal(await archive.check("wrong"), false);
    assert.equal(await guessPassword(archive), "infected");
  }
  await checkContents(archive, password);
}
await assert.rejects(openArchive(new File(["broken zip"], "broken.zip"), "zip"), /damaged/);
console.log("Lazy ZIP reader: plain and encrypted archives extract; invalid ZIPs report a readable error");

const oversized = new File([], "large.zip");
Object.defineProperty(oversized, "size", { value: (256 << 20) + 1 });
await assert.rejects(openArchive(oversized, "zip"), ArchiveLimitError);
const cancelled = new AbortController();
cancelled.abort();
await assert.rejects(openArchive(encryptedHeaders, "7z", "infected", cancelled.signal), { name: "AbortError" });
const pending = new AbortController();
const opening = openArchive(encryptedHeaders, "7z", "infected", pending.signal);
pending.abort();
await assert.rejects(opening, { name: "AbortError" });

// Lower only the budgets in a second copy to exercise real decompression without huge fixtures.
await writeFile(join(temp, "limited.mjs"), compiled.replace("256 << 20", "1024").replace("10_000", "2").replace('"./archive.zip.mjs"', '"./limited.zip.mjs"'));
await writeFile(join(temp, "limited.zip.mjs"), zip.replace('from "./archive.mjs"', 'from "./limited.mjs"'));
const limited = await import(pathToFileURL(join(temp, "limited.mjs")));
const bomb = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
await bomb.add("big.bin", new Uint8ArrayReader(new Uint8Array(4096)));
const bombBytes = await bomb.close();
const bombFile = new File([bombBytes], "expansion.zip");
const bombArchive = await limited.openArchive(bombFile, "zip");
await assert.rejects(bombArchive.extract(bombArchive.entries[0]), limited.ArchiveLimitError);
await bombArchive.close();
// Lie in the central directory: streaming output must still hit the byte budget.
const forged = bombBytes.slice();
const header = Buffer.from(forged).indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
new DataView(forged.buffer, forged.byteOffset).setUint32(header + 24, 1, true);
const forgedArchive = await limited.openArchive(new File([forged], "forged.zip"), "zip");
await assert.rejects(forgedArchive.extract(forgedArchive.entries[0]), /Invalid uncompressed size|Archive output exceeds/);
await forgedArchive.close();
const many = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
for (const name of ["one", "two", "three"]) await many.add(name, new Uint8ArrayReader(payload));
await assert.rejects(limited.openArchive(new File([await many.close()], "many.zip"), "zip"), limited.ArchiveLimitError);
const unsafe = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
await unsafe.add("../escape.bin", new Uint8ArrayReader(payload));
await assert.rejects(openArchive(new File([await unsafe.close()], "unsafe.zip"), "zip"), /unsafe file path|damaged/);
const bounded7z = await limited.openArchive(await fixture(), "7z");
bounded7z.entries[0].size = 1;
// The worker counts actual bytes independently of advertised metadata.
const originalPost = globalThis.Worker.prototype.postMessage;
globalThis.Worker.prototype.postMessage = function(data) { originalPost.call(this, { ...data, maxBytes: 8 }); };
await assert.rejects(bounded7z.extract(bounded7z.entries[0]), limited.ArchiveLimitError);
globalThis.Worker.prototype.postMessage = originalPost;
await bounded7z.close();
await writeFile(join(temp, "timeout.mjs"), compiled.replace("30_000", "1"));
const timed = await import(pathToFileURL(join(temp, "timeout.mjs")));
await assert.rejects(timed.openArchive(encryptedHeaders, "7z", "infected"), timed.ArchiveLimitError);
const zipCancel = new AbortController();
const zipWriter = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
await zipWriter.add("sample.bin", new Uint8ArrayReader(payload));
const cancellable = await openArchive(new File([await zipWriter.close()], "cancel.zip"), "zip", undefined, zipCancel.signal);
const extraction = cancellable.extract(cancellable.entries[0]);
zipCancel.abort();
await assert.rejects(extraction, { name: "AbortError" });
await cancellable.close();
await rm(temp, { recursive: true, force: true });
console.log("Archive input, entry count, expansion limits, unsafe paths, timeouts and cancellation: passed");

// The Node build of 7z-wasm sets this even for the expected, caught failures above.
process.exitCode = 0;
