// One-shot opener postMessage handoff protocol, without a wasm build.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypes } from "./strip-types.mjs";

const moduleUrl = source => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const source = stripTypes(await readFile(new URL("../src/openerImport.ts", import.meta.url), "utf8"));
const {
  OPENER_PROTOCOL_VERSION,
  isOpenerImportHash,
  sanitizeImportName,
  extractImportBytes,
  installOpenerImport,
} = await import(moduleUrl(source));

assert.equal(isOpenerImportHash("#import"), true);
assert.equal(isOpenerImportHash("#import&foo=1"), true);
assert.equal(isOpenerImportHash("#demo=wannacry"), false);
assert.equal(isOpenerImportHash(""), false);

assert.equal(sanitizeImportName("malware.exe"), "malware.exe");
assert.equal(sanitizeImportName("../../nested/path\\payload.dll"), "payload.dll");
assert.equal(sanitizeImportName(".."), "sample.bin");
assert.equal(sanitizeImportName(""), "sample.bin");
assert.equal(sanitizeImportName(null), "sample.bin");

assert.equal(extractImportBytes(new ArrayBuffer(0)), null);
assert.equal(extractImportBytes("not bytes"), null);
assert.deepEqual(Array.from(extractImportBytes(new Uint8Array([0x4d, 0x5a]))), [0x4d, 0x5a]);

function fakeWindow({ hash = "#import", hasOpener = true } = {}) {
  const listeners = new Set();
  const posted = [];
  const opener = hasOpener
    ? { postMessage(message, targetOrigin) { posted.push({ message, targetOrigin }); } }
    : null;
  return {
    win: {
      location: { hash },
      opener,
      addEventListener(type, fn) { if (type === "message") listeners.add(fn); },
      removeEventListener(type, fn) { if (type === "message") listeners.delete(fn); },
    },
    opener,
    posted,
    listeners,
    dispatch(event) {
      for (const fn of [...listeners]) fn(event);
    },
  };
}

// Inactive when hash is not #import or opener is missing.
{
  const f1 = fakeWindow({ hash: "#demo=wannacry" });
  installOpenerImport({ win: f1.win, onFile: () => { throw new Error("unexpected"); } });
  assert.equal(f1.posted.length, 0);
  assert.equal(f1.listeners.size, 0);

  const f2 = fakeWindow({ hasOpener: false });
  installOpenerImport({ win: f2.win, onFile: () => { throw new Error("unexpected"); } });
  assert.equal(f2.listeners.size, 0);
}

// Happy path: ready beacon, rejects wrong source/type/payload, accepts opener ArrayBuffer once, acks & clears hash.
{
  const f = fakeWindow();
  const received = [];
  let cleared = 0;
  const cleanup = installOpenerImport({
    win: f.win,
    onFile: (file) => received.push(file),
    onClearHash: () => { cleared++; },
  });

  assert.deepEqual(f.posted, [{ message: { type: "binfera:ready", version: OPENER_PROTOCOL_VERSION }, targetOrigin: "*" }]);
  assert.equal(f.listeners.size, 1);

  const sample = new Uint8Array([0x7f, 0x45, 0x4c, 0x46]);
  // Wrong source is ignored.
  f.dispatch({ source: {}, origin: "https://evil.example", data: { type: "binfera:open", name: "a.bin", bytes: sample.buffer } });
  // Wrong message type is ignored.
  f.dispatch({ source: f.opener, origin: "https://filebus.local", data: { type: "other", name: "a.bin", bytes: sample.buffer } });
  // Empty bytes is ignored.
  f.dispatch({ source: f.opener, origin: "https://filebus.local", data: { type: "binfera:open", name: "a.bin", bytes: new ArrayBuffer(0) } });
  assert.equal(received.length, 0);

  // Valid handoff from the actual opener.
  f.dispatch({
    source: f.opener,
    origin: "https://filebus.local",
    data: { type: "binfera:open", version: 1, name: "dir/beacon.elf", bytes: sample.buffer },
  });
  assert.equal(received.length, 1);
  assert.equal(received[0].name, "beacon.elf");
  assert.deepEqual(Array.from(new Uint8Array(await received[0].arrayBuffer())), [0x7f, 0x45, 0x4c, 0x46]);
  assert.equal(cleared, 1);
  assert.equal(f.listeners.size, 0);
  assert.deepEqual(f.posted[1], {
    message: { type: "binfera:ack", version: OPENER_PROTOCOL_VERSION },
    targetOrigin: "https://filebus.local",
  });

  // One-shot: a second message is ignored.
  f.dispatch({
    source: f.opener,
    origin: "https://filebus.local",
    data: { type: "binfera:open", version: 1, name: "second.elf", bytes: sample.buffer },
  });
  assert.equal(received.length, 1);
  cleanup();
}

console.log("Opener postMessage handoff protocol: passed");
