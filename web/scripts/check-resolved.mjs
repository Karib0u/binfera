// APIs the program loads with GetProcAddress are listed at their slot like imports, and the Asm
// view names the call operand after the API.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { fileURLToPath } from "node:url";

const bundle = async (entry) => {
  const out = await build({ entryPoints: [fileURLToPath(new URL(entry, import.meta.url))], bundle: true, format: "esm", write: false, logLevel: "error" });
  return await import(`data:text/javascript;base64,${Buffer.from(out.outputFiles[0].text).toString("base64")}`);
};
const { buildIndex } = await bundle("../src/listing/model.ts");
const { resolvedSlots } = await bundle("../src/resolved.ts");

// A .data section at 0x40f000 holding a real import slot and a resolved one, next to code that calls both.
const slot = 0x40f880;
const image = {
  ptrSize: 4,
  regions: [{ off: 0, size: 0x2000, va: 0x40e000 }],
  sections: [{ name: ".data", va: 0x40f000, size: 0x1000, vsize: 0x1000, perms: "rw-" }, { name: ".text", va: 0x40e000, size: 0x1000, vsize: 0x1000, perms: "r-x" }],
  imports: [{ dll: "KERNEL32.dll", name: "CloseHandle", va: 0x40f884 }, ...resolvedSlots(new Map([[slot, "ReadFile"]]))],
};
const index = buildIndex(image, [], new Map());
const imps = index.atoms.filter((a) => a.kind === "imp").map((a) => [a.va, a.name, a.dll]);
assert.deepEqual(imps, [[slot, "ReadFile", ""], [0x40f884, "CloseHandle", "KERNEL32.dll"]]);
console.log("Listing: a resolved API slot is an import item named after the API: passed");
