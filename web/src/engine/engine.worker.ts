// Runs one binfera invocation (the Rust CLI compiled to WebAssembly with the Ghidra decompiler)
// against an in-memory copy of the sample. stdout lines stream back as they are printed.
import createBinfera from "../wasm/binfera.js";
import { emulateArgs } from "./emulate";

export interface RawCodeOptions {
  format: "sc32" | "sc64";
  os: "windows" | "linux";
  /** Skip this many decoded input bytes; code addresses remain relative to the selected payload. */
  offset?: number;
}

interface Common {
  raw?: RawCodeOptions;
  /** Compiled once by the page and shared by every worker. */
  module: WebAssembly.Module;
  sample: ArrayBuffer;
  /** Signature databases and Function ID pack, mounted at `/sigs`. */
  data: Record<string, ArrayBuffer>;
}
export type EngineRequest =
  | (Common & { kind: "inspect" })
  | (Common & { kind: "capa"; rules: Record<string, string> })
  /** Packs base first; browser buffers, or nothing on desktop where the native side resolves paths. */
  | (Common & { kind: "family"; packs?: ArrayBuffer[]; packNames?: string[]; overlays?: number })
  | (Common & { kind: "decompile"; shard: [number, number] })
  | (Common & { kind: "fingerprint" })
  | (Common & { kind: "decompileOne"; address: number; resourceRetry?: boolean })
  /** A comparison over text files, such as fingerprints, mounted at the root. */
  | (Common & { kind: "diff"; files: Record<string, string>; args: string[] })
  /** Isolated p-code emulation of one function; `request` is the JSON `--emulate-request` reads on stdin. */
  | (Common & { kind: "emulate"; address: number; request: string; callSites?: number });

export type EngineMessage =
  | { type: "line"; line: string }
  | { type: "done" }
  /** `code` is binfera's exit status when it exited; 14 means the file is too large (see `TOO_LARGE`). */
  | { type: "fail"; message: string; code?: number };

const post = (m: EngineMessage) => (self as unknown as Worker).postMessage(m);

function mkdirs(fs: { mkdir(p: string): void }, path: string, made: Set<string>) {
  let cur = "";
  for (const part of path.split("/").filter(Boolean)) {
    cur += "/" + part;
    if (!made.has(cur)) { fs.mkdir(cur); made.add(cur); }
  }
}

/** A pack's display name as a plain file name: no folders, no leading dot or dash. */
export function packFileName(name: string | undefined): string {
  const safe = (name ?? "").replace(/[\/\\\0]/g, "_").replace(/^[.\-\s]+/, "").slice(0, 120);
  return safe || "pack.bxfam";
}

self.onmessage = async (ev: MessageEvent<EngineRequest>) => {
  const req = ev.data;
  const stderr: string[] = [];
  // Only an emulation reads stdin: its request, then end of input.
  const input = req.kind === "emulate" ? new TextEncoder().encode(req.request) : new Uint8Array(0);
  let read = 0;
  try {
    const mod = await createBinfera({
      print: (line: string) => post({ type: "line", line }),
      printErr: (line: string) => { if (stderr.length < 50) stderr.push(line); },
      stdin: () => (read < input.length ? input[read++] : null),
      instantiateWasm: (imports, success) => {
        WebAssembly.instantiate(req.module, imports).then((instance) => success(instance, req.module));
        return {};
      },
    });
    mod.FS.mkdir("/sigs");
    for (const [name, bytes] of Object.entries(req.data)) mod.FS.writeFile("/sigs/" + name, new Uint8Array(bytes));
    mod.FS.writeFile("/sample.bin", new Uint8Array(req.sample));
    let args: string[];
    if (req.kind === "inspect") {
      args = ["/sample.bin", "--image-info", "--guess-shellcode"];
    } else if (req.kind === "capa") {
      const made = new Set<string>(["/rules"]);
      mod.FS.mkdir("/rules");
      for (const [path, text] of Object.entries(req.rules)) {
        const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
        if (dir) mkdirs(mod.FS, "/rules/" + dir, made);
        mod.FS.writeFile("/rules/" + path, text);
      }
      // No threads in the browser build: --jobs 1 is the serial reference path.
      args = ["/sample.bin", "--json", "--jobs", "1", "--rules", "/rules"];
    } else if (req.kind === "family") {
      if (!req.packs?.length) throw new Error("No family pack supplied");
      args = ["family", "match"];
      // Each pack under its own name, in a folder of its own: the engine reports matches by file name.
      const made = new Set<string>();
      req.packs.forEach((pack, i) => {
        const dir = `/packs/${i}`;
        mkdirs(mod.FS, dir, made);
        const path = `${dir}/${packFileName(req.packNames?.[i])}`;
        mod.FS.writeFile(path, new Uint8Array(pack));
        args.push("--pack", path);
      });
      args.push("/sample.bin", "--json");
    } else if (req.kind === "fingerprint") {
      // Native recovery, like the decompiler's, with its higher limit.
      args = ["fingerprint", "/sample.bin", "--max-instructions", "3500000"];
    } else if (req.kind === "decompileOne") {
      args = ["/sample.bin", "--decompile-function", `0x${req.address.toString(16)}`, "--json", "--max-instructions", "3500000"];
      if (req.resourceRetry) args.push("--resource-retry");
    } else if (req.kind === "emulate") {
      args = emulateArgs("/sample.bin", req.address, req.callSites);
    } else if (req.kind === "diff") {
      for (const [path, text] of Object.entries(req.files)) mod.FS.writeFile("/" + path, text);
      args = ["diff", ...req.args];
    } else {
      // The decompiler needs about half the capability worker's memory per instruction and has no
      // rule set to hold, so it keeps going past the build's default limit (web/README.md).
      args = ["/sample.bin", "--decompile-all", "--no-resource-retry", "--shard", `${req.shard[0]}/${req.shard[1]}`, "--max-instructions", "3500000"];
    }
    if (req.raw && req.kind !== "family") args.push("--format", req.raw.format, "--os", req.raw.os);
    let code = 0;
    try { code = mod.callMain(args) ?? 0; } catch (e) {
      const status = (e as { status?: number }).status;
      if (typeof status !== "number") throw e;
      code = status;
    }
    // `diff` exits 1 to say the files differ, which is an answer rather than a failure.
    if (code !== 0 && !(req.kind === "diff" && code === 1)) post({ type: "fail", message: stderr.join("\n").trim() || `binfera exited with status ${code}`, code });
    else post({ type: "done" });
  } catch (e) {
    post({ type: "fail", message: String((e as Error)?.message ?? e) });
  }
};
