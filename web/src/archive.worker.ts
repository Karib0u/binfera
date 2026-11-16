import SevenZip from "7z-wasm";
import wasm from "7z-wasm/7zz.wasm?url";

// Each run owns a worker, so cancellation and deadlines can stop native decompression.
self.onmessage = async ({ data: { file, args, output, maxBytes, maxEntries } }) => {
  let written = 0, lines = 0, textBytes = 0, limited = false;
  const out: string[] = [], err: string[] = [];
  const print = (target: string[], text: string) => {
    textBytes += text.length;
    if (++lines > maxEntries * 32 || text.length > 65536 || textBytes > 8 << 20) {
      limited = true;
      throw new Error("Archive file list is too large.");
    }
    target.push(text);
  };
  try {
    const sz = await SevenZip({ print: s => print(out, s), printErr: s => print(err, s),
      stdin: () => null as unknown as number, locateFile: url => url.endsWith(".wasm") ? wasm : url });
    const fs = sz.FS as unknown as {
      mkdir(path: string): void;
      writeFile(path: string, bytes: Uint8Array): void;
      readFile(path: string): Uint8Array<ArrayBuffer>;
      write(stream: unknown, buffer: Uint8Array, offset: number, length: number, position?: number, canOwn?: boolean): number;
    };
    fs.mkdir("/in");
    fs.writeFile("/in/archive.7z", new Uint8Array(await file.arrayBuffer()));
    const write = fs.write.bind(fs);
    fs.write = (stream, buffer, offset, length, position, canOwn) => {
      if (length > maxBytes - written) {
        limited = true;
        throw new Error("Archive output exceeds 256 MiB.");
      }
      written += length;
      return write(stream, buffer, offset, length, position, canOwn);
    };
    let code = 0;
    try { code = sz.callMain(args) ?? 0; }
    catch (e) {
      if (limited) throw new Error("Archive output or file list exceeds its limit.");
      if (typeof e === "number") { self.postMessage({ password: true }); return; }
      const status = (e as { status?: number }).status;
      if (typeof status !== "number") throw e;
      code = status;
    }
    if (limited) throw new Error("Archive output or file list exceeds its limit.");
    if (code === 0 && err.some(l => /^ERROR/.test(l))) code = 2;
    const bytes = code === 0 && output ? fs.readFile(output).slice() : undefined;
    (self as unknown as Worker).postMessage({ code, out, err, bytes }, bytes ? [bytes.buffer] : []);
  } catch (e) { self.postMessage({ error: String((e as Error).message ?? e), limit: limited }); }
};
