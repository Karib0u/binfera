import { BlobReader, ZipReader, configure, type FileEntry } from "@zip.js/zip.js";
import { ARCHIVE_MAX_BYTES, ARCHIVE_MAX_ENTRIES, ARCHIVE_TIMEOUT_MS, ArchiveLimitError, checkEntry, baseName, looksLikeBinary, probeOf, type Archive, type ArchiveEntry } from "./archive";

configure({ useWebWorkers: false });

export async function openZip(file: File, signal?: AbortSignal): Promise<Archive> {
  const reader = new ZipReader(new BlobReader(file));
  const ctl = new AbortController();
  const cancel = () => ctl.abort();
  signal?.addEventListener("abort", cancel, { once: true });
  const close = async () => {
    ctl.abort();
    signal?.removeEventListener("abort", cancel);
    await reader.close();
  };
  const zips = new Map<string, FileEntry>();
  const entries: ArchiveEntry[] = [];
  try {
    let count = 0;
    for await (const z of reader.getEntriesGenerator()) {
      ctl.signal.throwIfAborted();
      if (++count > ARCHIVE_MAX_ENTRIES) throw new ArchiveLimitError("Archives may contain at most 10,000 entries.");
      if (z.directory) continue;
      if (zips.has(z.filename)) throw new Error("This archive contains duplicate file names.");
      zips.set(z.filename, z);
      entries.push({ name: z.filename, size: z.uncompressedSize, encrypted: z.encrypted, likely: looksLikeBinary(z.filename) });
    }
  } catch (e) {
    await close().catch(() => {});
    if (e instanceof ArchiveLimitError || signal?.aborted) throw e;
    throw new Error("This zip file is damaged or uses a format the browser cannot read.");
  }
  const get = async (e: ArchiveEntry, password?: string) => {
    ctl.signal.throwIfAborted();
    if (!entries.includes(e)) throw new Error("This file is not in the archive.");
    checkEntry(e);
    const job = new AbortController();
    const cancelJob = () => job.abort();
    ctl.signal.addEventListener("abort", cancelJob, { once: true });
    const timer = setTimeout(() => job.abort(new ArchiveLimitError("Archive reading exceeded 30 seconds.")), ARCHIVE_TIMEOUT_MS);
    const chunks: Uint8Array<ArrayBuffer>[] = [];
    let size = 0;
    try {
      await zips.get(e.name)!.getData(new WritableStream<Uint8Array<ArrayBuffer>>({ write(chunk) {
        if (chunk.length > ARCHIVE_MAX_BYTES - size) throw new ArchiveLimitError("Archive output exceeds 256 MiB.");
        size += chunk.length;
        chunks.push(chunk);
      } }), { password: password || undefined, signal: job.signal });
      return new Blob(chunks);
    } catch (error) {
      if (job.signal.aborted) throw job.signal.reason;
      throw error;
    } finally {
      clearTimeout(timer);
      ctl.signal.removeEventListener("abort", cancelJob);
    }
  };
  return {
    kind: "zip",
    entries,
    encrypted: entries.some((e) => e.encrypted),
    check: async (password) => {
      const probe = probeOf(entries);
      if (!probe) return true;
      try { await get(probe, password); return true; } catch (e) {
        if (e instanceof ArchiveLimitError || ctl.signal.aborted) throw e;
        return false;
      }
    },
    extract: async (e, password) => new File([await get(e, e.encrypted ? password : undefined)], baseName(e.name)),
    close,
  };
}
