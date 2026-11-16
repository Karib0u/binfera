// Zip and 7z archives, as malware is usually shared: a password-protected archive, most often with a
// well-known password. Everything is read in this tab; entries are only decompressed, never run.

/** Passwords that malware repositories and sandboxes conventionally use, tried before asking. */
export const KNOWN_PASSWORDS = ["infected", "malware", "virus", "password", "infected123", "1234", "12345", "123456", "admin", "sample", "samples", "darkwing", "clean"];

export const ARCHIVE_MAX_BYTES = 256 << 20;
export const ARCHIVE_MAX_ENTRIES = 10_000;
export const ARCHIVE_TIMEOUT_MS = 30_000;

export class ArchiveLimitError extends Error {}

export function checkEntry(e: ArchiveEntry) {
  if (!Number.isSafeInteger(e.size) || e.size < 0 || e.size > ARCHIVE_MAX_BYTES) {
    throw new ArchiveLimitError("Archive files must be at most 256 MiB after extraction.");
  }
  if (!e.name || /^[\\/]/.test(e.name) || /^[a-z]:/i.test(e.name) || e.name.includes("\0") || e.name.split(/[\\/]/).includes("..")) {
    throw new Error("This archive contains an unsafe file path.");
  }
}

export interface ArchiveEntry {
  /** Path inside the archive. */
  name: string;
  size: number;
  encrypted: boolean;
  /** The name looks like an executable or library, or has no extension at all. */
  likely: boolean;
}

export interface Archive {
  kind: "zip" | "7z";
  entries: ArchiveEntry[];
  /** Whether any file needs a password. */
  encrypted: boolean;
  /** The password the file list itself was unlocked with, when even the names were encrypted. */
  listedWith?: string;
  /** Whether `password` opens the encrypted files. */
  check: (password: string) => Promise<boolean>;
  /** Decompresses one entry into a file named by its last path component. */
  extract: (e: ArchiveEntry, password?: string) => Promise<File>;
  close: () => Promise<void>;
}

/** The archive needs a password even to list its files. */
export class PasswordError extends Error {
  constructor() { super("This archive needs a password."); }
}

export type ArchiveKind = "zip" | "7z";

/** What kind of archive the file is, from its first bytes. */
export async function archiveKind(file: File): Promise<ArchiveKind | null> {
  if (file.size < 6) return null;
  const h = new Uint8Array(await file.slice(0, 6).arrayBuffer());
  if (h[0] === 0x50 && h[1] === 0x4b && ((h[2] === 3 && h[3] === 4) || (h[2] === 5 && h[3] === 6))) return "zip";
  if (h[0] === 0x37 && h[1] === 0x7a && h[2] === 0xbc && h[3] === 0xaf && h[4] === 0x27 && h[5] === 0x1c) return "7z";
  return null;
}

const NOT_BINARY = /\.(txt|md|json|xml|html?|csv|log|ini|cfg|ya?ml|png|jpe?g|gif|bmp|ico|pdf|docx?|xlsx?|pptx?|rtf|zip|7z|rar|gz|tar|sha\d*|md5|sig)$/i;
const BINARY = /\.(exe|dll|sys|scr|ocx|cpl|drv|efi|elf|so(\.\d+)*|dylib|bundle|kext|bin|o|ko|out|axf)$/i;

export function looksLikeBinary(name: string): boolean {
  const base = name.slice(name.lastIndexOf("/") + 1);
  if (BINARY.test(base)) return true;
  if (NOT_BINARY.test(base)) return false;
  return !base.includes(".");
}

export const baseName = (name: string) => name.slice(name.lastIndexOf("/") + 1) || name;

/** Opens an archive and lists its files. `password` is only needed when the list itself is encrypted (7z). */
export async function openArchive(file: File, kind: ArchiveKind, password?: string, signal?: AbortSignal): Promise<Archive> {
  signal?.throwIfAborted();
  if (file.size > ARCHIVE_MAX_BYTES) throw new ArchiveLimitError("Archives must be at most 256 MiB.");
  return kind === "zip" ? (await import("./archive.zip")).openZip(file, signal) : openSevenZip(file, password, signal);
}

/** The first of the well-known passwords that opens the archive, if any. */
export async function guessPassword(a: Archive): Promise<string | null> {
  for (const p of KNOWN_PASSWORDS) if (await a.check(p)) return p;
  return null;
}

/** The smallest encrypted file: the cheapest one to prove a password on. */
export const probeOf = (entries: ArchiveEntry[]) => entries.filter((e) => e.encrypted).sort((x, y) => x.size - y.size)[0];

// ---- 7z, through 7-Zip compiled to WebAssembly (loaded only when a 7z is opened)

/** Stands in for "no password" so 7-Zip fails instead of waiting for input. */
const NONE = "\u0001binfera-no-password";

interface Run { code: number; out: string[]; err: string[]; bytes?: Uint8Array<ArrayBuffer> }

/** One 7-Zip run on a fresh instance holding a copy of the archive. */
async function sevenZip(file: File, args: (archive: string) => string[], signal: AbortSignal, output?: string): Promise<Run> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./archive.worker.ts", import.meta.url), { type: "module" });
    const finish = (error?: Error, result?: Run) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", cancel);
      worker.terminate();
      if (error) reject(error); else resolve(result!);
    };
    const cancel = () => finish(new DOMException("Archive reading cancelled.", "AbortError"));
    const timer = setTimeout(() => finish(new ArchiveLimitError("Archive reading exceeded 30 seconds.")), ARCHIVE_TIMEOUT_MS);
    signal.addEventListener("abort", cancel, { once: true });
    worker.onerror = () => finish(new Error("Could not read this 7z archive."));
    worker.onmessage = ({ data }) => {
      if (data.password) finish(new PasswordError());
      else if (data.error) finish(data.limit ? new ArchiveLimitError(data.error) : new Error(data.error));
      else finish(undefined, data);
    };
    worker.postMessage({ file, args: args("/in/archive.7z"), output, maxBytes: ARCHIVE_MAX_BYTES, maxEntries: ARCHIVE_MAX_ENTRIES });
  });
}

const wrongPassword = (r: Run) => /wrong password|encrypted file|Cannot open encrypted/i.test(r.err.join("\n") + r.out.join("\n"));

async function openSevenZip(file: File, password?: string, signal?: AbortSignal): Promise<Archive> {
  const ctl = new AbortController();
  const cancel = () => ctl.abort();
  signal?.addEventListener("abort", cancel, { once: true });
  const close = async () => { ctl.abort(); signal?.removeEventListener("abort", cancel); };
  try {
    const pw = password || NONE;
    const r = await sevenZip(file, (a) => ["l", "-slt", "-spd", "-y", "-p" + pw, a], ctl.signal);
    if (r.code !== 0) {
      if (wrongPassword(r)) throw new PasswordError();
      throw new Error("This 7z file is damaged or uses a format the browser cannot read.");
    }
    const entries: ArchiveEntry[] = [];
    let cur: Record<string, string> | null = null;
    let inFiles = false;
    const flush = () => {
      if (cur && cur.Path && cur.Folder !== "+" && !/^D/.test(cur.Attributes ?? "")) {
        if (entries.length >= ARCHIVE_MAX_ENTRIES) throw new ArchiveLimitError("Archives may contain at most 10,000 files.");
        entries.push({ name: cur.Path.replace(/\\/g, "/"), size: Number(cur.Size) || 0, encrypted: cur.Encrypted === "+", likely: looksLikeBinary(cur.Path.replace(/\\/g, "/")) });
      }
      cur = null;
    };
    for (const line of r.out) {
      if (line.startsWith("----------")) { inFiles = true; continue; }
      if (!inFiles) continue;
      if (line === "") { flush(); continue; }
      const eq = line.indexOf(" = ");
      if (eq < 0) continue;
      (cur ??= {})[line.slice(0, eq)] = line.slice(eq + 3);
    }
    flush();
    const listedWith = password;
    const get = async (e: ArchiveEntry, p?: string): Promise<File> => {
      if (!entries.includes(e)) throw new Error("This file is not in the archive.");
      checkEntry(e);
      const x = await sevenZip(file, (a) => ["x", "-y", "-spd", "-o/out", "-p" + (p || listedWith || NONE), "--", a, e.name], ctl.signal, "/out/" + e.name);
      if (x.code !== 0) throw wrongPassword(x) ? new PasswordError() : new Error("Could not extract " + e.name + ": " + (x.err.join(" ").trim() || "unknown error"));
      return new File([x.bytes!], baseName(e.name));
    };
    return {
      kind: "7z",
      entries,
      encrypted: entries.some((e) => e.encrypted) || !!password,
      listedWith,
      check: async (p) => {
        const probe = probeOf(entries);
        if (!probe) return true;
        try { await get(probe, p); return true; } catch (e) {
          if (e instanceof ArchiveLimitError || ctl.signal.aborted) throw e;
          return false;
        }
      },
      extract: (e, p) => get(e, p),
      close,
    };
  } catch (e) { await close(); throw e; }
}
