// Optional, local-only storage. Failure to hash, open or write must never stop an analysis.
const DATABASE = "binfera-results";
export const CACHE_MAX_BYTES = 300 * 1024 * 1024;
const kinds = ["image", "capa", "decomp"] as const;
export type CachedResults = Record<typeof kinds[number], Blob>;
interface Meta { sha256: string; engineId: string; size: number; lastUsed: number }

export async function digest(bytes: ArrayBuffer): Promise<string | null> {
  try {
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
  } catch { return null; }
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore("runs");
      request.result.createObjectStore("meta", { keyPath: "sha256" });
    };
    let blocked = false;
    request.onsuccess = () => { if (blocked) request.result.close(); else resolve(request.result); };
    request.onerror = () => reject(request.error);
    request.onblocked = () => { blocked = true; reject(new Error("result storage blocked")); };
  });
}

function finished(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(tx.error);
  });
}

function remove(tx: IDBTransaction, sha256: string) {
  tx.objectStore("runs").delete(IDBKeyRange.bound(`${sha256}:`, `${sha256}:\uffff`));
  tx.objectStore("meta").delete(sha256);
}

export async function readResults(sha256: string, engineId: string): Promise<CachedResults | null> {
  let db: IDBDatabase | undefined;
  try {
    db = await open();
    const tx = db.transaction(["runs", "meta"], "readwrite");
    const done = finished(tx);
    const meta = tx.objectStore("meta").get(sha256);
    const requests = kinds.map(kind => tx.objectStore("runs").get(`${sha256}:${engineId}:${kind}`));
    meta.onsuccess = () => {
      try {
        const entry = meta.result as Meta | undefined;
        if (entry?.engineId === engineId) tx.objectStore("meta").put({ ...entry, lastUsed: Date.now() });
      } catch { tx.abort(); }
    };
    await done;
    if (meta.result?.engineId !== engineId || requests.some(r => !(r.result instanceof Blob))) return null;
    return Object.fromEntries(kinds.map((kind, i) => [kind, requests[i].result])) as CachedResults;
  } catch { return null; }
  finally { db?.close(); }
}

export async function writeResults(sha256: string, engineId: string, results: CachedResults, maxBytes = CACHE_MAX_BYTES): Promise<void> {
  const size = kinds.reduce((sum, kind) => sum + results[kind].size, 0);
  if (size > maxBytes) return;
  let db: IDBDatabase | undefined;
  try {
    db = await open();
    const tx = db.transaction(["runs", "meta"], "readwrite");
    const done = finished(tx);
    const entries = tx.objectStore("meta").getAll();
    entries.onsuccess = () => {
      try {
        const others = (entries.result as Meta[]).filter(entry => entry.sha256 !== sha256);
        let total = others.reduce((sum, entry) => sum + entry.size, 0);
        others.sort((a, b) => a.lastUsed - b.lastUsed);
        for (const entry of others) {
          if (total + size <= maxBytes) break;
          remove(tx, entry.sha256);
          total -= entry.size;
        }
        remove(tx, sha256);
        for (const kind of kinds) tx.objectStore("runs").put(results[kind], `${sha256}:${engineId}:${kind}`);
        // Commit the metadata last, in the same transaction: partial runs are never visible.
        tx.objectStore("meta").put({ sha256, engineId, size, lastUsed: Date.now() } satisfies Meta);
      } catch { tx.abort(); }
    };
    await done;
  } catch { /* Blocked storage or quota exhaustion: keep the live result. */ }
  finally { db?.close(); }
}

/** All engine versions of one sample, including any incomplete entries. */
export async function forgetResults(sha256: string): Promise<void> {
  let db: IDBDatabase | undefined;
  try {
    db = await open();
    const tx = db.transaction(["runs", "meta"], "readwrite");
    const done = finished(tx);
    remove(tx, sha256);
    await done;
  } catch { /* Reanalysis still works when storage is unavailable. */ }
  finally { db?.close(); }
}
