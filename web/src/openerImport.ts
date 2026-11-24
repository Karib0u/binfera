/**
 * One-shot binary handoff from an opener tab (for example FileBus) via window.postMessage.
 *
 * When a tab opens Binfera at `#import`, Binfera announces readiness to `window.opener`
 * and accepts a single `{ type: "binfera:open", name, bytes }` message from that exact
 * opener window. Bytes stay in browser memory and are never uploaded.
 */

export const OPENER_PROTOCOL_VERSION = 1;
export const OPENER_IMPORT_HASH = "#import";
export const MAX_OPENER_IMPORT_BYTES = 256 * 1024 * 1024;

export interface OpenerMessageEventLike {
  source: unknown;
  origin: string;
  data: unknown;
}

export interface OpenerPostTarget {
  postMessage(message: unknown, targetOrigin: string): void;
}

export interface OpenerWindowLike {
  location: { hash: string };
  opener: OpenerPostTarget | null;
  addEventListener(type: "message", listener: (event: OpenerMessageEventLike) => void): void;
  removeEventListener(type: "message", listener: (event: OpenerMessageEventLike) => void): void;
}

export function isOpenerImportHash(hash: string): boolean {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  return params.has("import");
}

export function sanitizeImportName(name: unknown): string {
  if (typeof name !== "string") return "sample.bin";
  const leaf = name
    .replace(/\\/g, "/")
    .split("/")
    .pop()
    ?.replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  if (!leaf || leaf === "." || leaf === "..") return "sample.bin";
  return leaf;
}

export function extractImportBytes(raw: unknown): Uint8Array<ArrayBuffer> | null {
  let view: Uint8Array;
  if (raw instanceof ArrayBuffer) {
    view = new Uint8Array(raw);
  } else if (ArrayBuffer.isView(raw)) {
    view = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  } else {
    return null;
  }
  if (view.byteLength === 0 || view.byteLength > MAX_OPENER_IMPORT_BYTES) return null;
  const copy = new Uint8Array(new ArrayBuffer(view.byteLength));
  copy.set(view);
  return copy;
}

export function installOpenerImport({
  win,
  onFile,
  onClearHash,
}: {
  win: OpenerWindowLike;
  onFile: (file: File) => void;
  onClearHash?: () => void;
}): () => void {
  const opener = win.opener;
  if (!opener || !isOpenerImportHash(win.location.hash)) return () => {};

  let consumed = false;
  const onMessage = (event: OpenerMessageEventLike) => {
    if (consumed || event.source !== opener) return;
    const payload = event.data;
    if (!payload || typeof payload !== "object") return;
    const msg = payload as { type?: unknown; name?: unknown; bytes?: unknown };
    if (msg.type !== "binfera:open") return;
    const bytes = extractImportBytes(msg.bytes);
    if (!bytes) return;

    consumed = true;
    win.removeEventListener("message", onMessage);
    const name = sanitizeImportName(msg.name);
    const targetOrigin = event.origin && event.origin !== "null" ? event.origin : "*";
    try {
      opener.postMessage({ type: "binfera:ack", version: OPENER_PROTOCOL_VERSION }, targetOrigin);
    } catch {
      // Opener may have closed right after posting; still open the received bytes.
    }
    onClearHash?.();
    onFile(new File([bytes], name));
  };

  win.addEventListener("message", onMessage);
  try {
    opener.postMessage({ type: "binfera:ready", version: OPENER_PROTOCOL_VERSION }, "*");
  } catch {
    win.removeEventListener("message", onMessage);
    return () => {};
  }

  return () => {
    consumed = true;
    win.removeEventListener("message", onMessage);
  };
}
