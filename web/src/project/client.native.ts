// Desktop build's stand-in for client.ts: the project database through the Tauri commands in
// src-tauri/src/project.rs, the same file `binfera mcp` writes.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import type { Desktop, Folder, ProjectClient, Recent } from "./types";
import { sha256 } from "../names";

export const project: ProjectClient | null = {
  load: (sha256, name, size) => invoke("project_load", { sha256, name, size }),
  path: (sha256) => invoke("project_path", { sha256 }),
  revision: (sha256) => invoke("project_revision", { sha256 }),
  apply: (sha256, edits) => invoke("project_apply", { sha256, edits }),
  remove: (sha256, items) => invoke("project_remove", { sha256, items }),
  undo: (sha256, runId) => invoke("project_undo", { sha256, runId }),
  activity: (sha256) => invoke("project_activity", { sha256 }),
  reports: (sha256) => invoke("project_reports", { sha256 }),
  report: (sha256, version) => invoke("project_report", { sha256, version }),
  setup: () => invoke("mcp_setup"),
};

const read = async (path: string, name: string) => new File([await invoke<ArrayBuffer>("file_read", { path })], name);

export const desktop: Desktop | null = {
  recent: () => invoke<Recent[]>("project_recent"),
  forget: (sha) => invoke("project_forget", { sha256: sha }),
  pick: async (expect) => {
    const picked = await invoke<{ path: string; name: string; sha256: string } | null>("file_pick", { expect: expect ?? null });
    return picked && { file: await read(picked.path, picked.name), sha256: picked.sha256 };
  },
  open: async (entry) => {
    const path = await project!.path(entry.sha256);
    if (!path) throw new Error("This file is no longer available. Locate it to reopen.");
    const file = await read(path, entry.name);
    if (await sha256(new Uint8Array(await file.arrayBuffer())) !== entry.sha256) throw new Error(`${entry.name} has changed since it was analysed.`);
    return file;
  },
  reveal: (sha) => invoke("file_reveal", { sha256: sha }),
  pickFolder: () => invoke<Folder | null>("folder_pick"),
  scanFolder: (root) => invoke<Folder>("folder_scan", { root }),
  openFromFolder: async (root, path) => {
    const picked = await invoke<{ path: string; name: string }>("folder_open", { root, path });
    return read(picked.path, picked.name);
  },
};

interface Drag { kind: "over" | "leave" | "drop"; x: number; y: number; files: { path: string; name: string }[]; errors: string[]; folder: Folder | null }

/**
 * The window handles file drops itself (src-tauri/src/drop.rs) so that the history learns each
 * file's real path, which the page's own drop event never carries. The page's handlers are written
 * for DOM drag events, so each native drop is replayed as one: `dragover` and `dragleave` to
 * highlight where the file would go, and `drop` carrying the files, read from the paths Rust
 * registered, at the spot the pointer was.
 */
export function installNativeDrop() {
  let over: Element | null = null;
  const send = (type: string, target: Element, files: File[] = []) => {
    const transfer = new DataTransfer();
    for (const f of files) transfer.items.add(f);
    const event = new Event(type, { bubbles: true, cancelable: true });
    // The DragEvent constructor does not take a data transfer everywhere; the page only reads it.
    Object.defineProperty(event, "dataTransfer", { value: transfer });
    target.dispatchEvent(event);
  };
  const at = (x: number, y: number) => document.elementFromPoint(x / devicePixelRatio, y / devicePixelRatio) ?? document.body;
  void listen<Drag>("binfera-drag", async ({ payload: d }) => {
    if (d.kind === "leave") {
      if (over) send("dragleave", over);
      over = null;
    } else if (d.kind === "over") {
      const target = at(d.x, d.y);
      if (over && over !== target) send("dragleave", over);
      over = target;
      send("dragover", target);
    } else if (d.folder) {
      if (over) send("dragleave", over);
      over = null;
      window.dispatchEvent(new CustomEvent("binfera-folder", { detail: d.folder }));
    } else {
      const target = at(d.x, d.y);
      if (over) send("dragleave", over);
      over = null;
      const files = await Promise.all(d.files.map((f) => read(f.path, f.name).catch(() => null)));
      send("drop", target, files.filter((f): f is File => f !== null));
      if (d.errors.length) console.warn("not opened:", d.errors.join("; "));
    }
  });
}

const ZOOM_KEY = "binfera.zoom", ZOOM_STEPS = [0.5, 0.67, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3];

/** A webview has no browser menu, so page zoom is ours: Cmd/Ctrl with + (also =), - and 0, kept between launches. */
export const installZoom = (): void => {
  let level = 1;
  try { level = Number(localStorage.getItem(ZOOM_KEY)) || 1; } catch { /* storage unavailable */ }
  const apply = (next: number) => {
    level = next;
    try { localStorage.setItem(ZOOM_KEY, String(next)); } catch { /* the zoom lasts for this launch only */ }
    void getCurrentWebview().setZoom(next).catch(() => {});
  };
  if (level !== 1) apply(level);
  const nearest = () => ZOOM_STEPS.reduce((best, z, i) => (Math.abs(z - level) < Math.abs(ZOOM_STEPS[best] - level) ? i : best), 0);
  addEventListener("keydown", (e) => {
    if (!(e.metaKey || e.ctrlKey) || e.altKey) return;
    // Layouts differ: "+" needs Shift on a US keyboard and "=" is the same key; AZERTY has both on others.
    if (e.key === "+" || e.key === "=" || e.code === "NumpadAdd") { e.preventDefault(); apply(ZOOM_STEPS[Math.min(ZOOM_STEPS.length - 1, nearest() + 1)]); }
    else if (e.key === "-" || e.key === "_" || e.code === "NumpadSubtract") { e.preventDefault(); apply(ZOOM_STEPS[Math.max(0, nearest() - 1)]); }
    else if (e.key === "0" || e.code === "Numpad0") { e.preventDefault(); apply(1); }
  });
};
