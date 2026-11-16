import { createContext, useContext } from "react";
import { project } from "./project/client";
import type { Annotation, Edit } from "./project/types";

type NoteEdit = { kind: Edit["kind"]; target: string; value?: string };
type Write = { set?: Edit; clear?: { kind: Edit["kind"]; target: string } };

/** Analyst names, comments and stars for one sample, kept in this browser under its SHA-256. The names are looked up by every
 *  label, and shown in place of the original in the decompiled body and when it is copied. One per open file: two files
 *  being compared often have functions at the same address. */
export class Notes {
  private renames = new Map<number, string>();
  private stars = new Set<number>();
  /** Local variable names, per function: "address:original" -> name. */
  private vars = new Map<string, string>();
  private key = "";
  private history: (NoteEdit & { after?: string })[] = [];
  private writes: Promise<void> = Promise.resolve();
  private waitingEdits: Write[] | null = null;
  /** Comments from the project database, per function address. */
  private notes = new Map<number, { text: string; source: "human" | "ai" }[]>();
  /** Function names a model chose, with the confidence it gave. Names matched from library signatures are not among them. */
  private aiNames = new Map<number, string>();
  private synced: { sha: string; revision: number } | null = null;
  /** Names the file itself gives its functions: the export table. */
  private exported = new Map<number, string>();

  /** `legacy` is the older file-name key: notes saved under it move to the hash the first time the sample is opened. */
  load(sample: string, legacy?: string) {
    if (sample === this.key) return;
    this.key = sample;
    this.renames.clear();
    this.stars.clear();
    this.vars.clear();
    this.notes.clear();
    this.aiNames.clear();
    this.history = [];
    try {
      const old = legacy ? localStorage.getItem("binfera:" + legacy) : null;
      const stored = localStorage.getItem(this.storeKey());
      const raw = JSON.parse(stored ?? old ?? "{}") as { names?: Record<string, string>; stars?: number[]; vars?: Record<string, string>; comments?: Record<string, string> };
      for (const [ad, n] of Object.entries(raw.names ?? {})) this.renames.set(Number(ad), n);
      for (const ad of raw.stars ?? []) this.stars.add(ad);
      for (const [k, n] of Object.entries(raw.vars ?? {})) this.vars.set(k, n);
      for (const [ad, text] of Object.entries(raw.comments ?? {})) this.notes.set(Number(ad), [{ text, source: "human" }]);
      if (old !== null && stored === null) { localStorage.setItem(this.storeKey(), old); localStorage.removeItem("binfera:" + legacy); }
    } catch { /* blocked or corrupt storage: start empty */ }
  }

  /**
   * Desktop only: ties these notes to the project database `binfera mcp` also writes. The first time
   * a file is opened here, notes saved in this browser storage are imported as the analyst's own;
   * after that the database is the source of truth, polled so an agent's edits appear live.
   */
  attach(sha: string, name: string, size: number, onChange: () => void): () => void {
    const client = project;
    if (!client) return () => {};
    let live = true;
    const waiting: Write[] = [];
    this.waitingEdits = waiting;
    const flag = "binfera:imported:" + sha;
    const marksFlag = "binfera:marks-imported:" + sha;
    const merge = (loaded: { revision: number; annotations: Annotation[] }) => {
      this.renames.clear();
      this.stars.clear();
      this.vars.clear();
      this.notes.clear();
      this.aiNames.clear();
      for (const a of loaded.annotations) {
        if (a.kind === "rename_function") { this.renames.set(parseInt(a.target, 16), a.value); if (a.source === "ai" && a.run_id !== "auto-library") this.aiNames.set(parseInt(a.target, 16), a.confidence); }
        else if (a.kind === "rename_variable") {
          const [ad, id] = a.target.split(":");
          this.vars.set(parseInt(ad, 16) + ":" + id, a.value);
        } else if (a.kind === "star") {
          this.stars.add(parseInt(a.target, 16));
        } else if (a.kind === "add_comment") {
          const ad = parseInt(a.target, 16);
          this.notes.set(ad, [...(this.notes.get(ad) ?? []), { text: a.value, source: a.source }]);
        }
      }
      this.synced = { sha, revision: loaded.revision };
      this.save();
    };
    const pull = async (): Promise<void> => {
      const writes = this.writes;
      await writes;
      while (live && waiting.length) {
        const op = waiting.shift()!;
        if (op.set) await client.apply(sha, [op.set]); else await client.remove(sha, [op.clear!]);
      }
      const loaded = await client.load(sha, name, size);
      if ((writes !== this.writes || waiting.length) && live) return pull();
      if (live) { merge(loaded); onChange(); }
    };
    (async () => {
      let imported = false, marksImported = false;
      try { imported = localStorage.getItem(flag) !== null; marksImported = localStorage.getItem(marksFlag) !== null; } catch { /* storage unavailable */ }
      const loaded = await client.load(sha, name, size);
      if (!live) return;
      const edits: Edit[] = [];
      const add = (kind: Edit["kind"], target: string, value: string) => {
        // Existing database annotations win over legacy browser copies.
        if (!loaded.annotations.some((a) => a.kind === kind && a.target === target)) edits.push({ kind, target, value, confidence: "certain", evidence: [] });
      };
      if (!imported) {
        for (const [ad, value] of this.renames) add("rename_function", "0x" + ad.toString(16), value);
        for (const [key, value] of this.vars) { const [ad, id] = key.split(":"); add("rename_variable", "0x" + Number(ad).toString(16) + ":" + id, value); }
      }
      if (!marksImported) {
        for (const ad of this.stars) add("star", "0x" + ad.toString(16), "true");
        for (const [ad, comments] of this.notes) for (const c of comments) if (c.source === "human") add("add_comment", "0x" + ad.toString(16), c.text);
      }
      if (edits.length) await client.apply(sha, edits);
      if (!live) return;
      try { localStorage.setItem(flag, "1"); localStorage.setItem(marksFlag, "1"); } catch { /* storage unavailable */ }
      await pull();
    })().catch((e) => console.warn("project database unavailable; notes stay local", e));
    const timer = setInterval(async () => {
      if (document.hidden || !this.synced) return;
      try { if ((await client.revision(sha)) !== this.synced.revision) await pull(); } catch { /* retry on the next tick */ }
    }, 1500);
    this.refreshNow = pull;
    return () => { live = false; clearInterval(timer); this.synced = null; this.refreshNow = null; if (this.waitingEdits === waiting) this.waitingEdits = null; };
  }

  /** Re-reads the project database now, e.g. after an undo. */
  refreshNow: (() => Promise<void>) | null = null;

  /** Project readers must wait until registration and the initial notes import have finished. */
  isAttached(sha: string) { return this.synced?.sha === sha; }

  comments(ad: number) { return this.notes.get(ad) ?? []; }
  /** The comment on one instruction (or the function entry), as a single line of text. */
  commentAt(ad: number, byline = false): string | undefined {
    const list = this.notes.get(ad);
    return list?.length ? list.map((c) => (byline ? (c.source === "human" ? "You: " : "AI: ") : "") + c.text).join(" · ") : undefined;
  }
  /** The confidence of an agent's name for this function, or undefined when a person named it (or nobody did). */
  aiName(ad: number) { return this.renames.has(ad) ? this.aiNames.get(ad) : undefined; }
  hasComments() { return this.notes.size > 0; }

  /** Writes an analyst edit through to the project database. */
  private push(ops: Write) {
    const s = this.synced;
    if (!project) return;
    if (!s) { this.waitingEdits?.push(ops); return; }
    const client = project;
    this.writes = this.writes.then(async () => {
      const revision = ops.set ? await client.apply(s.sha, [ops.set]) : await client.remove(s.sha, [ops.clear!]);
      // A revision gap means another writer changed the project too; let polling pull it.
      if (this.synced === s && revision === s.revision + 1) s.revision = revision;
    }).catch((e) => console.warn("could not save to the project database", e));
  }

  private storeKey() { return "binfera:" + this.key; }

  private save() {
    if (!this.key) return;
    try {
      localStorage.setItem(this.storeKey(), JSON.stringify({ names: Object.fromEntries(this.renames), stars: [...this.stars], vars: Object.fromEntries(this.vars), comments: Object.fromEntries(this.allComments().filter((c) => c.source === "human").map((c) => [c.address, c.text])) }));
    } catch { /* storage unavailable: the notes last for this tab only */ }
  }

  renamed(ad: number) { return this.renames.get(ad); }
  varName(fn: number, id: string) { return this.vars.get(fn + ":" + id); }
  private value(kind: Edit["kind"], target: string): string | undefined {
    const [addr, id] = target.split(":");
    const ad = parseInt(addr, 16);
    if (kind === "rename_function") return this.renames.get(ad);
    if (kind === "rename_variable") return this.vars.get(ad + ":" + id);
    if (kind === "star") return this.stars.has(ad) ? "true" : undefined;
    return this.notes.get(ad)?.[0]?.text;
  }

  private edit(op: NoteEdit, remember = true) {
    const value = op.value?.trim() || undefined;
    const previous = this.value(op.kind, op.target);
    if (value === previous) return;
    if (remember) this.history.push({ kind: op.kind, target: op.target, value: previous, after: value });
    const [addr, id] = op.target.split(":");
    const ad = parseInt(addr, 16);
    if (op.kind === "rename_function") {
      this.aiNames.delete(ad);
      if (value) this.renames.set(ad, value); else this.renames.delete(ad);
    } else if (op.kind === "rename_variable") {
      if (value) this.vars.set(ad + ":" + id, value); else this.vars.delete(ad + ":" + id);
    } else if (op.kind === "star") {
      if (value) this.stars.add(ad); else this.stars.delete(ad);
    } else {
      if (value) this.notes.set(ad, [{ text: value, source: "human" }]); else this.notes.delete(ad);
    }
    this.save();
    this.push(value ? { set: { kind: op.kind, target: op.target, value, confidence: "certain", evidence: [] } } : { clear: { kind: op.kind, target: op.target } });
  }

  canUndo() { return this.history.some((op) => this.value(op.kind, op.target) === op.after); }
  undo(): NoteEdit | undefined {
    let op = this.history.pop();
    while (op && this.value(op.kind, op.target) !== op.after) op = this.history.pop();
    if (op) this.edit(op, false);
    return op;
  }
  allComments() { return [...this.notes].sort(([a], [b]) => a - b).flatMap(([address, comments]) => comments.map((c) => ({ address, ...c }))); }
  setComment(ad: number, text: string) { this.edit({ kind: "add_comment", target: "0x" + ad.toString(16), value: text }); }
  renameVar(fn: number, id: string, name: string) { this.edit({ kind: "rename_variable", target: "0x" + fn.toString(16) + ":" + id, value: name }); }
  isStarred(ad: number) { return this.stars.has(ad); }
  rename(ad: number, name: string) { this.edit({ kind: "rename_function", target: "0x" + ad.toString(16), value: name }); }
  toggleStar(ad: number) { this.edit({ kind: "star", target: "0x" + ad.toString(16), value: this.stars.has(ad) ? undefined : "true" }); }
  setExportNames(m: Map<number, string>) { this.exported = m; }
  exportOf(ad: number) { return this.exported.get(ad); }
  /** What to call a function, whichever names it has. */
  label(ad: number, name?: string | null) {
    return this.renamed(ad) ?? name ?? this.exportOf(ad) ?? "FUN_" + ad.toString(16).padStart(8, "0");
  }
}

const NotesContext = createContext(new Notes());
export const NotesProvider = NotesContext.Provider;
export const useNotes = () => useContext(NotesContext);

export const sha256 = async (data: Uint8Array) =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>)), (b) => b.toString(16).padStart(2, "0")).join("");
