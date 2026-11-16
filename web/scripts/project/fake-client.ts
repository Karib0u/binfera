// An in-memory stand-in for the Tauri project commands, with the store's revision semantics.
const db = { revision: 0, ann: [] as any[] };
export const calls: string[] = [];
let loadGate: Promise<void> | null = null;
export const pauseLoads = () => {
  let resume!: () => void;
  loadGate = new Promise<void>((resolve) => { resume = resolve; });
  return () => { loadGate = null; resume(); };
};
export const project = {
  load: async () => { await loadGate; return { revision: db.revision, annotations: db.ann.map((a) => ({ ...a })), counts: {} }; },
  revision: async () => db.revision,
  apply: async (_s: string, edits: any[]) => { for (const e of edits) { db.ann = db.ann.filter((a) => !(a.kind === e.kind && a.target === e.target)); db.ann.push({ ...e, source: "human", confidence: "certain", run_id: null }); } calls.push("apply:" + edits.length); return ++db.revision; },
  remove: async (_s: string, items: any[]) => { db.ann = db.ann.filter((a) => !items.some((i) => i.kind === a.kind && i.target === a.target)); calls.push("remove"); return ++db.revision; },
};
export const library = (target: string, value: string) => { db.ann.push({ kind: "rename_function", target, value, source: "ai", confidence: "likely", run_id: "auto-library" }); db.revision++; };
export const agent = (kind: string, target: string, value: string) => { db.ann = db.ann.filter((a) => a.kind !== kind || a.target !== target); db.ann.push({ kind, target, value, source: "ai", confidence: "likely", run_id: "r1" }); db.revision++; };
