import { useMemo, useState } from "react";
import { desktop } from "./project/client";
import type { Folder, FolderFile } from "./project/types";
import Wordmark from "./Wordmark";
import { bytes } from "./workspace/labels";

interface Dir { name: string; path: string; dirs: Dir[]; files: FolderFile[]; count: number }

const FORMAT = { pe: "PE", elf: "ELF", macho: "Mach-O", zip: "Zip", "7z": "7z" } as const;

function build(files: FolderFile[]): Dir {
  const root: Dir = { name: "", path: "", dirs: [], files: [], count: 0 };
  for (const f of files) {
    const parts = f.path.split("/");
    let at = root;
    at.count++;
    for (const [i, name] of parts.slice(0, -1).entries()) {
      const path = parts.slice(0, i + 1).join("/");
      let next = at.dirs.find((d) => d.name === name);
      if (!next) at.dirs.push((next = { name, path, dirs: [], files: [], count: 0 }));
      next.count++;
      at = next;
    }
    at.files.push(f);
  }
  return root;
}

/** Folds a chain of folders holding nothing but one folder into one row ("a/b/c"). */
function fold(d: Dir): Dir {
  while (d.files.length === 0 && d.dirs.length === 1 && d.path) {
    const only = d.dirs[0];
    d = { ...only, name: `${d.name}/${only.name}` };
  }
  return { ...d, dirs: d.dirs.map(fold) };
}

/** A folder on its own screen: the executables under it as a tree, to pick which one to analyze. */
export default function FolderView({ folder, onFolder, onFile, onBack }: {
  folder: Folder; onFolder: (f: Folder) => void; onFile: (f: File) => void; onBack: () => void;
}) {
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<Set<string> | null>(null);
  const [opening, setOpening] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const q = filter.trim().toLowerCase();
  const shown = useMemo(() => (q ? folder.files.filter((f) => f.path.toLowerCase().includes(q)) : folder.files), [folder, q]);
  const tree = useMemo(() => fold(build(shown)), [shown]);
  // Small folders start unfolded; a big one starts with its top level.
  const expanded = (d: Dir) => !!q || (open ? open.has(d.path) : folder.files.length <= 60);
  const toggle = (d: Dir) => {
    const next = new Set(open ?? (folder.files.length <= 60 ? allDirs(tree) : []));
    if (!next.delete(d.path)) next.add(d.path);
    setOpen(next);
  };

  const run = async (id: string, task: () => Promise<void>) => {
    setError(null);
    setOpening(id);
    try { await task(); } catch (e) { setError(String((e as Error).message ?? e)); } finally { setOpening(null); }
  };
  const openFile = (f: FolderFile) => run(f.path, async () => onFile(await desktop!.openFromFolder(folder.root, f.path)));
  const rescan = async () => {
    setBusy(true);
    await run("scan", async () => onFolder(await desktop!.scanFolder(folder.root)));
    setBusy(false);
  };
  const another = async () => {
    setBusy(true);
    await run("pick", async () => { const f = await desktop!.pickFolder(); if (f) { setOpen(null); setFilter(""); onFolder(f); } });
    setBusy(false);
  };

  const row = (f: FolderFile, depth: number) => (
    <li key={f.path}>
      <button type="button" className="ft-file" style={{ paddingLeft: 12 + depth * 16 }} onClick={() => openFile(f)} disabled={opening !== null} title={f.path}>
        <span className="arc-name">{f.path.split("/").pop()}</span>
        <em>{FORMAT[f.kind]}</em>
        <span className="arc-size">{opening === f.path ? "Opening…" : bytes(f.size)}</span>
      </button>
    </li>
  );
  const dir = (d: Dir, depth: number): React.ReactNode => {
    const isOpen = expanded(d);
    return (
      <li key={d.path}>
        <button type="button" className="ft-dir" style={{ paddingLeft: 12 + depth * 16 }} onClick={() => toggle(d)} aria-expanded={isOpen}>
          <span className="ft-caret" aria-hidden>{isOpen ? "▾" : "▸"}</span>
          <span className="arc-name">{d.name}</span>
          <span className="arc-size">{d.count}</span>
        </button>
        {isOpen && <ul>{d.dirs.map((c) => dir(c, depth + 1))}{d.files.map((f) => row(f, depth + 1))}</ul>}
      </li>
    );
  };

  return (
    <main className="landing archive">
      <button className="brand" onClick={onBack} title="Home"><Wordmark /></button>
      <section className="arc-card ft-card" aria-live="polite">
        <header className="arc-head">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
          </svg>
          <div>
            <strong>{folder.name}</strong>
            <span title={folder.root}>{folder.files.length} file{folder.files.length === 1 ? "" : "s"} found · PE, ELF, Mach-O, zip, 7z</span>
          </div>
        </header>
        {folder.files.length > 8 && (
          <input className="arc-filter" type="search" placeholder="Filter files" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter files" />
        )}
        {folder.files.length === 0
          ? <p className="arc-hint">No PE, ELF, Mach-O, zip or 7z files in this folder or its sub-folders.</p>
          : <ul className="arc-list ft-tree">{tree.dirs.map((d) => dir(d, 0))}{tree.files.map((f) => row(f, 0))}{shown.length === 0 && <li className="fine">No files match.</li>}</ul>}
        {folder.truncated && <p className="arc-hint">This folder is very large: the scan stopped early, so some files may be missing.</p>}
        {error && <p className="error" role="alert">{error}</p>}
        <div className="ft-actions">
          <button type="button" className="demo" onClick={rescan} disabled={busy || opening !== null}>{opening === "scan" ? "Scanning…" : "Rescan"}</button>
          <button type="button" className="demo" onClick={another} disabled={busy || opening !== null}>Choose another folder…</button>
        </div>
      </section>
      <button type="button" className="demo" onClick={onBack}>← Back</button>
    </main>
  );
}

function allDirs(d: Dir): string[] {
  return d.dirs.flatMap((c) => [c.path, ...allDirs(c)]);
}
