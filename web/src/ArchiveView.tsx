import { useEffect, useRef, useState } from "react";
import { KNOWN_PASSWORDS, PasswordError, archiveKind, guessPassword, openArchive, type Archive, type ArchiveEntry, type ArchiveKind } from "./archive";
import Wordmark from "./Wordmark";

const size = (n: number) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B");

type Phase =
  | { kind: "reading" }
  | { kind: "unlocking" }
  | { kind: "password"; wrong: boolean }
  | { kind: "ready" }
  | { kind: "error"; message: string };

/** A zip on its own screen: unlocks it (known passwords first, then asks) and lets the user pick which file to analyze. */
export default function ArchiveView({ file, onOpen, onNext, onBack }: { file: File; onOpen: (f: File) => void; onNext: (f: File) => void; onBack: () => void }) {
  const [phase, setPhase] = useState<Phase>({ kind: "reading" });
  const [archive, setArchive] = useState<Archive | null>(null);
  const [password, setPassword] = useState("");
  const [guessed, setGuessed] = useState(false);
  const [opening, setOpening] = useState<string | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [showAll, setShowAll] = useState(false);
  const live = useRef(true);
  const reading = useRef(new AbortController());

  const pick = (a: Archive, pw: string) => {
    const files = a.entries;
    const target = files.length === 1 ? files[0] : null;
    setPhase({ kind: "ready" });
    if (target) open(target, pw, a);
  };

  const open = async (e: ArchiveEntry, pw: string, a: Archive | null = archive) => {
    setOpening(e.name);
    setOpenError(null);
    try {
      const f = await a!.extract(e, pw);
      if (live.current) onOpen(f);
    } catch (err) {
      if (live.current) setOpenError(String((err as Error).message ?? err));
    } finally {
      if (live.current) setOpening(null);
    }
  };

  const [kind, setKind] = useState<ArchiveKind>("zip");

  /** Opens the archive; when even its file list is encrypted, `password` unlocks that. */
  const load = async (password?: string): Promise<Archive | "locked"> => {
    const k = (await archiveKind(file)) ?? "zip";
    setKind(k);
    try {
      return await openArchive(file, k, password, reading.current.signal);
    } catch (e) {
      if (e instanceof PasswordError) return "locked";
      throw e;
    }
  };

  const settle = (a: Archive, pw: string) => {
    setArchive(a);
    pick(a, pw);
  };

  useEffect(() => {
    live.current = true;
    reading.current = new AbortController();
    let opened: Archive | null = null;
    (async () => {
      try {
        let a = await load();
        if (a === "locked") {
          // The names are encrypted too: only a password lets the list open at all.
          setPhase({ kind: "unlocking" });
          for (const p of KNOWN_PASSWORDS) {
            const r = await load(p);
            if (!live.current) return;
            if (r !== "locked") { setPassword(p); setGuessed(true); opened = r; return settle(r, p); }
          }
          return setPhase({ kind: "password", wrong: false });
        }
        opened = a;
        if (!live.current) return void a.close();
        setArchive(a);
        if (a.entries.length === 0) return setPhase({ kind: "error", message: "This archive contains no files." });
        if (!a.encrypted) return pick(a, "");
        setPhase({ kind: "unlocking" });
        const found = await guessPassword(a);
        if (!live.current) return;
        if (found === null) return setPhase({ kind: "password", wrong: false });
        setPassword(found);
        setGuessed(true);
        pick(a, found);
      } catch (e) {
        if (live.current) setPhase({ kind: "error", message: String((e as Error).message ?? e) });
      }
    })();
    return () => { live.current = false; reading.current.abort(); opened?.close().catch(() => {}); };
  }, [file]);

  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    if (!password) return;
    setPhase({ kind: "unlocking" });
    try {
      if (!archive) {
        const r = await load(password);
        if (!live.current) return;
        if (r === "locked") return setPhase({ kind: "password", wrong: true });
        return settle(r, password);
      }
      const ok = await archive.check(password);
      if (!live.current) return;
      if (ok) pick(archive, password);
      else setPhase({ kind: "password", wrong: true });
    } catch (e) {
      if (live.current) setPhase({ kind: "error", message: String((e as Error).message ?? e) });
    }
  };

  const entries = archive?.entries ?? [];
  const likelyCount = entries.filter((e) => e.likely).length;
  // Show only plausible executables by default, unless there are none or the user asks for everything.
  const restrict = likelyCount > 0 && likelyCount < entries.length && !showAll;
  const q = filter.trim().toLowerCase();
  const rows = entries
    .filter((e) => (!restrict || e.likely) && (!q || e.name.toLowerCase().includes(q)))
    .sort((a, b) => Number(b.likely) - Number(a.likely) || a.name.localeCompare(b.name));

  return (
    <main
      className="landing archive"
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) onNext(f); }}
    >
      <button className="brand" onClick={onBack} title="Choose another file"><Wordmark /></button>
      <section className="arc-card" aria-live="polite">
        <header className="arc-head">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M4 7.5 12 3l8 4.5v9L12 21l-8-4.5zM4 7.5 12 12m0 0 8-4.5M12 12v9" />
          </svg>
          <div>
            <strong>{file.name}</strong>
            <span>{kind === "7z" ? "7z archive" : "Zip archive"} · {size(file.size)}{entries.length ? ` · ${entries.length} file${entries.length === 1 ? "" : "s"}` : ""}</span>
          </div>
        </header>

        {(phase.kind === "reading" || phase.kind === "unlocking") && (
          <p className="arc-status"><i className="spin" aria-hidden />{phase.kind === "reading" ? "Reading the archive…" : "Trying common passwords…"}</p>
        )}

        {phase.kind === "error" && <p className="error">{phase.message}</p>}

        {phase.kind === "password" && (
          <form className="arc-pass" onSubmit={submit}>
            <label htmlFor="arc-pw">This archive is password-protected. None of the usual malware-sharing passwords opened it.</label>
            <div>
              <input id="arc-pw" type="password" value={password} autoFocus autoComplete="off" spellCheck={false}
                placeholder="Password" onFocus={(e) => e.target.select()} onChange={(e) => setPassword(e.target.value)} />
              <button type="submit" disabled={!password}>Unlock</button>
            </div>
            {phase.wrong && <p className="error" role="alert">That password did not work.</p>}
            <p className="fine">The password stays in this tab.</p>
          </form>
        )}

        {phase.kind === "ready" && (
          <>
            {archive?.encrypted && <p className="arc-unlocked">Unlocked{guessed ? <> with the usual password <code>{password}</code></> : ""}.</p>}
            {entries.length > 1 && <p className="arc-hint">Choose the file to analyze.</p>}
            {entries.length > 8 && (
              <input className="arc-filter" type="search" placeholder="Filter files" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter files" />
            )}
            <ul className="arc-list">
              {rows.map((e) => (
                <li key={e.name}>
                  <button type="button" onClick={() => open(e, password)} disabled={opening !== null}>
                    <span className="arc-name" title={e.name}>{e.name}</span>
                    {e.likely && <em>executable?</em>}
                    <span className="arc-size">{opening === e.name ? "Opening…" : size(e.size)}</span>
                  </button>
                </li>
              ))}
              {rows.length === 0 && <li className="fine">No files match.</li>}
            </ul>
            {restrict && (
              <button type="button" className="demo" onClick={() => setShowAll(true)}>Show all {entries.length} files</button>
            )}
            {openError && <p className="error" role="alert">{openError}</p>}
          </>
        )}
      </section>
      <button type="button" className="demo" onClick={onBack}>← Choose another file</button>
    </main>
  );
}
