import { useEffect, useState } from "react";
import { listDemos, loadDemo, type DemoSample } from "./demos";
import { bytes } from "./workspace/labels";
import type { Target } from "./workspace/location";
import type { CompareState } from "./views/CompareView";
import { Tag } from "./views/FunctionDiff";
import Wordmark from "./Wordmark";
import ThemeToggle from "./ThemeToggle";
import RecentFiles from "./RecentFiles";
import LandingSamples from "./LandingSamples";
import LandingTour from "./LandingTour";
import { desktop } from "./project/client";
import type { Folder, Recent } from "./project/types";
import "./landing.css";

/** Where a file dragged over the page would go. */
type Aim = "analyze" | "a" | "b";

const REPO = "https://github.com/Karib0u/binfera";

function Slot({ side, label, file, over, disabled, onFile }: {
  side: "a" | "b"; label: string; file: File | null; over: boolean; disabled: boolean; onFile: (f: File) => void;
}) {
  return (
    <label className={"lp-slot" + (over ? " is-over" : "")} data-slot={side}>
      <input className="sr-only" type="file" disabled={disabled} onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = ""; }} />
      <Tag side={side} />
      {file
        ? <><strong className="lp-slot-file" title={file.name}>{file.name}</strong><small>{bytes(file.size)}</small></>
        : <><strong>Drop, or <u>browse</u></strong><small>{label}</small></>}
    </label>
  );
}

/** One box takes the visitor's file; everything below it is for people who don't have one yet. */
export default function Landing({ onFile, compare, error, resume, link, onRaw, folder, onFolder, onFolderBack }: {
  /** Desktop: the folder opened before, to return to its tree. */
  folder?: Folder | null;
  onFolder?: (f: Folder) => void;
  onFolderBack?: () => void;
  onFile: (f: File, demo?: DemoSample, place?: Target) => void;
  compare: CompareState;
  error?: string | null;
  onRaw?: (format: "sc32" | "sc64") => void;
  /** The analysis still open behind this page, to return to. */
  resume?: { name: string; detail: string; go: () => void } | null;
  /** The place a shared or reloaded URL names: it can only be shown once the file is opened again. */
  link?: Target;
}) {
  const [comparing, setComparing] = useState(() => !!(compare.a || compare.b));
  const [aim, setAim] = useState<Aim | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [samples, setSamples] = useState<DemoSample[]>([]);
  useEffect(() => { listDemos().then(setSamples); }, []);

  const attempt = async (id: string, work: () => Promise<void>) => {
    setNotice(null);
    setLoading(id);
    try {
      await work();
    } catch (e) {
      setNotice(String((e as Error).message ?? e));
    } finally {
      setLoading(null);
    }
  };
  // The desktop build opens files with the system dialog, which also tells the history where they are.
  const pickNative = (expect?: string) => attempt("pick", async () => {
    const picked = await desktop!.pick(expect);
    if (picked) onFile(picked.file);
  });
  const pickFolder = () => attempt("folder", async () => {
    const picked = await desktop!.pickFolder();
    if (picked) onFolder?.(picked);
  });
  const reopen = (r: Recent) => attempt("recent:" + r.sha256, async () => onFile(await desktop!.open(r)));
  const trySample = (s: DemoSample) => attempt(s.id, async () => onFile(await loadDemo(s), s));
  // A small harmless program bundled with the site (see demo/), so people can try the tool without a binary.
  const tryHarmless = () => attempt("harmless", async () => {
    const res = await fetch(`${import.meta.env.BASE_URL}demo.exe`);
    if (!res.ok) throw new Error(`demo sample unavailable (${res.status})`);
    onFile(new File([await res.blob()], "binfera-demo.exe"));
  });

  const running = compare.stage !== null;
  const aimOf = (target: EventTarget): Aim => {
    const slot = (target as Element).closest("[data-slot]")?.getAttribute("data-slot");
    if (slot === "a" || slot === "b") return slot;
    if (!comparing) return "analyze";
    return !compare.a ? "a" : "b";
  };
  // The whole page takes files: one goes to the open tab, two are compared.
  const drop = (e: React.DragEvent) => {
    e.preventDefault();
    setAim(null);
    setNotice(null);
    const files = [...e.dataTransfer.files];
    if (!files.length) return;
    if (files.length > 2) return setNotice("Drop one file to analyze it, or two to compare them.");
    if (files.length === 2) return void compare.run(files[0], files[1]);
    const to = aimOf(e.target);
    if (to === "analyze") return onFile(files[0]);
    if (!running) (to === "a" ? compare.setA : compare.setB)(files[0]);
  };
  const linkedAddress = !link?.demo && typeof link?.sel === "number" ? link.sel : null;

  return (
    <div
      className="lp"
      onDragOver={(e) => { e.preventDefault(); setAim(aimOf(e.target)); }}
      onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node)) setAim(null); }}
      onDrop={drop}
    >
      <header className="lp-nav">
        <div className="brand sm"><Wordmark /></div>
        <nav aria-label="Main">
          {resume && (
            <button type="button" className="lp-resume" onClick={resume.go} title={resume.detail}>
              <span>Back to {resume.name}</span> <span aria-hidden>→</span>
            </button>
          )}
          {!desktop && <button type="button" className="lp-navlink" onClick={() => document.getElementById("lp-features")?.scrollIntoView({ behavior: "smooth" })}>Features</button>}
          {!desktop && <a className="lp-navlink" href="https://docs.binfera.io/">Docs</a>}
          {!desktop && <a className="lp-navlink" href={`${REPO}/releases`} target="_blank" rel="noreferrer">Download</a>}
          <a className="lp-navlink" href={REPO} target="_blank" rel="noreferrer">GitHub</a>
          <ThemeToggle />
        </nav>
      </header>

      <main>
        <section className="lp-hero">
          <div>
            <h1>See what a <span className="lp-o">binary</span> does.</h1>
            <p className="lp-lede">Decompiled C, capabilities and diffs for Windows, Linux and macOS executables, {desktop ? "right on this machine" : "right in your browser"}.</p>
            <ul className="lp-trust">
              <li>{desktop ? "Nothing uploaded" : "Results stay in this browser. Nothing uploaded."}</li>
              {desktop ? <><li>Runs natively</li><li>Your notes are kept</li></> : <><li>No install</li><li>No account</li></>}
            </ul>
          </div>

          <div>
            <div className="lp-work">
              <div className="lp-tabs" role="tablist" aria-label="What to do">
                <button type="button" role="tab" id="lp-tab-analyze" aria-controls="lp-analyze" aria-selected={!comparing} onClick={() => setComparing(false)}>Analyze a file</button>
                <button type="button" role="tab" id="lp-tab-compare" aria-controls="lp-compare" aria-selected={comparing} onClick={() => setComparing(true)}>Compare two files</button>
              </div>

              <div className="lp-panel" id="lp-analyze" role="tabpanel" aria-labelledby="lp-tab-analyze" hidden={comparing}>
                <label className={"lp-drop" + (aim === "analyze" ? " is-over" : "")}>
                  <input className="sr-only" type="file" onClick={desktop ? (e) => { e.preventDefault(); void pickNative(); } : undefined} onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = ""; }} />
                  <strong><span className="lp-mouse">Drop a file here</span><span className="lp-touch">Pick a file to analyze</span></strong>
                  <span className="lp-cta">{loading === "pick" ? "Opening…" : "Choose a file"}</span>
                  <span className="lp-fmt">PE · ELF · Mach-O · shellcode · zip · 7z</span>
                </label>
                {desktop && (
                  <p className="lp-folder">
                    <button type="button" onClick={pickFolder} disabled={loading !== null}>{loading === "folder" ? "Scanning…" : "Open a folder…"}</button>
                    {folder && <button type="button" onClick={onFolderBack}>Back to {folder.name}</button>}
                  </p>
                )}
              </div>

              <div className="lp-panel" id="lp-compare" role="tabpanel" aria-labelledby="lp-tab-compare" hidden={!comparing}>
                <div className="lp-slots">
                  <Slot side="a" label="Older or reference" file={compare.a} over={aim === "a"} disabled={running} onFile={compare.setA} />
                  <Slot side="b" label="To compare" file={compare.b} over={aim === "b"} disabled={running} onFile={compare.setB} />
                </div>
                {compare.stage ? (
                  <div className="lp-progress" role="status">
                    <span>{compare.stage.label}…</span>
                    <button type="button" onClick={compare.cancel}>Cancel</button>
                  </div>
                ) : (
                  <button type="button" className="lp-cta lp-go" disabled={!compare.a || !compare.b} onClick={() => compare.run(compare.a, compare.b)}>Compare</button>
                )}
              </div>
            </div>

            {(error || notice) && <p className="error lp-message" role="alert">{error ?? notice}</p>}
            {compare.error && <p className="error lp-message" role="alert">{compare.error}</p>}
            {error && onRaw && (
              <div className="lp-message">
                <p>Know this is raw code? Choose its architecture to bypass detection, then adjust the start offset if needed.</p>
                <button className="ghost" onClick={() => onRaw("sc32")}>Open as raw x86</button>{" "}
                <button className="ghost" onClick={() => onRaw("sc64")}>Open as raw x64</button>
              </div>
            )}
            {linkedAddress !== null && !error && <p className="fine lp-message">This link points to function 0x{linkedAddress.toString(16)}. Open the same file to return to it.</p>}
          </div>
        </section>

        <RecentFiles busy={loading !== null} onOpen={reopen} onLocate={(r) => pickNative(r.sha256)} onError={setNotice} />

        {comparing ? (
          <section className="lp-section" aria-labelledby="lp-example-title">
            <div className="lp-head">
              <h2 id="lp-example-title">No files? Try an <span className="lp-o">example</span>.</h2>
              <p>Two harmless builds of one small program.</p>
            </div>
            <div className="lp-cabinet lp-versus">
              <div className="lp-match">
                <div className="lp-fighter"><img src="/mark.png" alt="" /><code>demo-v1.exe</code></div>
                <div className="lp-vs">VS</div>
                <div className="lp-fighter"><img src="/mark.png" alt="" /><code>demo-v2.exe</code></div>
              </div>
              {/* Real engine output, copied here. Re-copy it if the compare example changes. */}
              <div className="lp-result">
                <div><b>80.4%</b> <span>similar</span></div>
                <p>3 new · 4 changed · 8 unchanged functions</p>
                <button type="button" className="lp-start" onClick={compare.example} disabled={running}>Open this comparison →</button>
              </div>
            </div>
          </section>
        ) : (
          <LandingSamples samples={samples} loading={loading} onSample={trySample} onHarmless={tryHarmless} />
        )}

        {!desktop && <LandingTour />}
      </main>

      <footer className="lp-foot">
        <div className="lp-foot-left">
          <div className="brand sm"><Wordmark /></div>
          <p>Built by <a href="https://github.com/Karib0u" target="_blank" rel="noreferrer">Karib0u</a>, a malware analyst of 10+ years. Decompiler: Ghidra's C++ core. Rules: capa.</p>
        </div>
        <div className="lp-foot-links">
          {!desktop && <a href="https://docs.binfera.io/getting-started/">Quickstart</a>}
          {!desktop && <a href="https://docs.binfera.io/faq/">FAQ</a>}
          <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
          <a href={`${REPO}/releases`} target="_blank" rel="noreferrer">Download</a>
        </div>
      </footer>
    </div>
  );
}
