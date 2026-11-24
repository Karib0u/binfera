import { useEffect, useRef, useState } from "react";
import ArchiveView from "./ArchiveView";
import { useCompare } from "./views/CompareView";
import CompareWorkspace from "./views/CompareWorkspace";
import FolderView from "./FolderView";
import Landing from "./Landing";
import { archiveKind } from "./archive";
import { analyze } from "./analyze";
import { NATIVE } from "./engine/assets";
import { listDemos, loadDemo, type DemoSample } from "./demos";
import type { Analysis } from "./types";
import type { Folder } from "./project/types";
import { bytes } from "./workspace/labels";
import { lastEntry, locOf, pageUrl, parseHash, writeEntry, type Entry, type Target } from "./workspace/location";
import { installOpenerImport } from "./openerImport";
import Workspace from "./workspace/Workspace";
import type { RawCodeOptions } from "./engine/engine.worker";

/** The engine's message for a file it cannot read, in terms of the file the user chose. */
const failure = (name: string, message: string) =>
  /unsupported input format/i.test(message)
    ? `${name} isn't a supported executable and couldn't be recognized as x86/x64 shellcode.`
    : message.replace(/^error: /, "");

export default function App() {
  const [a, setA] = useState<Analysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const currentFile = useRef<File | null>(null);
  const currentRaw = useRef<RawCodeOptions | undefined>(undefined);
  const [archive, setArchive] = useState<File | null>(null);
  // Desktop: the opened folder, and whether its tree is what the window shows.
  const [folder, setFolder] = useState<Folder | null>(null);
  const [tree, setTree] = useState(false);
  const compare = useCompare();
  // The landing page can sit over a running analysis: New and browser Back keep it to return to.
  const [landing, setLanding] = useState(false);
  const [run, setRun] = useState(0);
  const runRef = useRef(0);
  // The place the URL named when the page loaded; used by the first file opened.
  const linked = useRef<Target>(parseHash());
  const [note, setNote] = useState<Target>(linked.current);
  const [initial, setInitial] = useState<{ at: number | null; layout?: string; sel: Entry["sel"] }>({ at: null, sel: "capa" });

  const start = async (file: File, demo?: DemoSample, replace = false, raw?: RawCodeOptions, again = false) => {
    abort.current?.abort();
    currentFile.current = file;
    currentRaw.current = raw;
    setTree(false);
    compare.cancel();
    setNote({});
    if (!raw && await archiveKind(file)) {
      setError(null);
      setA(null);
      setLanding(false);
      setArchive(file);
      return;
    }
    setArchive(null);
    const ctl = (abort.current = new AbortController());
    const t = linked.current;
    linked.current = {};
    const place = t.sel !== undefined && t.demo === demo?.id ? t : null;
    const id = Date.now(), sel = place?.sel ?? "capa", at = place?.at ?? null;
    runRef.current = id;
    setRun(id);
    setInitial({ at, layout: place?.layout, sel });
    if (!replace && !history.state?.binfera) history.replaceState(null, "", pageUrl());
    writeEntry(replace ? "replace" : "push", { binfera: true, run: id, i: 0, ...locOf(sel), at }, pageUrl());
    setError(null);
    setLanding(false);
    setA({ fileName: file.name, demo, size: file.size, order: [], strings: [], stringsTotal: 0, image: null, entry: null, arch: null, packed: null, functions: new Map(), names: new Map(), settled: false, capa: null, capaError: null, decompileError: null, tooLarge: null, capaTooLarge: null, loading: { label: "Preparing…", fraction: null }, done: false });
    // analyze() batches its updates on a timer, so one can still fire after a failure; it must not bring the workspace back.
    let failed = false;
    analyze(file, (next) => { if (!failed) setA({ ...next, demo }); }, ctl.signal, raw, again).catch((e) => {
      if (ctl.signal.aborted) return;
      failed = true;
      setA(null);
      history.replaceState(null, "", pageUrl());
      setError(failure(file.name, String(e.message ?? e)));
    });
  };

  // Desktop: a folder dropped on the window opens as a tree (see installNativeDrop).
  useEffect(() => {
    const onFolder = (e: Event) => { setFolder((e as CustomEvent<Folder>).detail); setTree(true); };
    window.addEventListener("binfera-folder", onFolder);
    return () => window.removeEventListener("binfera-folder", onFolder);
  }, []);

  const startRef = useRef(start);
  startRef.current = start;
  // External tools (e.g. FileBus) open `#import` and transfer raw bytes directly over postMessage.
  useEffect(() => installOpenerImport({
    win: window,
    onFile: (file) => { void startRef.current(file, undefined, true); },
    onClearHash: () => { history.replaceState(null, "", pageUrl()); },
  }), []);

  // Links also work when a tab is already showing the landing page.
  useEffect(() => {
    if (a && !landing) return;
    let cancelled = false;
    let request = 0;
    const openLinkedDemo = async () => {
      const target = parseHash();
      const id = ++request;
      linked.current = target;
      setNote(target);
      if (!target.demo) return;
      try {
        const sample = (await listDemos()).find((s) => s.id === target.demo);
        if (cancelled || id !== request) return;
        if (!sample) { linked.current = {}; setNote({}); return; }
        const file = await loadDemo(sample);
        if (!cancelled && id === request) await start(file, sample, true);
      } catch (e) { if (!cancelled && id === request) setError(String((e as Error).message ?? e)); }
    };
    void openLinkedDemo();
    window.addEventListener("hashchange", openLinkedDemo);
    return () => { cancelled = true; window.removeEventListener("hashchange", openLinkedDemo); };
  }, [!a || landing]);

  useEffect(() => {
    const onPop = () => {
      const st = history.state as Entry | null;
      setLanding(!(st?.binfera && st.run === runRef.current) && !(!st && parseHash().sel !== undefined));
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const showNew = () => { setLanding(true); history.pushState(null, "", pageUrl()); };
  const resume = () => { if (lastEntry) writeEntry("push", lastEntry.state, lastEntry.url); setLanding(false); };

  if (compare.result) return <CompareWorkspace key={compare.result.document.inputs[0].sha256 + compare.result.document.inputs[1].sha256} c={compare.result} onReset={compare.reset} />;
  if (!a && archive) return <ArchiveView file={archive} onOpen={(f) => start(f)} onNext={(f) => start(f)} onBack={() => { setArchive(null); if (folder) setTree(true); }} />;
  return (
    <>
      {tree && folder && <FolderView folder={folder} onFolder={setFolder} onFile={(f) => start(f)} onBack={() => setTree(false)} />}
      {a && <div style={{ display: landing || tree ? "none" : "contents" }}><Workspace key={run} a={a} run={run} active={!landing} initial={initial} onNew={showNew} onFile={(f) => start(f)}
        onCompare={() => { compare.setA(currentFile.current); compare.setB(null); showNew(); }}
        onAnalyzeAgain={NATIVE ? undefined : () => { if (currentFile.current) start(currentFile.current, a.demo, true, currentRaw.current, true); }}
        onShellcodeChange={raw => { if (currentFile.current) start(currentFile.current, a.demo, true, raw); }} /></div>}
      {(!a || landing) && !tree && (
        <Landing folder={folder} onFolder={(f) => { setFolder(f); setTree(true); }} onFolderBack={() => setTree(true)} onFile={(f, demo, place) => { if (place) linked.current = place; start(f, demo); }} error={error} link={note} compare={compare}
          onRaw={error && currentFile.current ? format => { if (currentFile.current) start(currentFile.current, undefined, true, { format, os: "windows" }); } : undefined}
          resume={a && { name: a.demo?.name ?? a.fileName, detail: `${bytes(a.size)} · ${a.done ? `${a.order.length} functions` : "still analyzing"}`, go: resume }} />
      )}
    </>
  );
}
