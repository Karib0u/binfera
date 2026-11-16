import { useEffect, useRef, useState } from "react";
import { compareFiles, type Comparison, type Stage } from "../compare";

/** The two files chosen and their comparison. It outlives the results, so going back finds the files still chosen. */
export function useCompare() {
  const [a, setA] = useState<File | null>(null);
  const [b, setB] = useState<File | null>(null);
  const [stage, setStage] = useState<Stage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Comparison | null>(null);
  // Browser Back from a result returns to the choice of files; Forward comes back to the result.
  const [showResult, setShowResult] = useState(true);
  useEffect(() => {
    const onPop = () => setShowResult(history.state?.binferaCompare === true);
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);
  const abort = useRef<AbortController | null>(null);
  const begin = (label: string) => {
    abort.current?.abort();
    const ctl = (abort.current = new AbortController());
    setError(null);
    setStage({ label, fraction: null });
    return ctl;
  };
  const run = async (left: File | null, right: File | null) => {
    if (!left || !right) return;
    setA(left);
    setB(right);
    const ctl = begin("Starting");
    try {
      const done = await compareFiles(left, right, (s) => { if (!ctl.signal.aborted) setStage(s); }, ctl.signal);
      if (!ctl.signal.aborted) { setResult(done); setShowResult(true); }
    } catch (e) {
      if (!ctl.signal.aborted) setError(String((e as Error).message ?? e).replace(/^error: /, ""));
    } finally {
      if (!ctl.signal.aborted) setStage(null);
    }
  };
  // Two harmless builds of one small program, the second with a few changes (see demo/).
  const example = async () => {
    const ctl = begin("Loading the example");
    try {
      const [left, right] = await Promise.all(["demo-v1.exe", "demo-v2.exe"].map(async (name) => {
        const res = await fetch(`${import.meta.env.BASE_URL}${name}`, { signal: ctl.signal });
        if (!res.ok) throw new Error(`example unavailable (${res.status})`);
        return new File([await res.blob()], name);
      }));
      await run(left, right);
    } catch (e) {
      if (!ctl.signal.aborted) {
        setError(String((e as Error).message ?? e));
        setStage(null);
      }
    }
  };
  const cancel = () => { abort.current?.abort(); setStage(null); };
  return { a, b, setA, setB, stage, error, result: showResult ? result : null, run, example, cancel, reset: () => { setResult(null); history.pushState(null, "", location.pathname + location.search); } };
}

export type CompareState = ReturnType<typeof useCompare>;
