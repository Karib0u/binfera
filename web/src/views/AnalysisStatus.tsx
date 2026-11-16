import type { Analysis } from "../types";

/** Downloading happens first; capabilities and decompilation then run side by side, each with its own progress. */
export function ProgressCard({ a }: { a: Analysis }) {
  const downloading = !!a.loading;
  const total = a.order.length, done = a.functions.size;
  const decompiled = total ? done / total : null;
  const steps = [
    { name: "Download the analysis engine", note: downloading ? a.loading!.label : "First visit only, then cached by your browser", state: downloading ? "active" : "done", fraction: downloading ? a.loading!.fraction : 1 },
    { name: "Match capabilities", note: "capa rules run on your device", state: downloading ? "todo" : "active", fraction: null },
    { name: "Decompile functions", note: total ? `${done} of ${total}` : "Recovering functions from the file", state: downloading ? "todo" : "active", fraction: decompiled },
  ] as const;
  return (
    <div className="view progress-card">
      <h2>{downloading ? "Getting ready" : "Analyzing"}</h2>
      <p className="fine">Everything runs in your browser. Nothing is uploaded.</p>
      <ol className="steps">
        {steps.map((st, i) => (
          <li key={st.name} className={st.state}>
            <span className="num">{st.state === "done" ? "✓" : i + 1}</span>
            <span className="step-body">
              <b>{st.name}</b><small>{st.note}</small>
              {st.state === "active" && (
                <span className={"pbar" + (st.fraction === null ? " indeterminate" : "")} role="progressbar" aria-label={st.name} aria-valuemin={0} aria-valuemax={100} aria-valuenow={st.fraction === null ? undefined : Math.round(st.fraction * 100)}>
                  <i style={{ width: st.fraction === null ? undefined : `${Math.max(3, st.fraction * 100)}%` }} />
                </span>
              )}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

/** The engine's refusal of a file with more code than a browser worker's memory can hold. */
export function TooLarge({ message, whole }: { message: string; whole: boolean }) {
  const limit = /after (\d+) instructions/.exec(message)?.[1];
  return (
    <div className="notice error">
      This file has too much code {whole ? "to analyze" : "for capability analysis"} in the browser{limit ? `: code recovery stopped at ${Number(limit).toLocaleString("en-US")} instructions, the limit for its 4 GB of memory` : ""}.
      {whole ? "" : " The decompiled functions are still listed."} Run the binfera command-line tool on it instead; it has no limit by default.
    </div>
  );
}

export function PackedNotice({ a }: { a: Analysis }) {
  if (!a.packed) return a.fileWarnings?.length ? (
    <details className="warn"><summary>File analysis warnings</summary>
      <ul>{a.fileWarnings.map((warning, i) => <li key={i}>{warning}</li>)}</ul>
    </details>
  ) : null;
  const by = a.packed.packer ? `packed with ${a.packed.packer}` : "packed";
  return (
    <details className="warn packed">
      <summary>This file looks {by}: the code here is mostly the unpacker, not the program. Unpack it first to see what it does.</summary>
      <ul>{a.packed.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul>
      {!!a.fileWarnings?.length && <ul>{a.fileWarnings.map((warning, i) => <li key={i}>{warning}</li>)}</ul>}
    </details>
  );
}
