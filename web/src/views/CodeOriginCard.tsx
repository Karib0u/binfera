import { useRef, useState } from "react";
import { getFamilyPackName } from "../engine/assets";
import {
  describeMatchKinds,
  formatSourceName,
  matchStrength,
  STRENGTH_LABEL,
  type FunctionOriginKind,
} from "../familyOrigin";
import type { Analysis, FamilyMatch, FamilyReport } from "../types";

const pct = (n: number, d: number) => (d > 0 ? (100 * n) / d : 0);
const fmtPct = (v: number) => (v > 0 && v < 1 ? "<1%" : `${Math.round(v)}%`);
const num = (n: number) => n.toLocaleString("en-US");
const plural = (n: number, one: string, many = one + "s") => `${num(n)} ${n === 1 ? one : many}`;

export function CodeOriginCard({
  a,
  onFilterOrigin,
  onOpenFunction,
}: {
  a: Analysis;
  onFilterOrigin: (kind: FunctionOriginKind) => void;
  onOpenFunction: (address: number) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [loadingPack, setLoadingPack] = useState(false);
  const [packErr, setPackErr] = useState<string | null>(null);

  if (a.shellcode) return null;

  const report = a.family;

  const onPickPack = async (file: File) => {
    if (!a.runFamilyPack) return;
    setLoadingPack(true);
    setPackErr(null);
    try {
      await a.runFamilyPack(file);
    } catch (e) {
      setPackErr(String((e as Error)?.message ?? e));
    } finally {
      setLoadingPack(false);
    }
  };

  const packInput = a.runFamilyPack && (
    <input
      ref={inputRef}
      className="sr-only"
      type="file"
      accept=".bxfam"
      onChange={(e) => {
        const f = e.target.files?.[0];
        if (f) void onPickPack(f);
        e.target.value = "";
      }}
    />
  );
  const pickPack = (label: string) =>
    a.runFamilyPack && (
      <button
        type="button"
        className="co-link"
        disabled={loadingPack}
        onClick={() => inputRef.current?.click()}
        title="Match against a local .bxfam fingerprint pack. It stays in this browser and is never uploaded."
      >
        {loadingPack ? "Matching…" : label}
      </button>
    );

  // Stay invisible until analysis has a report, or finishes with an option to load a custom pack.
  if (!report) {
    if (!a.done && !a.familyError) return null;
    if (!a.runFamilyPack && !a.familyError) return null;
    return (
      <section className="ov-card co-card co-empty" aria-label="Code origin">
        <header>
          <h2>Code origin</h2>
          <div className="co-head-meta">
            <span>{a.familyError || packErr || "No fingerprint pack loaded"}</span>
            {packInput}
            {pickPack("Load a .bxfam pack…")}
          </div>
        </header>
      </section>
    );
  }

  const elig = report.eligible_functions;
  const tooSmall = Math.max(0, report.total_functions - elig);
  const segments: { kind: FunctionOriginKind; label: string; count: number; hint: string }[] = [
    { kind: "malware", label: "Family code", count: report.family_matched_functions, hint: "Functions attributed to a malware family in the pack" },
    { kind: "shared", label: "Common malware code", count: report.shared_malware_functions, hint: "Seen across many unrelated malware families: says nothing about which family this is" },
    { kind: "unique", label: "Unique", count: report.unique_functions, hint: "Not found anywhere in the pack: the code to reverse first" },
    { kind: "trusted", label: "Known libraries", count: report.trusted_functions, hint: report.trusted_sources.length ? `Known library code: ${report.trusted_sources.map((t) => formatSourceName(t.source)).join(", ")}` : "Compiler runtimes, FLIRT signatures and known benign software" },
  ];
  const [top, ...others] = report.families;

  return (
    <section className="ov-card co-card" aria-label="Code origin">
      <header>
        <h2>Code origin</h2>
      </header>

      {(a.familyError || packErr) && <p className="co-error">{a.familyError ?? packErr}</p>}

      {elig === 0 ? (
        <p className="fine">No function is large enough to fingerprint (20+ instructions, 2+ blocks).</p>
      ) : (
        <>
          <Verdict report={report} top={top} onOpenFunction={onOpenFunction} onFilterOrigin={onFilterOrigin} />

          <div className="co-bar" role="img" aria-label={segments.filter((s) => s.count > 0).map((s) => `${s.label} ${fmtPct(pct(s.count, elig))}`).join(", ")}>
            {segments.map((s) =>
              s.count > 0 ? (
                <i key={s.kind} className={"co-seg co-" + s.kind} style={{ flexGrow: s.count }} title={`${s.label}: ${fmtPct(pct(s.count, elig))} (${plural(s.count, "function")})`} />
              ) : null,
            )}
          </div>

          <div className="co-legend" role="group" aria-label="Show functions by code origin">
            {segments.map((s) => (
              <button key={s.kind} type="button" className={"co-bucket"} disabled={s.count === 0} title={s.hint} onClick={() => onFilterOrigin(s.kind)}>
                <i className={"co-swatch co-" + s.kind} aria-hidden />
                <span>{s.label}</span>
                <b>{fmtPct(pct(s.count, elig))}</b>
                <small>{num(s.count)}</small>
              </button>
            ))}
          </div>

          {(others.length > 0 || report.trusted_sources.length > 0) && (
            <dl className="co-more">
              {others.length > 0 && (
                <>
                  <dt>Also resembles</dt>
                  <dd>
                    {others.slice(0, 4).map((fam) => (
                      <button key={fam.family} type="button" className="co-chip" onClick={() => (fam.functions[0] ? onOpenFunction(fam.functions[0].address) : onFilterOrigin("malware"))} title={`${STRENGTH_LABEL[matchStrength(fam)]}: ${plural(fam.exclusive_functions, "function")} found only in this family`}>
                        <code>{fam.family}</code> <em>{STRENGTH_LABEL[matchStrength(fam)].split(" ")[0].toLowerCase()}</em>
                      </button>
                    ))}
                  </dd>
                </>
              )}
              {report.trusted_sources.length > 0 && (
                <>
                  <dt>Libraries</dt>
                  <dd>
                    {report.trusted_sources.slice(0, 6).map((src) => (
                      <button key={src.source} type="button" className="co-chip co-chip-trusted" onClick={() => (src.addresses[0] !== undefined ? onOpenFunction(src.addresses[0]) : onFilterOrigin("trusted"))} title={`${plural(src.functions, "function")} of ${num(elig)} fingerprinted (${num(src.instructions)} instructions)`}>
                        {formatSourceName(src.source)} <em>{fmtPct(pct(src.functions, elig))}</em>
                      </button>
                    ))}
                  </dd>
                </>
              )}
            </dl>
          )}
        </>
      )}

      <footer className="co-foot">
        {packInput}
        <span title={tooSmall > 0 ? `${plural(tooSmall, "function")} are under 20 instructions or 2 blocks: too small to fingerprint reliably` : undefined}>
          {num(elig)} of {num(report.total_functions)} functions fingerprinted
        </span>
        <span aria-hidden>·</span>
        <span>{getFamilyPackName() ?? "Starter pack"}</span>
        {a.runFamilyPack && <span aria-hidden>·</span>}
        {pickPack("Use another pack…")}
      </footer>
    </section>
  );
}

/** One sentence that answers "what is this?" and one that answers "where do I look?". */
function Verdict({
  report,
  top,
  onOpenFunction,
  onFilterOrigin,
}: {
  report: FamilyReport;
  top: FamilyMatch | undefined;
  onOpenFunction: (address: number) => void;
  onFilterOrigin: (kind: FunctionOriginKind) => void;
}) {
  const elig = report.eligible_functions;
  const unique = report.unique_functions;
  const next =
    unique > 0 ? (
      <button type="button" className="co-next" onClick={() => onFilterOrigin("unique")}>
        <i className="co-swatch co-unique" aria-hidden />
        <span>
          <b>{plural(unique, "unique function")}</b> {unique === 1 ? "isn't" : "aren't"} in any pack: start reversing there
        </span>
        <span className="co-go" aria-hidden>→</span>
      </button>
    ) : (
      <p className="co-next co-next-quiet">No unique code: every fingerprinted function is already known.</p>
    );

  if (!top) {
    const trustedShare = pct(report.trusted_functions, elig);
    return (
      <div className="co-verdict co-verdict-none">
        <p className="co-headline">
          No known malware family
          {trustedShare >= 50 && <span className="co-sub"> · {fmtPct(trustedShare)} is known library code</span>}
        </p>
        {next}
      </div>
    );
  }

  const strength = matchStrength(top);
  const topFn = top.functions[0];
  const kinds = describeMatchKinds(top);
  return (
    <div className={"co-verdict co-verdict-" + strength}>
      <div className="co-headline">
        <span className="co-pill">{STRENGTH_LABEL[strength]}</span>
        <button type="button" className="co-family" onClick={() => (topFn ? onOpenFunction(topFn.address) : onFilterOrigin("malware"))} title={topFn ? `Open the largest matched function (0x${topFn.address.toString(16)})` : "Show matched functions"}>
          <code>{top.family}</code>
        </button>
      </div>
      <p className="co-evidence">
        <b>{plural(top.exclusive_functions, "function")}</b> found only in this family's samples, covering{" "}
        <b title="Distinctive code: fingerprinted functions that are neither known libraries nor common malware code">{fmtPct(top.coverage * 100)}</b> of the file's distinctive code
        {kinds && <span className="co-kinds" title="Identical: same normalised instructions. Same control flow: same basic-block graph shape. Similar: fuzzy (MinHash) match."> · matched as {kinds}</span>}
      </p>
      {next}
    </div>
  );
}
