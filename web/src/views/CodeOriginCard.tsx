import { useRef, useState } from "react";
import { getFamilyPackName } from "../engine/assets";
import { formatSourceName, type FunctionOriginKind } from "../familyOrigin";
import type { Analysis } from "../types";

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
  const packName = getFamilyPackName();

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

  const packPicker = a.runFamilyPack && (
    <>
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
      <button
        type="button"
        className="co-pack-btn"
        disabled={loadingPack}
        onClick={() => inputRef.current?.click()}
        title="Load a local .bxfam fingerprint pack (stays in this browser, never uploaded)"
      >
        {loadingPack ? "Matching pack…" : packName ? `Pack: ${packName}` : report ? "Load pack…" : "Load .bxfam pack…"}
      </button>
    </>
  );

  // Stay invisible until analysis has a report or finishes with an option to load a custom pack.
  if (!report) {
    if (!a.done && !a.familyError) return null;
    if (!a.runFamilyPack && !a.familyError) return null;
    return (
      <section className="ov-card co-card co-empty" aria-label="Code origin">
        <header>
          <h2>Code origin</h2>
          <div className="co-head-meta">
            <span>{a.familyError || packErr || "No fingerprint pack loaded"}</span>
            {packPicker}
          </div>
        </header>
      </section>
    );
  }

  const { breakdown: b } = report;
  const segments: { kind: FunctionOriginKind; label: string; pct: number; count: number; hint: string }[] = [
    { kind: "malware", label: "Malware family", pct: b.malware_pct, count: report.family_matched_functions, hint: "Functions attributed to a known malware family" },
    { kind: "shared", label: "Shared malware", pct: b.shared_pct, count: report.shared_malware_functions, hint: "Boilerplate shared across multiple malware families" },
    { kind: "unique", label: "Unique", pct: b.unique_pct, count: report.unique_functions, hint: "Unseen code worth reversing first" },
    { kind: "trusted", label: "Trusted", pct: b.trusted_pct, count: report.trusted_functions, hint: "Known runtime, FLIRT, or benign software functions" },
  ];

  return (
    <section className="ov-card co-card" aria-label="Code origin">
      <header>
        <h2>Code origin</h2>
        <div className="co-head-meta">
          <span>
            {report.eligible_functions.toLocaleString("en-US")} of {report.total_functions.toLocaleString("en-US")} functions analyzed
          </span>
          {packPicker}
        </div>
      </header>

      {(a.familyError || packErr) && <p className="co-error">{a.familyError ?? packErr}</p>}

      {report.eligible_functions > 0 ? (
        <>
          <div className="co-bar" role="img" aria-label={segments.filter((s) => s.count > 0).map((s) => `${s.label} ${s.pct.toFixed(1)}%`).join(", ")}>
            {segments.map((s) =>
              s.count > 0 ? (
                <i
                  key={s.kind}
                  className={"co-seg-" + s.kind}
                  style={{ flexGrow: s.count }}
                  title={`${s.label}: ${s.pct.toFixed(1)}% (${s.count})`}
                />
              ) : null,
            )}
          </div>

          <div className="co-legend" role="group" aria-label="Filter functions by code origin">
            {segments.map((s) => (
              <button
                key={s.kind}
                type="button"
                className={"co-bucket co-b-" + s.kind}
                disabled={s.count === 0}
                title={s.hint}
                onClick={() => onFilterOrigin(s.kind)}
              >
                <i aria-hidden />
                <span>{s.label}</span>
                <b>{s.pct.toFixed(1)}%</b>
                <small>{s.count.toLocaleString("en-US")}</small>
              </button>
            ))}
          </div>
        </>
      ) : (
        <p className="fine">No functions met the minimum size threshold for pack matching.</p>
      )}

      <div className="co-details">
        {report.families.length > 0 ? (
          <ul className="co-families">
            {report.families.map((fam) => {
              const topFn = fam.functions[0];
              const hits = [
                fam.exact_content_hits > 0 && `${fam.exact_content_hits} content`,
                fam.exact_shape_hits > 0 && `${fam.exact_shape_hits} shape`,
                fam.fuzzy_hits > 0 && `${fam.fuzzy_hits} fuzzy`,
              ]
                .filter(Boolean)
                .join(" · ");
              return (
                <li key={fam.family}>
                  <button
                    type="button"
                    className="co-fam-row"
                    onClick={() => (topFn ? onOpenFunction(topFn.address) : onFilterOrigin("malware"))}
                    title={topFn ? `Open largest matched function (0x${topFn.address.toString(16)})` : "Show matched functions"}
                  >
                    <span className="co-fam-name">
                      <i className="co-dot co-malware" aria-hidden />
                      <code>{fam.family}</code>
                    </span>
                    <span className="co-fam-meta">
                      <b>{fam.exclusive_functions}</b> exclusive · <b>{Math.round(fam.coverage * 100)}%</b> coverage
                      {hits && <> · {hits}</>}
                    </span>
                    <em className="co-score" title="Weighted family match score">score {fam.score.toFixed(1)}</em>
                  </button>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="co-clean">
            <i className="co-dot co-trusted" aria-hidden />
            No known malware family matched above threshold.
          </p>
        )}

        {report.trusted_sources.length > 0 && (
          <div className="co-trusted-row">
            <span className="co-trusted-label">Trusted code</span>
            <div className="co-trusted-chips">
              {report.trusted_sources.slice(0, 6).map((src) => (
                <button
                  key={src.source}
                  type="button"
                  className="co-trusted-chip"
                  onClick={() => (src.addresses[0] !== undefined ? onOpenFunction(src.addresses[0]) : onFilterOrigin("trusted"))}
                  title={`${src.functions} functions (${src.instructions.toLocaleString("en-US")} instructions)`}
                >
                  {formatSourceName(src.source)} <em>{src.functions}</em>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
