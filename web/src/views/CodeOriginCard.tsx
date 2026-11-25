import { useRef, useState } from "react";
import { getFamilyPackName } from "../engine/assets";
import {
  describeMatchKinds,
  formatSourceName,
  matchStrength,
  STRENGTH_LABEL,
  type FunctionOriginKind,
} from "../familyOrigin";
import type { Analysis, FamilyMatch, FamilyPackInfo, FamilyReport, StringOriginKind, StringOriginReport } from "../types";

const pct = (n: number, d: number) => (d > 0 ? (100 * n) / d : 0);
const fmtPct = (v: number) => (v > 0 && v < 1 ? "<1%" : `${Math.round(v)}%`);
const num = (n: number) => n.toLocaleString("en-US");
const plural = (n: number, one: string, many = one + "s") => `${num(n)} ${n === 1 ? one : many}`;

export function CodeOriginCard({
  a,
  onFilterOrigin,
  onOpenFunction,
  onShowStrings,
}: {
  a: Analysis;
  onFilterOrigin: (kind: FunctionOriginKind) => void;
  onOpenFunction: (address: number) => void;
  /** Open the Strings view filtered to one String Reuse class, optionally searching for a value. */
  onShowStrings?: (kind: StringOriginKind | null, query?: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const overlayRef = useRef<HTMLInputElement>(null);
  const [loadingPack, setLoadingPack] = useState(false);
  const [packErr, setPackErr] = useState<string | null>(null);

  if (a.shellcode) return null;

  const report = a.family;

  const canPickPack = a.pickFamilyPack || a.runFamilyPack;
  const onPickPack = async (run: () => Promise<void>) => {
    setLoadingPack(true);
    setPackErr(null);
    try {
      await run();
    } catch (e) {
      setPackErr(String((e as Error)?.message ?? e));
    } finally {
      setLoadingPack(false);
    }
  };

  const runFamilyPack = a.runFamilyPack;
  const packInput = runFamilyPack && (
    <input
      ref={inputRef}
      className="sr-only"
      type="file"
      accept=".bxfam"
      onChange={(e) => {
        const f = e.target.files?.[0];
        if (f) void onPickPack(() => runFamilyPack(f));
        e.target.value = "";
      }}
    />
  );
  const addOverlay = a.addFamilyOverlay;
  const overlayInput = addOverlay && !a.pickFamilyPack && (
    <input
      ref={overlayRef}
      className="sr-only"
      type="file"
      accept=".bxfam"
      onChange={(e) => {
        const f = e.target.files?.[0];
        if (f) void onPickPack(() => addOverlay(f));
        e.target.value = "";
      }}
    />
  );
  const removeOverlay = a.removeFamilyOverlay;
  const pickPack = (label: string) =>
    canPickPack && (
      <button
        type="button"
        className="co-link"
        disabled={loadingPack}
        onClick={() => a.pickFamilyPack ? void onPickPack(a.pickFamilyPack) : inputRef.current?.click()}
        title={a.pickFamilyPack
          ? "Match against a local .bxfam fingerprint pack"
          : "Match against a local .bxfam fingerprint pack. It stays in this browser and is never uploaded."}
      >
        {loadingPack ? "Matching…" : label}
      </button>
    );

  // Stay invisible until analysis has a report, or finishes with an option to load a custom pack.
  if (!report) {
    if (!a.done && !a.familyError) return null;
    if (!canPickPack && !a.familyError) return null;
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
  // The inventory the header counts; the engine lists functions the way the decompiler does.
  const total = a.order.length || report.total_functions;
  const tooSmall = Math.max(0, total - elig);
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

      {elig > 0 && report.strings && report.strings.total_strings > 0 && (
        <StringReuse strings={report.strings} codeAbstained={report.families.length === 0} onShowStrings={onShowStrings} />
      )}

      <footer className="co-foot">
        {packInput}
        {overlayInput}
        <span title={tooSmall > 0 ? `${plural(tooSmall, "function")} are under 20 instructions or 2 blocks: too small to fingerprint reliably` : undefined}>
          {num(elig)} of {num(total)} functions fingerprinted
        </span>
        <span aria-hidden>·</span>
        <PackChips
          packs={a.familyPacks ?? [{ name: a.familyPackName ?? getFamilyPackName() ?? "Starter pack", role: "base" }]}
          busy={loadingPack}
          onRemove={removeOverlay && ((i) => void onPickPack(() => removeOverlay(i)))}
        />
        {addOverlay && (
          <button
            type="button"
            className="co-link"
            disabled={loadingPack}
            onClick={() => (a.pickFamilyPack ? void onPickPack(() => addOverlay()) : overlayRef.current?.click())}
            title="Layer another .bxfam pack over these, such as your organization's Trusted code. A function or string any pack trusts is Trusted."
          >
            {loadingPack ? "Matching…" : "Add overlay pack…"}
          </button>
        )}
        {canPickPack && <span aria-hidden>·</span>}
        {pickPack("Use another base pack…")}
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

const fmtSize = (n: number) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`);

/** The active packs, base first, each removable when it is an overlay. */
function PackChips({ packs, busy, onRemove }: { packs: FamilyPackInfo[]; busy: boolean; onRemove?: (overlayIndex: number) => void }) {
  let overlay = -1;
  return (
    <span className="co-packs" role="list" aria-label="Fingerprint packs, base first">
      {packs.map((p, i) => {
        const index = p.role === "overlay" ? ++overlay : -1;
        const meta = [p.format, p.size !== undefined ? fmtSize(p.size) : undefined].filter(Boolean).join(" · ");
        return (
          <span key={i} role="listitem" className={"co-pack" + (p.role === "overlay" ? " co-pack-overlay" : "")} title={`${p.role === "base" ? "Base pack" : `Overlay ${index + 1}: later packs take precedence for Trusted names`}${meta ? ` · ${meta}` : ""}`}>
            {p.role === "overlay" && <span aria-hidden>+</span>}
            <b>{p.name}</b>
            {meta && <small>{meta}</small>}
            {p.role === "overlay" && onRemove && (
              <button type="button" className="co-pack-x" disabled={busy} aria-label={`Remove overlay ${p.name}`} title="Remove this overlay and match again" onClick={() => onRemove(index)}>×</button>
            )}
          </span>
        );
      })}
    </span>
  );
}

const STRING_SEGMENTS: { kind: StringOriginKind; label: string; key: keyof Pick<StringOriginReport, "malware_strings" | "shared_strings" | "unique_strings" | "trusted_strings"> }[] = [
  { kind: "malware", label: "Family", key: "malware_strings" },
  { kind: "shared", label: "Shared", key: "shared_strings" },
  { kind: "unique", label: "Unique", key: "unique_strings" },
  { kind: "trusted", label: "Trusted", key: "trusted_strings" },
];

/**
 * String Reuse: supporting evidence beside the code verdict, never part of it. Exclusive strings
 * open the Strings view; a string-only hint is shown only when code attribution abstained.
 */
function StringReuse({ strings, codeAbstained, onShowStrings }: { strings: StringOriginReport; codeAbstained: boolean; onShowStrings?: (kind: StringOriginKind | null, query?: string) => void }) {
  const total = strings.total_strings;
  const exclusive = strings.entries.filter((e) => e.kind === "malware").slice(0, 5);
  const hint = codeAbstained ? strings.string_only_hint : undefined;
  return (
    <section className="co-strings" aria-label="String reuse">
      <div className="co-strings-head">
        <h3>String reuse</h3>
        <span className="co-sub" title="Strings are classified after the code verdict and never change it">
          {plural(total, "string")} · supporting evidence only
        </span>
      </div>
      <div className="co-bar co-bar-thin" role="img" aria-label={STRING_SEGMENTS.filter((s) => strings[s.key] > 0).map((s) => `${s.label} ${fmtPct(pct(strings[s.key], total))}`).join(", ")}>
        {STRING_SEGMENTS.map((s) => strings[s.key] > 0 ? <i key={s.kind} className={"co-seg co-" + s.kind} style={{ flexGrow: strings[s.key] }} /> : null)}
      </div>
      <div className="co-legend" role="group" aria-label="Show strings by origin">
        {STRING_SEGMENTS.map((s) => (
          <button key={s.kind} type="button" className="co-bucket" disabled={strings[s.key] === 0 || !onShowStrings} onClick={() => onShowStrings?.(s.kind)}
            title={s.kind === "trusted" ? "Common in benign software: hide these to read what the malware wrote" : s.kind === "unique" ? "Not in any loaded pack" : s.kind === "shared" ? "Seen in two or three malware families" : "Seen in one malware family's samples only"}>
            <i className={"co-swatch co-" + s.kind} aria-hidden />
            <span>{s.label}</span>
            <b>{fmtPct(pct(strings[s.key], total))}</b>
            <small>{num(strings[s.key])}</small>
          </button>
        ))}
      </div>
      {hint && (
        <p className="co-hint" role="note">
          <span className="co-hint-tag">Low-confidence string-only hint</span>
          {" "}<code>{hint.family}</code>: {plural(hint.exclusive_strings, "exclusive string")} agree. Code attribution abstained, so this is a lead to verify, not a match.
        </p>
      )}
      {(strings.families.length > 0 || exclusive.length > 0) && (
        <dl className="co-more">
          {strings.families.length > 0 && (
            <>
              <dt>Families</dt>
              <dd>
                {strings.families.slice(0, 4).map((f) => (
                  <button key={f.family} type="button" className="co-chip" disabled={!onShowStrings} onClick={() => onShowStrings?.("malware", f.family)}
                    title={`${plural(f.exclusive_strings, "string")} found only in ${f.family}, ${plural(f.shared_strings, "string")} shared with other families${f.corroborates_code ? ". Code attribution names it too." : ""}`}>
                    <code>{f.family}</code> <em>{num(f.exclusive_strings)}</em>{f.corroborates_code && <span className="co-corr" aria-label="corroborates code">✓ code</span>}
                  </button>
                ))}
              </dd>
            </>
          )}
          {exclusive.length > 0 && (
            <>
              <dt>Exclusive</dt>
              <dd className="co-str-list">
                {exclusive.map((e) => (
                  <button key={e.hash} type="button" className="co-str" disabled={!onShowStrings} onClick={() => onShowStrings?.(null, e.value)} title={`${e.value}\nOnly in ${e.families?.join(", ") || "one family"}: show it in Strings`}>
                    <span>{e.value}</span><em>{e.families?.[0]}</em>
                  </button>
                ))}
              </dd>
            </>
          )}
        </dl>
      )}
    </section>
  );
}
