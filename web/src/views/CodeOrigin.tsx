import { useRef, useState } from "react";
import { getFamilyPackName } from "../engine/assets";
import {
  describeMatchKinds,
  matchStrength,
  STRENGTH_LABEL,
  type FunctionOrigin,
  type FunctionOriginKind,
} from "../familyOrigin";
import Sheet from "../Sheet";
import { Modal } from "../dialog";
import type { Analysis, FamilyPackInfo } from "../types";

const num = (n: number) => n.toLocaleString("en-US");
const plural = (n: number, one: string, many = one + "s") => `${num(n)} ${n === 1 ? one : many}`;
const fmtSize = (n: number) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`);

/** The packs the last match used, base first; a named default when the engine did not list them. */
export function activePacks(a: Analysis): FamilyPackInfo[] {
  return a.familyPacks ?? [{ name: a.familyPackName ?? getFamilyPackName() ?? "Starter pack", role: "base" }];
}

/** Whether this analysis can change its fingerprint packs at all. */
export const canManagePacks = (a: Analysis) => !!(a.pickFamilyPack || a.runFamilyPack || a.addFamilyOverlay);

/**
 * Shown in the file header only when a malware family matched: the one Code origin result that
 * deserves the top of the page. One tappable row, like the header's other summaries; it opens the
 * family's functions. Everything else about code origin is a row in First look.
 */
export function OriginBanner({ a, onFilterOrigin }: {
  a: Analysis;
  onFilterOrigin: (kind: FunctionOriginKind) => void;
}) {
  const report = a.family;
  const top = report?.families[0];
  if (a.shellcode || !report || !top || report.eligible_functions === 0) return null;
  const strength = matchStrength(top);
  const kinds = describeMatchKinds(top);
  const strings = report.strings?.families.find((f) => f.family === top.family)?.exclusive_strings ?? 0;
  const others = report.families.slice(1, 4).map((f) => f.family);
  const unique = report.unique_functions;
  const detail = [
    `${STRENGTH_LABEL[strength]}: ${top.family}`,
    `Covers ${Math.round(top.coverage * 100)}% of the file's distinctive code`,
    kinds && `Matched as ${kinds}`,
    others.length > 0 && `Also resembles ${others.join(", ")}`,
    "Open the family's functions",
  ].filter(Boolean).join("\n");
  return (
    <button type="button" className={"origin-banner ob-" + strength} onClick={() => onFilterOrigin("malware")} title={detail} aria-label={`${STRENGTH_LABEL[strength]}: ${top.family}. Show the family's functions`}>
      <i className="ob-dot" aria-hidden />
      <span className="ob-text">
        <span className="ob-title"><code>{top.family}</code><em>{STRENGTH_LABEL[strength]}</em></span>
        <span className="ob-sub">
          {plural(top.exclusive_functions, "function")} only in this family
          {strings > 0 && ` · ${plural(strings, "string")} agree`}
          {unique > 0 && ` · ${num(unique)} unique`}
        </span>
      </span>
      <span className="ob-chev" aria-hidden><span className="ob-cta">Show family code</span>›</span>
    </button>
  );
}

/** One badge for a function's origin, the same in the header, the phone's chips and anywhere else. */
export function OriginBadge({ origin }: { origin?: FunctionOrigin }) {
  if (!origin || origin.kind === "unique") return null;
  const text = origin.kind === "malware" ? origin.label : origin.kind === "trusted" ? (origin.label && origin.label !== "Library" ? `Library · ${origin.label}` : "Library") : "Common malware";
  return <span className={"cap co-badge co-badge-" + origin.kind} title={origin.detail}>{text}</span>;
}

/** The pack names for the status bar: the base, plus how many overlays sit on it. */
export function packsLabel(a: Analysis): string {
  const packs = activePacks(a);
  const overlays = packs.filter((p) => p.role === "overlay").length;
  return (packs.find((p) => p.role === "base")?.name ?? packs[0]?.name ?? "No pack") + (overlays ? ` +${overlays}` : "");
}

/**
 * Fingerprint packs: which packs Code origin compares against, and the controls to change them.
 * A setting, so it lives behind the status bar and the menu instead of on every analysis.
 */
export function PacksDialog({ a, mobile, onClose }: { a: Analysis; mobile: boolean; onClose: () => void }) {
  const baseRef = useRef<HTMLInputElement>(null);
  const overlayRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    try { await fn(); } catch (e) { setErr(String((e as Error)?.message ?? e)); } finally { setBusy(false); }
  };
  const report = a.family;
  const packs = report || a.familyPacks ? activePacks(a) : [];
  const total = a.order.length || report?.total_functions || 0;
  const checked = report?.eligible_functions ?? 0;
  const replaceBase = a.pickFamilyPack ?? (a.runFamilyPack ? () => baseRef.current?.click() : undefined);
  const addOverlay = a.addFamilyOverlay && (a.pickFamilyPack ? () => void run(() => a.addFamilyOverlay!()) : () => overlayRef.current?.click());
  const fileInput = (ref: React.RefObject<HTMLInputElement | null>, use?: (f: File) => Promise<void>) => use && (
    <input ref={ref} className="sr-only" type="file" accept=".bxfam" tabIndex={-1}
      onChange={(e) => { const f = e.target.files?.[0]; if (f) void run(() => use(f)); e.target.value = ""; }} />
  );
  let overlay = -1;
  const body = (
    <div className="packs">
      <p className="fine">Code origin compares this file's functions and strings with these packs. {a.pickFamilyPack ? "They are read from this computer." : "They stay in this browser and are never uploaded."}</p>
      {(a.familyError || err) && <p className="packs-err" role="alert">{err ?? a.familyError}</p>}
      {packs.length > 0 ? (
        <ul className="packs-list" aria-label="Fingerprint packs, base first">
          {packs.map((p, i) => {
            const index = p.role === "overlay" ? ++overlay : -1;
            const meta = [p.format, p.size !== undefined ? fmtSize(p.size) : undefined].filter(Boolean).join(" · ");
            return (
              <li key={i}>
                <span className="packs-role">{p.role === "base" ? "Base" : `Overlay ${index + 1}`}</span>
                <b>{p.name}</b>
                {meta && <small>{meta}</small>}
                {p.role === "overlay" && a.removeFamilyOverlay && (
                  <button type="button" className="ghost" disabled={busy} onClick={() => void run(() => a.removeFamilyOverlay!(index))} aria-label={`Remove overlay ${p.name}`}>Remove</button>
                )}
              </li>
            );
          })}
        </ul>
      ) : <p className="packs-none">No fingerprint pack is loaded.</p>}
      {report && total > 0 && (
        <p className="fine">
          {num(checked)} of {plural(total, "function")} checked
          {total > checked ? `; ${num(total - checked)} are too small to fingerprint (under 20 instructions or 2 blocks)` : ""}.
          {packs.length > 1 && " A function or string any pack calls library code counts as library code."}
        </p>
      )}
      <div className="packs-actions">
        {fileInput(baseRef, a.runFamilyPack)}
        {!a.pickFamilyPack && fileInput(overlayRef, a.addFamilyOverlay)}
        {addOverlay && packs.length > 0 && <button type="button" disabled={busy} onClick={addOverlay} title="Layer another .bxfam pack over these, such as your organization's library code">Add overlay pack…</button>}
        {replaceBase && <button type="button" disabled={busy} onClick={() => (a.pickFamilyPack ? void run(a.pickFamilyPack) : replaceBase())}>{packs.length ? "Replace base pack…" : "Load a .bxfam pack…"}</button>}
        {busy && <span className="fine" role="status">Matching…</span>}
      </div>
    </div>
  );
  if (mobile) return <Sheet title="Fingerprint packs" onClose={onClose}>{body}</Sheet>;
  return (
    <Modal className="keys packs-dialog" labelledBy="packs-title" onClose={onClose}>
      <div className="keys-head">
        <h2 id="packs-title">Fingerprint packs</h2>
        <button className="ghost" onClick={onClose}>Close</button>
      </div>
      {body}
    </Modal>
  );
}
