import type { FamilyMatch, FamilyMatchKind, FamilyReport, StringMatch, StringOriginKind } from "./types";

export type FunctionOriginKind = "malware" | "shared" | "trusted" | "unique";

/**
 * The words the UI uses for each class, everywhere: lists, filters, badges, the file map. The engine
 * and CLI say "trusted"; the app says "library", which is what an analyst calls it.
 */
export const ORIGIN_NAME: Record<FunctionOriginKind, string> = {
  malware: "Family",
  shared: "Common malware",
  unique: "Unique",
  trusted: "Library",
};

export const ORIGIN_HINT: Record<FunctionOriginKind, string> = {
  malware: "Code found in one malware family's samples",
  shared: "Code seen across many unrelated malware families: says nothing about which family this is",
  unique: "Not found in any loaded pack: the code to reverse first",
  trusted: "Compiler runtimes, FLIRT signatures and known benign libraries",
};

export interface FunctionOrigin {
  kind: FunctionOriginKind;
  /** Top malware family name or trusted source name, when applicable. */
  label?: string;
  /** Human-readable match detail for tooltips and badges. */
  detail?: string;
  exclusive?: boolean;
  /** Symbol name a BXFAM003 pack records for this Trusted function. */
  symbol?: string;
}

/** A pack-derived name for a Trusted function, shown only when nothing better names it. */
export interface TrustedName {
  name: string;
  /** Formatted Trusted source, e.g. "OpenSSL". */
  source?: string;
  pack?: string;
  /** Tooltip text, e.g. "Trusted symbol from pack · OpenSSL · EVP_DecryptUpdate". */
  detail: string;
}

export interface OriginIndex {
  byAddress: Map<number, FunctionOrigin>;
  trustedSet: Set<number>;
  malwareSet: Set<number>;
  sharedSet: Set<number>;
  uniqueSet: Set<number>;
}

export function formatMatchKind(kind: FamilyMatchKind): string {
  if (kind === "exact_content") return "exact content";
  if (kind === "exact_shape") return "exact shape";
  return `fuzzy (${kind.fuzzy_band.bands}/8 bands)`;
}

export type MatchStrength = "strong" | "likely" | "weak";

/**
 * Turns a family match into a word an analyst can act on. The engine's `score` is an unbounded
 * weighted sum, so the verdict rests on what it is made of instead: how many functions occur only
 * in this family, how much of the file's distinctive code they cover, and whether any match is exact.
 */
export function matchStrength(fam: Pick<FamilyMatch, "exclusive_functions" | "coverage" | "exact_content_hits" | "exact_shape_hits">): MatchStrength {
  const exact = fam.exact_content_hits + fam.exact_shape_hits > 0;
  let level: MatchStrength =
    fam.exclusive_functions >= 10 && fam.coverage >= 0.5 ? "strong"
    : fam.exclusive_functions >= 3 && fam.coverage >= 0.25 ? "likely"
    : "weak";
  if (!exact) level = level === "strong" ? "likely" : "weak";
  return level;
}

export const STRENGTH_LABEL: Record<MatchStrength, string> = {
  strong: "Strong match",
  likely: "Likely match",
  weak: "Weak match",
};

/** Plain-language count of how the family's functions matched, e.g. "36 identical, 2 same control flow". */
export function describeMatchKinds(fam: Pick<FamilyMatch, "exact_content_hits" | "exact_shape_hits" | "fuzzy_hits">): string {
  return [
    fam.exact_content_hits > 0 && `${fam.exact_content_hits} identical`,
    fam.exact_shape_hits > 0 && `${fam.exact_shape_hits} same control flow`,
    fam.fuzzy_hits > 0 && `${fam.fuzzy_hits} similar`,
  ].filter(Boolean).join(", ");
}

export function formatSourceName(source: string): string {
  return source
    .replace(/^windows-/, "Windows ")
    .replace(/^linux-/, "Linux ")
    .replace(/^macos-/, "macOS ")
    .replace(/^runtime-stdlib$/, "Runtime / FLIRT")
    .replace(/-/g, " ");
}

/**
 * Indexes per-function code-origin verdicts from a `FamilyReport` plus FLIRT/capa library hits.
 * Priority matches the engine: malware family > shared malware > trusted > unique.
 */
export function buildOriginIndex(
  report: FamilyReport | null,
  capaLibrary?: readonly number[],
): OriginIndex {
  const byAddress = new Map<number, FunctionOrigin>();
  const trustedSet = new Set<number>(capaLibrary ?? []);
  const malwareSet = new Set<number>();
  const sharedSet = new Set<number>();
  const uniqueSet = new Set<number>();

  if (report) {
    const symbols = trustedNames(report);
    for (const src of report.trusted_sources) {
      const label = formatSourceName(src.source);
      for (const ad of src.addresses) {
        trustedSet.add(ad);
        const symbol = symbols.get(ad)?.name;
        byAddress.set(ad, {
          kind: "trusted",
          label,
          symbol,
          detail: `Library · ${label}${symbol ? ` · ${symbol}` : ""}`,
        });
      }
    }
    for (const ad of report.shared_addresses) {
      sharedSet.add(ad);
      if (!byAddress.has(ad)) {
        byAddress.set(ad, {
          kind: "shared",
          label: "Common malware",
          detail: "Common malware code: seen across many unrelated families",
        });
      }
    }
    for (const ad of report.unique_addresses) {
      uniqueSet.add(ad);
      if (!byAddress.has(ad)) {
        byAddress.set(ad, {
          kind: "unique",
          label: "Unique",
          detail: "Unique: not in any loaded pack",
        });
      }
    }
    // Highest-ranked family wins the primary label for functions matched by multiple families.
    for (const fam of report.families) {
      for (const fn of fam.functions) {
        malwareSet.add(fn.address);
        if (byAddress.get(fn.address)?.kind !== "malware") {
          const kindLabel = formatMatchKind(fn.kind);
          const excl = fn.exclusivity === 1;
          byAddress.set(fn.address, {
            kind: "malware",
            label: fam.family,
            exclusive: excl,
            detail: `${fam.family} · ${kindLabel}${excl ? " · exclusive" : ""}`,
          });
        }
      }
    }
  }

  // Ensure capa/FLIRT library hits without a pack entry still get a trusted label.
  for (const ad of trustedSet) {
    if (!byAddress.has(ad)) {
      byAddress.set(ad, {
        kind: "trusted",
        label: "Library",
        detail: "Library function (FLIRT / Function ID)",
      });
    }
  }

  return { byAddress, trustedSet, malwareSet, sharedSet, uniqueSet };
}

/** Names the decompiler makes up for functions without a symbol (`FUN_00401000`, `sub_401000`). */
export function isAutoName(name: string | null | undefined): boolean {
  return !name || /^(?:thunk_)?(?:FUN|sub)_[0-9a-f]+$/i.test(name);
}

/** Pack-derived names for Trusted functions (BXFAM003), by address. Empty for BXFAM002 packs. */
export function trustedNames(report: FamilyReport | null | undefined): Map<number, TrustedName> {
  const out = new Map<number, TrustedName>();
  for (const hit of report?.trusted_symbols ?? []) {
    const name = hit.trusted_symbol.trim();
    if (!name) continue;
    const source = hit.source ? formatSourceName(hit.source) : undefined;
    out.set(hit.address, {
      name,
      source,
      pack: hit.pack_name,
      detail: ["Library name from pack", source, name].filter(Boolean).join(" · ") + (hit.pack_name ? ` (${hit.pack_name})` : ""),
    });
  }
  return out;
}

/** Most characters of a string value the engine keeps in a report entry. */
const MAX_STRING_ENTRY_CHARS = 200;

/**
 * The key the engine's String Reuse entries are stored under: whitespace collapsed, at most 200
 * characters. It does not apply the engine's eligibility rules (those decide what is counted);
 * it only finds the report entry for a string the page already shows.
 */
export function stringOriginKey(raw: string): string {
  const collapsed = raw.split(/\s+/).filter(Boolean).join(" ");
  const chars = Array.from(collapsed);
  return chars.length > MAX_STRING_ENTRY_CHARS ? chars.slice(0, MAX_STRING_ENTRY_CHARS).join("") : collapsed;
}

/** String Reuse entries by {@link stringOriginKey}, or null when the match has no string data (BXFAM002 packs). */
export function buildStringOriginIndex(report: FamilyReport | null | undefined): Map<string, StringMatch> | null {
  const strings = report?.strings;
  if (!strings || strings.total_strings === 0) return null;
  const out = new Map<string, StringMatch>();
  for (const e of strings.entries) if (!out.has(e.value)) out.set(e.value, e);
  return out;
}

/** Look up a page string's String Reuse class; strings the report leaves out are not in any pack. */
export function stringOriginOf(index: Map<string, StringMatch> | null, raw: string): StringOriginKind | null {
  if (!index) return null;
  return index.get(stringOriginKey(raw))?.kind ?? "unique";
}

/** A compact badge for a classified string: the family for an exclusive string, else its class. */
export function stringOriginBadge(m: StringMatch): { text: string; title: string } {
  const fams = m.families ?? [];
  if (m.kind === "malware") return { text: fams[0] ?? "Malware", title: `Seen only in ${fams[0] ?? "one malware family"}'s samples` };
  if (m.kind === "shared") return { text: "Common malware", title: fams.length ? `Seen in ${fams.join(", ")}` : "Seen in several malware families" };
  if (m.kind === "trusted") return { text: "Library", title: "Common in benign software, per a loaded pack" };
  return { text: "Unique", title: "Not in any loaded pack" };
}
