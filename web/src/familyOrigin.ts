import type { FamilyMatch, FamilyMatchKind, FamilyReport } from "./types";

export type FunctionOriginKind = "malware" | "shared" | "trusted" | "unique";

export interface FunctionOrigin {
  kind: FunctionOriginKind;
  /** Top malware family name or trusted source name, when applicable. */
  label?: string;
  /** Human-readable match detail for tooltips and badges. */
  detail?: string;
  exclusive?: boolean;
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
    for (const src of report.trusted_sources) {
      const label = formatSourceName(src.source);
      for (const ad of src.addresses) {
        trustedSet.add(ad);
        byAddress.set(ad, {
          kind: "trusted",
          label,
          detail: `Trusted · ${label}`,
        });
      }
    }
    for (const ad of report.shared_addresses) {
      sharedSet.add(ad);
      if (!byAddress.has(ad)) {
        byAddress.set(ad, {
          kind: "shared",
          label: "Shared",
          detail: "Shared across multiple malware families",
        });
      }
    }
    for (const ad of report.unique_addresses) {
      uniqueSet.add(ad);
      if (!byAddress.has(ad)) {
        byAddress.set(ad, {
          kind: "unique",
          label: "Unique",
          detail: "Unique code (unseen in pack)",
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
