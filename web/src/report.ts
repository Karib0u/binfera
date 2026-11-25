import type { CodeBreakdown } from "./types";

/** A readable summary of an analysis, as Markdown or a single self-contained HTML page, and CSV tables for spreadsheets. */

export interface ReportInput {
  fileName: string; size: number; sha256?: string; format?: string; os?: string; arch?: string;
  toolchains: string[]; packed?: string;
  codeOrigin?: {
    breakdown: CodeBreakdown;
    families: { family: string; score: number; exclusive: number; coverage: number }[];
    trustedSources: { source: string; functions: number }[];
    /** Active packs, base first, e.g. "Starter pack (BXFAM002)". */
    packs?: string[];
    /** Pack-derived names for Trusted functions that nothing else names (BXFAM003). */
    trustedSymbols?: { address: string; name: string; source?: string }[];
    /** String Reuse summary (BXFAM003); supporting evidence only. */
    strings?: {
      total: number; trusted: number; malware: number; shared: number; unique: number;
      families: { family: string; exclusive: number; corroboratesCode: boolean }[];
      exclusive: { value: string; families: string[] }[];
      hint?: { family: string; strings: number };
    };
  };
  stringsShown?: number; stringsTotal?: number;
  findings: { severity: "warn" | "info"; text: string }[];
  signatures: string[];
  capabilities: { name: string; attack: string[]; tactic: string; matches: number; functions: string[] }[];
  indicators: { kind: string; values: string[] }[];
  sections: { name: string; address: string; size: number; perms: string; entropy: number }[];
  starred: string[];
  comments?: { address: string; text: string; source: "human" | "ai" }[];
}

const MAX_FUNCTIONS = 6, MAX_VALUES = 25;
const bytes = (n: number) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B");

/** Capabilities under their ATT&CK tactic, tactics with the most matches first. */
function byTactic(input: ReportInput) {
  const groups = new Map<string, ReportInput["capabilities"]>();
  for (const c of input.capabilities) groups.set(c.tactic || "Other", [...(groups.get(c.tactic || "Other") ?? []), c]);
  return [...groups].sort((x, y) => y[1].length - x[1].length || x[0].localeCompare(y[0]));
}

export interface Block { heading: string; lines: { text: string; sub?: string[] }[]; table?: { head: string[]; rows: string[][] } }

function blocks(input: ReportInput): Block[] {
  const out: Block[] = [];
  const identity = [
    `File: ${input.fileName}`, `Size: ${bytes(input.size)}`,
    input.sha256 && `SHA-256: ${input.sha256}`,
    [input.format?.toUpperCase(), input.os, input.arch].filter(Boolean).join(" · ") && `Type: ${[input.format?.toUpperCase(), input.os, input.arch].filter(Boolean).join(" · ")}`,
    input.toolchains.length ? `Built with: ${input.toolchains.join(", ")} (a hint from marks in the file)` : "",
    input.packed ? `Packing: ${input.packed}` : "",
    ...input.signatures.map((s) => `Signature: ${s}`),
  ].filter(Boolean) as string[];
  out.push({ heading: "Identity", lines: identity.map((text) => ({ text })) });
  if (input.codeOrigin) {
    const { breakdown: b, families, trustedSources } = input.codeOrigin;
    const lines: Block["lines"] = [
      { text: `Breakdown: ${b.malware_pct.toFixed(1)}% malware family, ${b.shared_pct.toFixed(1)}% shared malware, ${b.unique_pct.toFixed(1)}% unique, ${b.trusted_pct.toFixed(1)}% trusted` },
    ];
    if (families.length) {
      lines.push({
        text: "Matched families",
        sub: families.map((f) => `${f.family}: ${f.exclusive} function${f.exclusive === 1 ? "" : "s"} found only in this family, ${Math.round(f.coverage * 100)}% of distinctive code`),
      });
    } else {
      lines.push({ text: "Matched families: none above threshold" });
    }
    if (trustedSources.length) {
      lines.push({ text: `Trusted sources: ${trustedSources.map((s) => `${s.source} (${s.functions})`).join(", ")}` });
    }
    const { packs, trustedSymbols, strings } = input.codeOrigin;
    if (packs && packs.length > 1) lines.push({ text: `Packs (base first): ${packs.join(", ")}` });
    if (trustedSymbols?.length) {
      lines.push({
        text: `Trusted symbols from packs (${trustedSymbols.length})`,
        sub: [
          ...trustedSymbols.slice(0, MAX_VALUES).map((t) => `${t.address} ${t.name}${t.source ? ` (${t.source})` : ""}`),
          ...(trustedSymbols.length > MAX_VALUES ? [`and ${trustedSymbols.length - MAX_VALUES} more`] : []),
        ],
      });
    }
    if (strings && strings.total > 0) {
      const p = (n: number) => `${((100 * n) / strings.total).toFixed(1)}%`;
      lines.push({ text: `String reuse (supporting evidence, not part of the verdict): ${strings.total} strings, ${p(strings.malware)} malware family, ${p(strings.shared)} shared, ${p(strings.unique)} unique, ${p(strings.trusted)} trusted` });
      if (strings.families.length) {
        lines.push({ text: "String reuse by family", sub: strings.families.map((f) => `${f.family}: ${f.exclusive} exclusive string${f.exclusive === 1 ? "" : "s"}${f.corroboratesCode ? ", corroborates the code match" : ""}`) });
      }
      if (strings.exclusive.length) {
        lines.push({ text: "Malware-exclusive strings", sub: strings.exclusive.slice(0, MAX_VALUES).map((e) => `${e.value} (${e.families.join(", ")})`) });
      }
      if (strings.hint) {
        lines.push({ text: `Low-confidence string-only hint: ${strings.hint.family} (${strings.hint.strings} exclusive strings). Code attribution abstained; this is not a match.` });
      }
    }
    out.push({ heading: "Code origin", lines });
  }
  if (input.findings.length) out.push({ heading: "Findings", lines: [...input.findings].sort((x, y) => Number(y.severity === "warn") - Number(x.severity === "warn")).map((f) => ({ text: `${f.severity === "warn" ? "Review: " : ""}${f.text}` })) });
  if (input.capabilities.length) {
    out.push({
      heading: `Capabilities (${input.capabilities.length})`,
      lines: byTactic(input).map(([tactic, list]) => ({
        text: `${tactic} (${list.length})`,
        sub: list.map((c) => `${c.name}${c.attack.length ? ` [${c.attack.join(", ")}]` : ""}${c.functions.length ? ` in ${c.functions.slice(0, MAX_FUNCTIONS).join(", ")}${c.functions.length > MAX_FUNCTIONS ? ` and ${c.functions.length - MAX_FUNCTIONS} more` : ""}` : ""}`),
      })),
    });
  }
  if (input.stringsShown !== undefined && input.stringsTotal !== undefined && input.stringsTotal > input.stringsShown) {
    out.push({ heading: "Strings", lines: [{ text: `Showing the first ${input.stringsShown.toLocaleString("en-US")} of ${input.stringsTotal.toLocaleString("en-US")} strings, by address` }] });
  }
  if (input.indicators.length) out.push({ heading: "Indicators", lines: input.indicators.map((i) => ({ text: `${i.kind} (${i.values.length})`, sub: [...i.values.slice(0, MAX_VALUES), ...(i.values.length > MAX_VALUES ? [`and ${i.values.length - MAX_VALUES} more`] : [])] })) });
  if (input.comments?.length) out.push({ heading: "Comments", lines: input.comments.map((c) => ({ text: `${c.address} (${c.source === "human" ? "You" : "AI"}): ${c.text}` })) });
  if (input.starred.length) out.push({ heading: "Starred functions", lines: input.starred.map((text) => ({ text })) });
  if (input.sections.length) out.push({ heading: "Sections", lines: [], table: { head: ["Name", "Address", "Size", "Permissions", "Entropy"], rows: input.sections.map((s) => [s.name || "(unnamed)", s.address, bytes(s.size), s.perms, s.entropy.toFixed(2)]) } });
  return out;
}

export const mdEscape = (s: string) => s.replace(/([\\`*_{}[\]<>|])/g, "\\$1").replace(/\r?\n/g, " ");

const NOTE = "Generated by binfera from static analysis. Pattern matches and hints are candidates to check, not verdicts; static analysis does not prove what the file does at run time.";

/** Blocks as Markdown under a title. */
export function markdownOf(title: string, items: Block[], note = NOTE): string {
  const parts = [`# ${mdEscape(title)}`, "", `_${note}_`, ""];
  for (const b of items) {
    parts.push(`## ${b.heading}`, "");
    for (const l of b.lines) { parts.push(`- ${mdEscape(l.text)}`); for (const s of l.sub ?? []) parts.push(`  - ${mdEscape(s)}`); }
    if (b.table) {
      parts.push(`| ${b.table.head.join(" | ")} |`, `| ${b.table.head.map(() => "---").join(" | ")} |`);
      for (const r of b.table.rows) parts.push(`| ${r.map(mdEscape).join(" | ")} |`);
    }
    parts.push("");
  }
  return parts.join("\n");
}

export function reportMarkdown(input: ReportInput): string {
  return markdownOf(`Analysis of ${input.fileName}`, blocks(input));
}

const html = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Blocks as one self-contained page that follows the reader's light or dark setting. */
export function htmlOf(title: string, items: Block[], note = NOTE): string {
  const body = items.map((b) => {
    const list = b.lines.length ? `<ul>${b.lines.map((l) => `<li>${html(l.text)}${l.sub ? `<ul>${l.sub.map((s) => `<li>${html(s)}</li>`).join("")}</ul>` : ""}</li>`).join("")}</ul>` : "";
    const table = b.table ? `<table><thead><tr>${b.table.head.map((h) => `<th>${html(h)}</th>`).join("")}</tr></thead><tbody>${b.table.rows.map((r) => `<tr>${r.map((c) => `<td>${html(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>` : "";
    return `<section><h2>${html(b.heading)}</h2>${list}${table}</section>`;
  }).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${html(title)}</title>
<style>:root{color-scheme:light dark;--bg:#fafaf9;--text:#1c1917;--muted:#78716c;--line:#e7e5e4}@media(prefers-color-scheme:dark){:root{--bg:#0c0a09;--text:#f5f5f4;--muted:#a8a29e;--line:#292524}}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif}main{max-width:860px;margin:0 auto;padding:40px 20px 80px}
h1{font-size:26px;margin:0 0 6px;overflow-wrap:anywhere}h2{font-size:16px;margin:32px 0 10px;padding-top:16px;border-top:1px solid var(--line)}.note{color:var(--muted);font-size:13px}
ul{margin:0;padding-left:20px}li{margin:3px 0;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:5px 10px 5px 0;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}</style></head>
<body><main><h1>${html(title)}</h1><p class="note">${html(note)}</p>${body}</main></body></html>`;
}

export function reportHtml(input: ReportInput): string {
  return htmlOf(`Analysis of ${input.fileName}`, blocks(input));
}

/** One CSV table. Cells that start like a formula are prefixed so a spreadsheet shows them as text; strings come from the analyzed file. */
export function csv(head: string[], rows: (string | number)[][]): string {
  const cell = (v: string | number) => {
    let s = String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [head, ...rows].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

export function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = Object.assign(document.createElement("a"), { href: url, download: name });
  link.click();
  URL.revokeObjectURL(url);
}
