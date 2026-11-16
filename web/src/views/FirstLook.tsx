import { useMemo } from "react";
import { entropyOf, entropyWord, HIGH_ENTROPY } from "../engine/entropy";
import type { Indicator } from "../indicators";
import type { Analysis } from "../types";
import { bytes as size } from "../workspace/labels";

type Image = NonNullable<Analysis["image"]>;

/** Toolchains that leave a recognizable string, section or header behind. Matches are hints from marks in the file, not proof. */
const TOOLCHAINS: { name: string; strings?: RegExp; sections?: RegExp }[] = [
  { name: "UPX", strings: /^UPX!|\$Info: This file is packed with the UPX/, sections: /^UPX[0-9!]$/ },
  { name: "Go", strings: /^go1\.\d+|Go build ID|runtime\.gopanic/, sections: /^\.go\.buildinfo$|^\.gopclntab$/ },
  { name: "Rust", strings: /rustc version|\.cargo\/registry|rust_panic|core::panicking/, sections: /^\.rustc$/ },
  { name: "GCC", strings: /GCC: \(/ },
  { name: "Clang/LLVM", strings: /clang version|Apple clang/ },
  { name: "MinGW", strings: /Mingw-w64 runtime|MinGW/ },
  { name: "Microsoft Visual C++", strings: /Microsoft Visual C\+\+ Runtime|MSVCR\d+|VCRUNTIME\d+|api-ms-win-crt/ },
  { name: "PyInstaller", strings: /PyInstaller|_MEIPASS|pyi-runtime/ },
  { name: "Nuitka", strings: /Nuitka/ },
  { name: "Delphi", strings: /Borland|Embarcadero|SOFTWARE\\Borland\\Delphi/, sections: /^\.itext$/ },
  { name: "Nim", strings: /@m.*\.nim|nimMain/ },
  { name: "Zig", strings: /\bzig\b.*\bstd\b/ },
  { name: "AutoIt", strings: /AutoIt v3/ },
  { name: "Electron / Node", strings: /node_modules|electron\.asar/ },
];

export function guessToolchains(a: Analysis, image: Image): string[] {
  const found = new Set<string>();
  if (a.arch === "cil" || image.arch === "cil") found.add(".NET");
  const texts = a.strings.slice(0, 20000).map((s) => s.s);
  for (const t of TOOLCHAINS) {
    if (t.sections && image.sections.some((s) => t.sections!.test(s.name))) found.add(t.name);
    else if (t.strings && texts.some((s) => t.strings!.test(s))) found.add(t.name);
  }
  return [...found];
}

/** Share of mapped file bytes in executable sections and the average entropy of those. */
function codeEntropy(image: Image) {
  const exec = image.sections.filter((s) => s.perms.includes("x") && s.size > 0);
  const big = exec.filter((s) => s.entropy >= HIGH_ENTROPY);
  const sum = exec.reduce((n, s) => n + s.size, 0);
  return { exec, packedSections: big, ratio: sum ? big.reduce((n, s) => n + s.size, 0) / sum : 0 };
}

/** What each kind of string says about the file, in words a reader needs no registry or networking background for. */
const STRING_GROUPS: { label: string; kinds: string[]; note: string }[] = [
  { label: "Network", kinds: ["URLs", "IP addresses", "Domains", "Email addresses"], note: "Addresses written in the file. It may contact them, or just mention them." },
  { label: "Commands", kinds: ["Commands", "User agents"], note: "Command lines or HTTP identifiers the file contains." },
  { label: "Registry", kinds: ["Registry keys"], note: "Windows settings keys named in the file. Programs read them for system info or write them to keep settings or persist." },
  { label: "Files & objects", kinds: ["File paths", "Named objects"], note: "Paths and system object names the file refers to." },
];
const clip = (v: string, n = 56) => (v.length > n ? v.slice(0, n - 1) + "…" : v);

interface Item { label: string; value: React.ReactNode; tone?: "warn" | "ok"; go?: () => void; note?: string }

/** Where to start with an unknown file: what built it, whether it hides, what it does and what it talks to. */
export function FirstLook({ a, image, indicators, caps, onPick, onFile, onIndicators, onCaps }: {
  a: Analysis; image: Image; indicators: Indicator[]; caps: number;
  onPick: (va: number) => void; onFile: () => void; onIndicators: () => void; onCaps: () => void;
}) {
  const items = useMemo(() => {
    const out: Item[] = [];
    const d = image.details;
    const toolchains = guessToolchains(a, image);
    const compiled = d?.facts.find((f) => f.label === "PDB path")?.value;
    out.push({ label: "Built with", value: toolchains.length ? toolchains.join(", ") : "No toolchain marks found" });
    if (compiled) out.push({ label: "Debug path", value: <code title={compiled}>{compiled}</code> });
    const whole = entropyOf(image.bytes, 0, image.bytes.length, 1 << 18);
    const code = codeEntropy(image);
    if (a.packed) out.push({ label: "Packing", tone: "warn", value: a.packed.packer ? `Packed with ${a.packed.packer}` : "Looks packed", go: onFile });
    else if (code.ratio > 0.5) out.push({ label: "Packing", tone: "warn", value: `${code.packedSections.map((s) => s.name).join(", ")} is ${entropyWord(Math.max(...code.packedSections.map((s) => s.entropy)))}: likely packed`, go: onFile });
    else out.push({ label: "Packing", tone: whole >= HIGH_ENTROPY ? undefined : "ok", value: whole >= HIGH_ENTROPY
      ? `No packed code sections · file entropy ${whole.toFixed(1)} (high; see Findings)`
      : `No signs · file entropy ${whole.toFixed(1)}` });
    const wx = image.sections.filter((s) => s.perms.includes("w") && s.perms.includes("x"));
    if (wx.length) out.push({ label: "Memory", tone: "warn", value: `${wx.map((s) => s.name || "unnamed").join(", ")} writable and executable`, go: () => onPick(wx[0].va) });
    if (d?.signatures.length) out.push({ label: "Signature", tone: d.signatures.some((s) => s.digestMatches === false) ? "warn" : undefined, value: d.signatures.some((s) => s.digestMatches === false) ? "Digest does not match the file" : `${d.signatures[0].kind}${d.signatures[0].digestMatches ? ", digest matches" : ""}`, go: onFile });
    else if (d) out.push({ label: "Signature", value: "Not signed" });
    if (d?.overlay && d.overlay.size > 1024) out.push({ label: "Appended data", tone: d.overlay.entropy >= HIGH_ENTROPY ? "warn" : undefined, value: `${size(d.overlay.size)} after the image${d.overlay.kind ? ` (${d.overlay.kind})` : ""}`, go: onFile });
    const embedded = d?.resources.filter((r) => r.detected === "PE" || r.detected === "ELF" || r.detected === "Mach-O") ?? [];
    if (embedded.length) out.push({ label: "Embedded files", tone: "warn", value: `${embedded.length} executable${embedded.length === 1 ? "" : "s"} in resources`, go: onFile });
    if (a.capa) {
      const tactics = new Map<string, number>();
      for (const r of a.capa.rules) if (!r.lib) for (const t of new Set(r.attack.map((x) => x.tactic))) tactics.set(t, (tactics.get(t) ?? 0) + 1);
      const top = [...tactics].sort((x, y) => y[1] - x[1]).slice(0, 4);
      if (top.length) out.push({ label: "Behaviours", value: top.map(([t, n]) => `${t.toLowerCase()} (${n})`).join(", "), go: onCaps });
      else if (caps) out.push({ label: "Behaviours", value: `${caps} capabilities`, go: onCaps });
    }
    for (const g of STRING_GROUPS) {
      const values = indicators.filter((x) => g.kinds.includes(x.kind)).map((x) => x.value);
      if (!values.length) continue;
      out.push({ label: g.label, note: g.note, value: <><code title={values[0]}>{clip(values[0])}</code>{values.length > 1 && <small> +{values.length - 1} more</small>}</>, go: onIndicators });
    }
    return out;
  }, [a, image, indicators, caps]);

  return (
    <section className="ov-card first-look">
      <header><h2>First look</h2><span>from marks in the file, not verdicts</span></header>
      <dl>
        {items.map((it) => (
          <div key={it.label} className={"fl-row" + (it.tone ? " " + it.tone : "")}>
            <dt>{it.label}</dt>
            <dd>{it.go ? <button onClick={it.go}>{it.value}</button> : it.value}{it.note && <small className="fl-note">{it.note}</small>}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
