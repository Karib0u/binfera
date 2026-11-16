import type { Section } from "../engine/image";

const LABELS = { exec: "Executable", write: "Writable", read: "Read-only", wx: "Writable + executable", other: "Other" };

export function sectionKind(s: Section): keyof typeof LABELS {
  if (s.perms.includes("x")) return s.perms.includes("w") ? "wx" : "exec";
  if (s.perms.includes("w")) return "write";
  return s.perms.includes("r") ? "read" : "other";
}

export function SectionLegend({ sections }: { sections: Section[] }) {
  const present = new Set(sections.map(sectionKind));
  if (!present.size) return null;
  return <div className="section-legend" aria-label="Section permissions">
    {(Object.keys(LABELS) as (keyof typeof LABELS)[]).filter((k) => present.has(k)).map((k) => (
      <span key={k} className={"section-" + k}><i aria-hidden />{LABELS[k]}</span>
    ))}
  </div>;
}
