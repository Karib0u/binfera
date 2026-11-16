import { useState } from "react";
import type { Analysis } from "../types";
import { bytes } from "../workspace/labels";
import { PackedNotice } from "./AnalysisStatus";

function Hash({ name, value }: { name: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setFailed(false);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      setFailed(true);
    }
  };
  return (
    <div className="hashrow">
      <span>{name}</span><code title={value}>{value}</code>
      <button className="hexlink" onClick={copy} aria-label={`Copy ${name}`}>{copied ? "Copied" : "Copy"}</button>
      {failed && <span role="status">Select the hash to copy it.</span>}
    </div>
  );
}

/** Identity first, followed by direct routes into the analysis. */
export function Glance({ a, functions, caps, indicators, onCode, onData, onIndicators }: {
  a: Analysis; functions: number; caps: number; indicators: number;
  onCode: () => void; onData: (k: "strings" | "imports" | "hex") => void; onIndicators: () => void;
}) {
  const count = (n: number | undefined | null, known = false) => (n || known || a.done ? n ?? 0 : "…");
  const capaCount = a.capa ? caps : a.done ? "-" : "…";
  const toCaps = (e: React.MouseEvent) => e.currentTarget.closest(".ov")?.querySelector(".caps")?.scrollIntoView({ behavior: "smooth", block: "start" });
  const imports = a.image ? a.image.imports.length + a.image.exports.length : undefined;
  const facts = [a.capa?.format.toUpperCase() ?? a.image?.format.toUpperCase(), a.capa?.os, a.capa?.arch ?? a.arch, bytes(a.size)].filter(Boolean);
  const partial = !!(a.capaError || a.decompileError || a.tooLarge || a.capaTooLarge);
  const sha256 = a.image?.details?.facts.find((f) => f.group === "Hashes" && f.label === "SHA-256")?.value ?? a.capa?.sample.sha256;
  const stat = (n: number | string, name: string, go: (e: React.MouseEvent) => void, short?: string) => (
    <button className="stat" onClick={go}><b>{typeof n === "number" ? n.toLocaleString("en-US") : n}</b><span>{short ? <><i className="long">{name}</i><i className="short">{short}</i></> : name}</span></button>
  );
  return (
    <header className="view glance">
      <div className="identity">
        <div className="ov-title-row"><h1 title={a.fileName}>{a.demo?.name ?? a.fileName}</h1><span className={"ov-status" + (!a.done ? " working" : "")}><i aria-hidden />{a.done ? partial ? "Analysis incomplete" : "Analyzed" : "Analyzing"}</span></div>
        <p className="ov-facts">{a.demo && <span>{a.demo.kind}</span>}{facts.map((fact, i) => <span key={i}>{fact}</span>)}</p>
        {a.demo && <p className="fine">{a.demo.note}</p>}
      </div>
      {sha256 && <div className="ov-hash"><Hash key={sha256} name="SHA-256" value={sha256} /></div>}
      <PackedNotice a={a} />
      <div className="stats" aria-label="Analysis summary">
        {stat(capaCount, "Capabilities", toCaps)}
        {stat(count(functions), "Functions", onCode)}
        {stat(count(indicators, !!a.image), "Indicators", onIndicators)}
        {stat(count(imports, !!a.image), "Imports & exports", () => onData("imports"), "Imports")}
        {stat(count(a.strings.length, !!a.image), "Strings", () => onData("strings"))}
        {stat(count(a.image?.sections.length, !!a.image), "Sections", () => onData("hex"))}
      </div>
    </header>
  );
}
