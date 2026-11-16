import type { Analysis, CapaRule } from "../types";
import { hex } from "../workspace/labels";
import { useMemo, useState } from "react";
import { useMobile } from "../workspace/useMobile";
import { TooLarge, ProgressCard } from "./AnalysisStatus";

/** ATT&CK tactics, the ones that say the most about a sample first. */
const TACTICS = ["Impact", "Credential Access", "Privilege Escalation", "Defense Evasion", "Command and Control", "Exfiltration", "Lateral Movement", "Collection", "Persistence", "Execution", "Discovery", "Initial Access", "Reconnaissance", "Resource Development"];
const rank = (tactic: string) => { const i = TACTICS.indexOf(tactic); return i < 0 ? TACTICS.length : i; };
const tacticOf = (r: CapaRule) => r.attack.map((t) => t.tactic).filter(Boolean).sort((x, y) => rank(x) - rank(y))[0] as string | undefined;
const pretty = (ns: string) => (ns[0]?.toUpperCase() ?? "") + ns.slice(1).replace(/-/g, " ");

/** Public reference page for an ATT&CK technique (T1027.001). */
const attackUrl = (id: string) => /^T\d{4}(\.\d{3})?$/.test(id) ? `https://attack.mitre.org/techniques/${id.replace(".", "/")}/` : undefined;
const slug = (s?: string) => s?.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
/** MBC: one page per behavior in the MBC repository, `<objective>/<behavior>.md`; micro-behaviors (C…) sit under `micro-behaviors/<category>/`. */
const mbcUrl = (m: { id: string; objective?: string; behavior?: string }) => {
  // Two page names differ from the title by a hyphen.
  const fix = (s?: string) => slug(s)?.replace("pseudo-random", "pseudorandom").replace("non-cryptographic", "noncryptographic");
  const o = fix(m.objective), b = fix(m.behavior);
  if (!o || !b) return undefined;
  return `https://github.com/MBCProject/mbc-markdown/blob/main/${m.id.startsWith("C") ? "micro-behaviors/" : ""}${o}/${b}.md`;
};
function Ext({ href, children }: { href?: string; children: React.ReactNode }) {
  return href ? <a className="ext" href={href} target="_blank" rel="noopener noreferrer">{children}</a> : <>{children}</>;
}

type Owner = (ad: number) => { address: number; label: string } | undefined;

/** One framework reference: a labelled link with its tactic and technique. */
function Ref({ kind, id, href, parts }: { kind: "ATT&CK" | "MBC"; id: string; href?: string; parts: (string | undefined)[] }) {
  const [head, ...rest] = parts.filter(Boolean) as string[];
  return (
    <li className="capref">
      <span className={"capref-kind " + (kind === "MBC" ? "mbc" : "att")}>{kind}</span>
      <Ext href={href}><code>{id}{href && <span aria-hidden> ↗</span>}</code></Ext>
      <span className="capref-text">{head && <b>{head}</b>}{rest.length > 0 && " · " + rest.join(" · ")}</span>
    </li>
  );
}

const SHOWN = 6;

function CapRow({ rule, onGoto, owner }: { rule: CapaRule; onGoto: (ad: number) => void; owner?: Owner }) {
  const [open, setOpen] = useState(false);
  const [all, setAll] = useState(false);
  const path = (rule.namespace ?? "").split("/").slice(1).filter(Boolean).join(" / ");
  const ids = [...rule.attack.map((t) => t.id), ...rule.mbc.map((m) => m.id)].filter(Boolean);
  const located = rule.scope !== "file" && rule.addresses.length > 0;
  // Matches grouped by the function they sit in: one row per function, the first match to jump to.
  const groups = useMemo(() => {
    const m = new Map<string, { label: string; hits: number[] }>();
    for (const ad of rule.addresses) {
      const o = owner?.(ad), key = o ? String(o.address) : "?";
      const g = m.get(key) ?? { label: o?.label ?? "unplaced", hits: [] };
      g.hits.push(ad);
      m.set(key, g);
    }
    return [...m.values()];
  }, [rule.addresses, owner]);
  const shown = all ? groups : groups.slice(0, SHOWN);
  return (
    <div className={"caprow" + (open ? " open" : "")}>
      <button className="caprow-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="caprow-name">{rule.name}</span>
        <span className="caprow-meta"><small>{rule.scope === "file" ? "File" : `${rule.count} ${rule.count === 1 ? "match" : "matches"}`}</small></span>
        <svg viewBox="0 0 24 24" aria-hidden><path d="M9 6l6 6-6 6" /></svg>
      </button>
      {open && (
        <div className="caprow-body">
          <p className="caprow-context">{path && `${path} · `}{rule.scope}</p>
          {rule.description && <p>{rule.description}</p>}
          {ids.length > 0 && (
            <ul className="caprefs">
              {rule.attack.map((t) => <Ref key={t.id} kind="ATT&CK" id={t.id} href={attackUrl(t.id)} parts={[t.tactic, t.technique, t.subtechnique]} />)}
              {rule.mbc.map((m) => <Ref key={m.id} kind="MBC" id={m.id} href={mbcUrl(m)} parts={[m.objective, m.behavior, m.method]} />)}
            </ul>
          )}
          {located && (
            <div className="capmatches">
              <h4>Found in {groups.length} {groups.length === 1 ? "function" : "functions"}</h4>
              {shown.map((g) => (
                <button key={g.label + g.hits[0]} className="capmatch" onClick={() => onGoto(g.hits[0])}>
                  <span className="capmatch-fn">{g.label}</span>
                  <small>{g.hits.length > 1 ? `${g.hits.length} matches · ` : ""}{hex(g.hits[0])}</small>
                </button>
              ))}
              {shown.length < groups.length && <button className="capmatch more" onClick={() => setAll(true)}>Show {groups.length - shown.length} more functions</button>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function CapabilityView({ a, fileLevel, onGoto, owner }: { a: Analysis; fileLevel: CapaRule[]; onGoto: (ad: number) => void; owner?: Owner }) {
  const mobile = useMobile();
  const [q, setQ] = useState("");
  const [tactic, setTactic] = useState<string | null>(null);
  const rules = useMemo(() => (a.capa?.rules ?? []).filter((r) => !r.lib), [a.capa]);
  const tactics = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of rules) for (const t of new Set(r.attack.map((x) => x.tactic).filter(Boolean))) counts.set(t, (counts.get(t) ?? 0) + 1);
    return [...counts].sort(([x], [y]) => rank(x) - rank(y));
  }, [rules]);
  const sections = useMemo(() => {
    const n = q.trim().toLowerCase();
    const shown = rules.filter((r) => (!tactic || r.attack.some((t) => t.tactic === tactic)) && (!n ||
      [r.name, r.namespace ?? "", ...r.attack.flatMap((t) => [t.id, t.tactic, t.technique, t.subtechnique]), ...r.mbc.flatMap((m) => [m.id, m.objective, m.behavior, m.method])].some((s) => s?.toLowerCase().includes(n))));
    // ATT&CK-mapped behaviour leads, by tactic; each rule appears once, under its most telling tactic. The rest keep their capa namespace.
    const mapped = new Map<string, CapaRule[]>(), other = new Map<string, CapaRule[]>();
    for (const r of shown) {
      const t = tacticOf(r);
      const into = t ? mapped : other, key = t ?? pretty(r.namespace?.split("/")[0] ?? "other");
      into.set(key, [...(into.get(key) ?? []), r]);
    }
    return [...[...mapped].sort(([x], [y]) => rank(x) - rank(y)), ...[...other].sort(([x], [y]) => x.localeCompare(y))]
      .map(([title, rs]) => ({ title, rules: [...rs].sort((x, y) => x.name.localeCompare(y.name)) }));
  }, [rules, q, tactic]);

  const refusal = a.tooLarge ?? a.capaTooLarge;
  if (refusal) return <div className="view"><h2 className="caps-title">Capabilities</h2><TooLarge message={refusal} whole={!!a.tooLarge} /></div>;
  if (a.capaError) return <div className="view"><div className="notice error">Capability analysis failed: {a.capaError}</div></div>;
  if (!a.capa) return <ProgressCard a={a} />;
  const count = sections.reduce((n, s) => n + s.rules.length, 0);

  return (
    <div className={"view caps" + (mobile ? " mcaps" : "")}>
      {a.decompileError && <div className="notice error">Decompiler: {a.decompileError.replace(/^error: /, "")}</div>}
      <div className="ov-cap-heading"><h2 className="caps-title">Capabilities <small>{count === rules.length ? count : `${count} of ${rules.length}`}</small></h2></div>
      {rules.length > 0 && (
        <div className="caps-tools">
          <input className="caps-filter" type="search" placeholder="Search capabilities" aria-label="Filter capabilities" value={q} onChange={(e) => setQ(e.target.value)} />
          {tactics.length > 0 && <select className="caps-tactic-select" aria-label="Filter by tactic" value={tactic ?? ""} onChange={(e) => setTactic(e.target.value || null)}>
            <option value="">All tactics</option>
            {tactics.map(([t, n]) => <option key={t} value={t}>{t} ({n})</option>)}
          </select>}
        </div>
      )}
      {rules.length === 0 && <p className="empty">No capabilities matched.</p>}
      {rules.length > 0 && count === 0 && <p className="empty">No capabilities match this filter.</p>}
      {sections.map((s) => (
        <section key={s.title}>
          <h2>{s.title} <small>{s.rules.length}</small></h2>
          <div className="caprows">{s.rules.map((r) => <CapRow key={r.name} rule={r} onGoto={onGoto} owner={owner} />)}</div>
        </section>
      ))}
      {fileLevel.length > 0 && <p className="fine caps-note">Includes {fileLevel.length} file-level matches.</p>}
    </div>
  );
}
