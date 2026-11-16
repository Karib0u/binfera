import { useMemo } from "react";
import { referencedStrings, stringsDelta, summaryOf } from "../compareModel";
import type { Comparison, DiffDocument, ListDelta, RuleSummary } from "../compare";
import { bytes } from "../workspace/labels";
import { hex, pct, SideColumn, Tag } from "./FunctionDiff";

const VERDICT = { identical: "Identical", equivalent: "Same code", changed: "Changed" } as const;
type Open = (side: "a" | "b", at: number) => void;

/** The two files side by side; a value that differs is marked. */
function Versus({ d }: { d: DiffDocument }) {
  const [a, b] = d.inputs;
  const hash = (h: string) => <code title={h}>{h.slice(0, 16)}…</code>;
  const size = (n: number) => (a.size !== b.size && bytes(a.size) === bytes(b.size) ? `${n.toLocaleString()} bytes` : bytes(n));
  const rows: { label: string; a: React.ReactNode; b: React.ReactNode; same: boolean }[] = [
    { label: "SHA-256", a: hash(a.sha256), b: hash(b.sha256), same: a.sha256 === b.sha256 },
    { label: "Format", a: `${a.format} · ${a.arch}`, b: `${b.format} · ${b.arch}`, same: a.format === b.format && a.arch === b.arch },
    // Exact when rounding would make two different sizes read the same.
    { label: "Size", a: size(a.size), b: size(b.size), same: a.size === b.size },
    { label: "Functions", a: a.functions.toLocaleString(), b: b.functions.toLocaleString(), same: a.functions === b.functions },
    { label: "Instructions", a: a.instructions.toLocaleString(), b: b.instructions.toLocaleString(), same: a.instructions === b.instructions },
  ];
  if (a.packed || b.packed) rows.push({ label: "Looks packed", a: a.packed ? "Yes" : "No", b: b.packed ? "Yes" : "No", same: a.packed === b.packed });
  const imphash = d.file_delta.imphash;
  if (imphash) rows.push({ label: "Imphash", a: <code>{imphash[0] ?? "none"}</code>, b: <code>{imphash[1] ?? "none"}</code>, same: false });
  return (
    <div className="cmp-scroll-x">
      <table className="cmp-versus">
        <thead>
          <tr>
            <td />
            <th scope="col"><Tag side="a" /> <span className="cmp-file-name" title={a.name}>{a.name}</span></th>
            <th scope="col"><Tag side="b" /> <span className="cmp-file-name" title={b.name}>{b.name}</span></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label} className={r.same ? "" : "differs"}>
              <th scope="row">{r.label}</th>
              <td>{r.a}</td>
              <td>{r.b}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DeltaList({ title, delta }: { title: string; delta: ListDelta }) {
  if (!delta.added.length && !delta.removed.length && !delta.changed.length) return null;
  const items = (list: string[]) => <ul>{list.map((x) => <li key={x}>{x}</li>)}</ul>;
  return (
    <section className="cmp-delta">
      <h3>{title}</h3>
      {(delta.added.length > 0 || delta.removed.length > 0) && (
        <div className="cmp-two">
          <SideColumn side="a" empty={!delta.removed.length}>{items(delta.removed)}</SideColumn>
          <SideColumn side="b" empty={!delta.added.length}>{items(delta.added)}</SideColumn>
        </div>
      )}
      {delta.changed.length > 0 && (
        <div className="cmp-both">
          <h4>In both, different <small>values read <Tag side="a" /> → <Tag side="b" /></small></h4>
          <ul>{delta.changed.map((x) => <li key={x.name}>{x.name} <small>{x.changes.join(", ")}</small></li>)}</ul>
        </div>
      )}
    </section>
  );
}

function FunctionLinks({ list, side, onOpen }: { list: number[]; side: "a" | "b"; onOpen: Open }) {
  if (!list.length) return null;
  return <small className="cmp-links">In {list.map((at) => <button key={at} type="button" onClick={() => onOpen(side, at)}><code>{hex(at)}</code></button>)}</small>;
}

function RuleList({ rules, attack, side, onOpen }: { rules: RuleSummary[]; attack: string[]; side: "a" | "b"; onOpen: Open }) {
  return (
    <>
      <ul className="cmp-rules">
        {rules.map((r) => <li key={r.name}><span><b>{r.name}</b><small>{[r.namespace, ...r.attack].filter(Boolean).join(" · ")}</small><FunctionLinks list={r.functions} side={side} onOpen={onOpen} /></span></li>)}
      </ul>
      {attack.length > 0 && <p className="fine">ATT&amp;CK techniques only here: {attack.join(", ")}</p>}
    </>
  );
}

function Capabilities({ d, onOpen }: { d: DiffDocument; onOpen: Open }) {
  const c = d.capability_delta;
  if (!c) return <p className="fine">Capabilities were not compared.</p>;
  const nothing = !c.added.length && !c.removed.length && !c.retargeted.length;
  if (nothing) return <p className="fine">A and B match the same {c.unchanged} rules, in the same functions.</p>;
  return (
    <>
      <div className="cmp-two">
        <SideColumn side="a" empty={!c.removed.length}><RuleList rules={c.removed} attack={c.attack_removed} side="a" onOpen={onOpen} /></SideColumn>
        <SideColumn side="b" empty={!c.added.length}><RuleList rules={c.added} attack={c.attack_added} side="b" onOpen={onOpen} /></SideColumn>
      </div>
      {c.retargeted.length > 0 && (
        <div className="cmp-both">
          <h4>In both, in different functions</h4>
          <ul className="cmp-rules">
            {c.retargeted.map((r) => (
              <li key={r.name}><span><b>{r.name}</b>
                {r.lost.length > 0 && <small className="cmp-links"><Tag side="a" /> no longer matches in the counterpart of {r.lost.map((at) => <button key={at} type="button" onClick={() => onOpen("a", at)}><code>{hex(at)}</code></button>)}</small>}
                {r.gained.length > 0 && <small className="cmp-links"><Tag side="b" /> now matches in {r.gained.map((at) => <button key={at} type="button" onClick={() => onOpen("b", at)}><code>{hex(at)}</code></button>)}</small>}
              </span></li>
            ))}
          </ul>
        </div>
      )}
      {c.unchanged > 0 && <p className="fine">{c.unchanged} other {c.unchanged === 1 ? "rule matches" : "rules match"} the same in both.</p>}
      {c.unmapped > 0 && <p className="fine">{c.unmapped} matches lie outside every recovered function, so they could not be followed.</p>}
    </>
  );
}

/** The strings code refers to, which is what the strings score counts. */
function Strings({ c }: { c: Comparison }) {
  const delta = useMemo(() => stringsDelta(referencedStrings(c.sides[0].facts), referencedStrings(c.sides[1].facts)), [c]);
  const items = (list: string[]) => <ul className="cmp-plain">{list.map((x) => <li key={x}><code>{JSON.stringify(x)}</code></li>)}</ul>;
  if (!delta.added.length && !delta.removed.length) return <p className="fine">Code in A and B refers to the same {delta.same} strings.</p>;
  return (
    <>
      <div className="cmp-two">
        <SideColumn side="a" empty={!delta.removed.length}>{items(delta.removed)}</SideColumn>
        <SideColumn side="b" empty={!delta.added.length}>{items(delta.added)}</SideColumn>
      </div>
      {delta.same > 0 && <p className="fine">{delta.same} other {delta.same === 1 ? "string is" : "strings are"} referred to in both. Strings no code refers to are not counted.</p>}
    </>
  );
}

/** Everything compared at file level: the facts behind the summary, for when they are wanted. */
export default function CompareDetails({ c, onOpen, onFunctions }: { c: Comparison; onOpen: Open; onFunctions?: () => void }) {
  const d = c.document, file = d.file_delta, summary = summaryOf(d);
  const fileSame = !file.sections.added.length && !file.sections.removed.length && !file.sections.changed.length
    && !file.imports.added.length && !file.imports.removed.length && !file.exports.added.length && !file.exports.removed.length && !file.exports.changed.length
    && !file.resources.added.length && !file.resources.removed.length && !file.resources.changed.length && !file.overlay.length && !file.imphash;
  const go = (e: React.MouseEvent, id: string) => e.currentTarget.closest(".cmp-overview")?.querySelector("#cmp-" + id)?.scrollIntoView({ behavior: "smooth" });
  const tile = (name: string, value: number | null, what: string, run: (e: React.MouseEvent) => void) => (
    <button type="button" className="cmp-metric" title={what} onClick={run}><span>{name}</span><b>{pct(value)}</b></button>
  );
  return (
    <div className="cmp-overview">
      <section className="cmp-verdict">
        <span className={"cmp-badge v-" + d.verdict}>{VERDICT[d.verdict]}</span>
        <h1 className="cmp-headline">{summary.headline}</h1>
        {summary.details.map((x) => <p key={x} className="fine">{x}</p>)}
        <Versus d={d} />
        <div className="cmp-metrics">
          {tile("Code", d.similarity.code, "How alike the functions are, by size. Goes to the changes.", (e) => (onFunctions ? onFunctions() : go(e, "file")))}
          {tile("Capabilities", d.similarity.capabilities, "Rules both match, over rules either matches.", (e) => go(e, "caps"))}
          {tile("Imports", d.similarity.imports, "Imports both have, over imports either has.", (e) => go(e, "file"))}
          {tile("Strings", d.similarity.strings, "Strings code in both refers to, over strings code in either refers to.", (e) => go(e, "strings"))}
        </div>
        <p className="fine">{pct(d.similarity.overall)} alike overall, weighing these four.</p>
        {d.warnings.map((w) => <p key={w} className="cmp-warning" role="note">{w}</p>)}
      </section>
      <section className="cmp-panel" id="cmp-caps">
        <h2>Capabilities</h2>
        <Capabilities d={d} onOpen={onOpen} />
      </section>
      {d.functions_compared && (
        <section className="cmp-panel" id="cmp-strings">
          <h2>Strings</h2>
          <Strings c={c} />
        </section>
      )}
      <section className="cmp-panel" id="cmp-file">
        <h2>File</h2>
        {fileSame && <p className="fine">A and B have the same sections, imports, exports, resources and overlay.</p>}
        <DeltaList title="Imports" delta={file.imports} />
        <DeltaList title="Exports" delta={file.exports} />
        <DeltaList title="Sections" delta={file.sections} />
        <DeltaList title="Resources" delta={file.resources} />
        {file.overlay.length > 0 && <section className="cmp-delta"><h3>Overlay</h3><p className="fine">{file.overlay.join(", ")} <small>(<Tag side="a" /> → <Tag side="b" />)</small></p></section>}
      </section>
    </div>
  );
}
