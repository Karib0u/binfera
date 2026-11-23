import { useState, type ReactNode } from "react";
import type { Fact, Resource, Signature, Structure } from "../engine/image";
import type { Analysis } from "../types";
import { bytes as size, hex } from "../workspace/labels";
import { SectionsList } from "./SectionsList";

type Image = NonNullable<Analysis["image"]>;

/** A collapsible part of the page; its contents render on first opening, since headers can run to thousands of rows. */
function Part({ title, count, open: initial = false, children }: { title: string; count?: string | number; open?: boolean; children: () => ReactNode }) {
  const [opened, setOpened] = useState(initial);
  return (
    <details className="fv-sec" data-part={title.toLowerCase()} open={initial} onToggle={(e) => { if (e.currentTarget.open) setOpened(true); }}>
      <summary>{title}{count !== undefined && <em>{count}</em>}</summary>
      {opened && <div className="fv-body">{children()}</div>}
    </details>
  );
}

function save(image: Image, fileName: string, label: string, off: number, length: number) {
  const data = image.bytes.slice(off, off + length);
  const url = URL.createObjectURL(new Blob([data], { type: "application/octet-stream" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `${fileName}.${label}.bin`;
  link.click();
  URL.revokeObjectURL(url);
}

const GROUPS = ["Identity", "Security", "Build", "Dependencies", "Hashes"];

function Facts({ facts, onPick }: { facts: Fact[]; onPick: (va: number) => void }) {
  return (
    <>
      {GROUPS.filter((g) => facts.some((f) => f.group === g)).map((group) => (
        <div key={group}>
          <div className="fv-group">{group}</div>
          <dl className="fv-kv">
            {facts.filter((f) => f.group === group).map((f, n) => (
              <div key={f.label + n} style={{ display: "contents" }}>
                <dt>{f.label}</dt>
                <dd>{f.va !== undefined ? <button className="fv-link" onClick={() => onPick(f.va!)}>{f.value}</button> : group === "Hashes" ? <code>{f.value}</code> : f.value}</dd>
              </div>
            ))}
          </dl>
        </div>
      ))}
    </>
  );
}

function SignatureCard({ signature: s }: { signature: Signature }) {
  const rows: [string, string | undefined][] = [
    ["Program", s.program], ["Signing time", s.signingTime], ["Timestamp", s.timestamp], ["Timestamp by", s.timestampSigner],
    ["Digest", s.digestAlgorithm], ["Signed digest", s.signedDigest], ["File digest", s.digestMatches === false ? s.computedDigest : undefined],
    ...s.properties.map((p): [string, string] => [p.label, p.value]),
  ];
  const certificates = [...s.certificates].sort((x, y) => Number(y.signer) - Number(x.signer));
  return (
    <div className="fv-sig">
      <h4>
        {s.kind}
        {s.digestMatches === true && <span className="fv-badge ok">Digest matches the file</span>}
        {s.digestMatches === false && <span className="fv-badge bad">Digest mismatch: file changed after signing</span>}
        {s.digestMatches === undefined && <span className="fv-badge">Digest not checked</span>}
      </h4>
      <dl className="fv-kv">
        {rows.filter(([, value]) => value).map(([label, value]) => (
          <div key={label} style={{ display: "contents" }}><dt>{label}</dt><dd>{value}</dd></div>
        ))}
      </dl>
      {certificates.map((c) => (
        <div className="fv-cert" key={c.sha256}>
          <b>{c.signer ? "Signer: " : ""}{c.subject || "(no subject)"}</b>
          <dl className="fv-kv">
            <dt>Issued by</dt><dd>{c.selfSigned ? "self-signed" : c.issuer}</dd>
            <dt>Valid</dt><dd>{c.notBefore} to {c.notAfter}</dd>
            <dt>Serial</dt><dd><code>{c.serial}</code></dd>
            <dt>SHA-1</dt><dd><code>{c.sha1}</code></dd>
            <dt>SHA-256</dt><dd><code>{c.sha256}</code></dd>
          </dl>
        </div>
      ))}
      {s.entitlements && <pre className="fv-pre">{s.entitlements}</pre>}
    </div>
  );
}

const MAX_RESOURCE_ROWS = 2000;

function Resources({ image, fileName, resources, onPick }: { image: Image; fileName: string; resources: Resource[]; onPick: (va: number) => void }) {
  return (
    <div className="fv-scroll">
      <table className="fv-table">
        <thead><tr><th>Type</th><th>Name</th><th>Language</th><th>Size</th><th>Entropy</th><th>Contents</th><th>Address</th><th /></tr></thead>
        <tbody>
          {resources.slice(0, MAX_RESOURCE_ROWS).map((r, n) => (
            <tr key={n} className="go" onClick={() => onPick(r.va)}>
              <td>{r.type}</td><td>{r.name}</td><td>{r.lang}</td><td>{size(r.size)}</td>
              <td className={"num" + ((r.entropy ?? 0) >= 7.5 ? " flag" : "")}>{r.entropy?.toFixed(2) ?? "–"}</td>
              <td className={r.detected === "PE" || r.detected === "ELF" || r.detected === "Mach-O" ? "flag" : ""}>{r.detected ?? ""}</td>
              <td className="num">{hex(r.va)}</td>
              <td>{r.off !== undefined && <button className="fv-save" onClick={(e) => { e.stopPropagation(); save(image, fileName, `${r.type}-${r.name}`.replace(/[^\w-]/g, "_"), r.off!, r.size); }}>Save</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {resources.length > MAX_RESOURCE_ROWS && <p className="fv-note">Showing the first {MAX_RESOURCE_ROWS} of {resources.length} resources.</p>}
    </div>
  );
}

function StructureRows({ structure: s, onPick }: { structure: Structure; onPick: (va: number) => void }) {
  const [opened, setOpened] = useState(false);
  return (
    <details className="fv-struct" onToggle={(e) => { if (e.currentTarget.open) setOpened(true); }}>
      <summary>{s.name}<small>file offset {hex(s.off)} · {s.size} bytes{s.va === undefined ? " · not mapped" : ""}</small></summary>
      {opened && (
        <div className="fv-scroll">
          <table className="fv-table">
            <thead><tr><th>Offset</th><th>Field</th><th>Value</th><th>Meaning</th></tr></thead>
            <tbody>
              {s.fields.map((f) => (
                <tr key={f.off + f.name}>
                  <td className="num">{hex(f.off)}</td><td>{f.name}</td><td className="num">{f.value}</td>
                  <td>{f.note}{f.target !== undefined && <>{f.note ? " " : ""}<button className="fv-link" onClick={() => onPick(f.target!)}>→ {hex(f.target)}</button></>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </details>
  );
}

/** What the file says about itself: triage facts, findings, resources, signatures and raw headers. */
export function FileView({ image, fileName, cursor, onPick }: { image: Image; fileName: string; cursor: number | null; onPick: (va: number) => void }) {
  const d = image.details;
  if (!d) return <div className="view fv"><h1>File</h1><p className="empty">This engine build does not report file details.</p><Part title="Sections" count={image.sections.length} open>{() => <SectionsList image={image} cursor={cursor} onPick={onPick} />}</Part></div>;
  const anomalies = [...d.anomalies].sort((x, y) => Number(y.severity === "warn") - Number(x.severity === "warn"));
  const warnings = d.anomalies.filter((x) => x.severity === "warn").length;
  const fields = d.structures.reduce((n, s) => n + s.fields.length, 0);
  return (
    <div className="view fv">
      <h1>File</h1>
      <Part title="Findings" count={d.anomalies.length ? `${warnings} to review, ${d.anomalies.length - warnings} notes` : "none"} open>
        {() => anomalies.length === 0 ? <p className="fv-empty">Nothing unusual in the headers.</p> : anomalies.map((x, n) => {
          const body = <><i aria-hidden /><span>{x.text}</span>{x.va !== undefined && <code>{hex(x.va)}</code>}</>;
          const cls = "fv-finding" + (x.severity === "warn" ? " warn" : "");
          return x.va !== undefined ? <button key={n} className={cls} onClick={() => onPick(x.va!)}>{body}</button> : <div key={n} className={cls}>{body}</div>;
        })}
      </Part>
      <Part title="Summary" open>{() => <Facts facts={d.facts} onPick={onPick} />}</Part>
      {image.sections.length > 0 && <Part title="Sections" count={image.sections.length} open>{() => <SectionsList image={image} cursor={cursor} onPick={onPick} />}</Part>}
      {d.versionInfo.length > 0 && (
        <Part title="Version information" count={d.versionInfo.length} open>
          {() => <dl className="fv-kv">{d.versionInfo.map((p) => <div key={p.label} style={{ display: "contents" }}><dt>{p.label}</dt><dd>{p.value}</dd></div>)}</dl>}
        </Part>
      )}
      {d.signatures.length > 0 && (
        <Part title="Signatures" count={d.signatures.length} open>
          {() => <>
            <p className="fv-note">The digest shows whether the file still matches what was signed. Certificate chains and trust are not checked, so a matching digest does not make a signer trustworthy.</p>
            {d.signatures.map((s, n) => <SignatureCard key={n} signature={s} />)}
          </>}
        </Part>
      )}
      {d.resources.length > 0 && (
        <Part title="Resources" count={d.resources.length} open={d.resources.length <= 50}>
          {() => <Resources image={image} fileName={fileName} resources={d.resources} onPick={onPick} />}
        </Part>
      )}
      {d.overlay && (
        <Part title="Overlay" count={size(d.overlay.size)} open>
          {() => (
            <dl className="fv-kv">
              <dt>File offset</dt><dd><code>{hex(d.overlay!.off)}</code></dd>
              <dt>Size</dt><dd>{size(d.overlay!.size)}</dd>
              <dt>Entropy</dt><dd>{d.overlay!.entropy.toFixed(2)}</dd>
              <dt>Contents</dt><dd>{d.overlay!.kind ?? "not recognized"}</dd>
              <dt>Bytes</dt><dd><button className="fv-save" onClick={() => save(image, fileName, "overlay", d.overlay!.off, d.overlay!.size)}>Save</button></dd>
            </dl>
          )}
        </Part>
      )}
      {d.manifest && <Part title="Manifest">{() => <pre className="fv-pre">{d.manifest}</pre>}</Part>}
      {d.structures.length > 0 && (
        <Part title="Headers" count={`${d.structures.length} structures, ${fields} fields`}>
          {() => d.structures.map((s) => <StructureRows key={s.off + s.name} structure={s} onPick={onPick} />)}
        </Part>
      )}
    </div>
  );
}
