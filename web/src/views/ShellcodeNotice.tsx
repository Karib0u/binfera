import { useEffect, useState } from "react";
import type { Analysis } from "../types";
import type { RawCodeOptions } from "../engine/engine.worker";

export function ShellcodeNotice({ a, onChange }: { a: Analysis; onChange?: (raw: RawCodeOptions) => void }) {
  const [offset, setOffset] = useState(String(a.shellcode?.offset ?? 0));
  const [error, setError] = useState("");
  useEffect(() => { setOffset(String(a.shellcode?.offset ?? 0)); }, [a.shellcode?.offset]);
  const raw = a.shellcode;
  if (!raw) return null;
  const options = { format: raw.format, os: raw.os, offset: raw.offset };
  const applyOffset = (e: React.FormEvent) => {
    e.preventDefault();
    const value = Number(offset);
    if (!offset.trim() || !Number.isSafeInteger(value) || value < 0 || value >= raw.inputSize) {
      setError(`Enter an offset from 0 to ${raw.inputSize - 1} (decimal or 0x hex).`);
      return;
    }
    setError("");
    onChange?.({ ...options, offset: value });
  };
  return <div className="shellcode-notice" role="region" aria-label="Shellcode settings">
    <span><b>{raw.guessed ? "Possible shellcode" : "Raw shellcode"}</b> · {raw.guessed ? raw.ambiguous ? "Architecture ambiguous. " : "Architecture guessed. " : ""}Addresses start at 0.
      {raw.encoding !== "binary" && <> Decoded {raw.encoding}.</>}
      {!!raw.offset && <> Skipped {raw.offset} bytes.</>}
    </span>
    <label>Architecture <select value={raw.format} disabled={!onChange} onChange={e => onChange?.({ ...options, format: e.target.value as RawCodeOptions["format"] })}>
      <option value="sc32">x86 (32-bit)</option><option value="sc64">x64 (64-bit)</option>
    </select></label>
    <label>Calling convention <select value={raw.os} disabled={!onChange} onChange={e => onChange?.({ ...options, os: e.target.value as RawCodeOptions["os"] })}>
      <option value="windows">Windows</option><option value="linux">Linux</option>
    </select>{raw.guessed && <span>{raw.osDetected ? "(inferred)" : "(default, OS unknown)"}</span>}</label>
    <form onSubmit={applyOffset}>
      <label>Start offset <input value={offset} onChange={e => setOffset(e.target.value)} disabled={!onChange} title="Skip decoded input bytes before this offset. Decimal or 0x hex." /></label>
      <button className="ghost" disabled={!onChange || Number(offset) === (raw.offset ?? 0)}>Apply</button>
    </form>
    {raw.evidence.length > 0 && <span className="shellcode-evidence">Clues: {raw.evidence.join(", ")}</span>}
    {error && <span role="alert">{error}</span>}
  </div>;
}
