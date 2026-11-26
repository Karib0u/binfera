// The function inspector's Emulate tab: runs the function, or its call sites, in Binfera's isolated
// p-code emulator. Imports are stubs that return zero; no host API runs and nothing leaves the engine.
// A function with callers opens on what each call produces; your own arguments are one click away.
import { useEffect, useRef, useState } from "react";
import type { Analysis } from "../types";
import {
  addressOf, argsFromPrototype, buildRequest, bytesHex, describeArg, hexWord, InputError, LIMITS, MAX_SITES, outputs, parseExact, siteOutput, SITE_LIMITS, stackPointer, stopText,
  type ArgInput, type CallSitesResult, type EmulationResult, type Output,
} from "../engine/emulate";

type Mode = "run" | "sites";
type Outcome =
  | { mode: "run"; result: EmulationResult; buffers: Map<number, { address: number; size: number }> }
  | { mode: "sites"; result: CallSitesResult };

/** What each function's tab held, so switching tabs or functions does not lose it. */
const saved = new Map<string, { mode: Mode; args: ArgInput[]; outcomes: Partial<Record<Mode, Outcome>>; error?: string }>();

interface Props {
  a: Analysis;
  address: number;
  /** The decompiled C, for the prototype's arguments. */
  text?: string;
  /** Direct callers, once cross-references are ready. */
  callers?: number[];
  label: (ad: number) => string;
  /** Opens a caller at a call site. */
  onSite: (fn: number, at: number) => void;
  /** Shows file bytes in the Hex view; absent where there is none. */
  onBytes?: (va: number, len: number) => void;
  mobile?: boolean;
}

export function EmulatePanel({ a, address, text, callers, label, onSite, onBytes, mobile }: Props) {
  const key = `${a.fileName}:${a.size}:${address}`;
  const initial = saved.get(key);
  const hasCallers = (callers?.length ?? 0) > 0;
  const [mode, setMode] = useState<Mode>(initial?.mode ?? (hasCallers ? "sites" : "run"));
  const [args, setArgs] = useState<ArgInput[]>(() => initial?.args ?? argsFromPrototype(text));
  const [outcomes, setOutcomes] = useState<Partial<Record<Mode, Outcome>>>(initial?.outcomes ?? {});
  const [error, setError] = useState<string | undefined>(initial?.error);
  const [busy, setBusy] = useState(false);
  const run = useRef<AbortController | null>(null);
  const chosen = useRef(!!initial);
  useEffect(() => () => run.current?.abort(), []);
  useEffect(() => { saved.set(key, { mode, args, outcomes, error }); }, [key, mode, args, outcomes, error]);

  const image = a.image;
  const ptrSize = image?.ptrSize ?? (a.arch === "x86" ? 4 : 8);
  const available = !!a.emulate && !!image && a.functions.size > 0;

  const start = async (which: Mode) => {
    if (!a.emulate || !image) return;
    chosen.current = true;
    run.current?.abort();
    const controller = new AbortController();
    run.current = controller;
    setError(undefined);
    try {
      const built = buildRequest(address, which === "run" ? args : [], ptrSize, image.sections, which === "run" ? LIMITS : SITE_LIMITS);
      setBusy(true);
      const json = await a.emulate(address, built.json, which === "sites" ? MAX_SITES : undefined, controller.signal);
      if (controller.signal.aborted) return;
      const outcome: Outcome = which === "run" ? { mode: "run", result: parseExact<EmulationResult>(json), buffers: built.buffers } : { mode: "sites", result: parseExact<CallSitesResult>(json) };
      setOutcomes((o) => ({ ...o, [which]: outcome }));
    } catch (e) {
      if (controller.signal.aborted) return;
      setError(e instanceof InputError ? e.message : String((e as Error)?.message ?? e).replace(/^binfera: /, ""));
    } finally {
      if (run.current === controller) { run.current = null; setBusy(false); }
    }
  };
  const cancel = () => { run.current?.abort(); run.current = null; setBusy(false); };
  const switchTo = (m: Mode) => { chosen.current = true; cancel(); setError(undefined); setMode(m); };

  // A function with callers decodes them as soon as the tab opens; callers can arrive after it does.
  useEffect(() => {
    if (!available || chosen.current || !hasCallers) return;
    chosen.current = true;
    setMode("sites");
    void start("sites");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [available, hasCallers]);

  const setArg = (i: number, patch: Partial<ArgInput>) => setArgs((list) => list.map((arg, k) => (k === i ? { ...arg, ...patch } : arg)));
  const shown = outcomes[mode];
  const cls = "emu" + (mobile ? " m" : "");

  if (!available) {
    return <div className={cls}><p className="fine">{!a.done ? "Available once analysis finishes." : "Emulation needs a decompiled native image."}</p></div>;
  }
  const status = busy && (
    <div className="emu-busy fine"><span className="spin" /> Running… <button type="button" className="emu-link" onClick={cancel}>Cancel</button></div>
  );
  return (
    <div className={cls} aria-label="Emulate">
      {mode === "sites" ? (
        <>
          <p className="emu-lede">What this function produces at each call.</p>
          {status}
          {!busy && !shown && <div className="emu-actions"><button type="button" className="primary" onClick={() => void start("sites")}>Decode call sites</button></div>}
          {error && <div className="notice error emu-error">{error}</div>}
          {!busy && shown?.mode === "sites" && <SiteResults result={shown.result} label={label} onSite={onSite} onAgain={() => void start("sites")} />}
          <button type="button" className="emu-link emu-switch" onClick={() => switchTo("run")}>Try your own arguments</button>
        </>
      ) : (
        <>
          {hasCallers && <button type="button" className="emu-link emu-back" onClick={() => switchTo("sites")}>‹ Call sites</button>}
          <form className="emu-args" onSubmit={(e) => { e.preventDefault(); void start("run"); }}>
            {args.length === 0 && <p className="fine">Takes no arguments.</p>}
            {args.map((arg, i) => {
              const note = describeArg(arg, ptrSize);
              return (
                <label key={i} className="emu-arg">
                  <span className="emu-arg-name">
                    <code>{arg.decl ?? `argument ${i + 1}`}</code>
                    <button type="button" className="emu-x" aria-label={`Remove argument ${i + 1}`} onClick={(e) => { e.preventDefault(); setArgs((list) => list.filter((_, k) => k !== i)); }}>×</button>
                  </span>
                  <input aria-label={`Argument ${i + 1}`} spellCheck={false} autoComplete="off" value={arg.text} placeholder={arg.pointer ? 'Bytes, "text" or an address' : "0"}
                    onChange={(e) => setArg(i, { text: e.target.value, kind: "auto" })} aria-invalid={note.error || undefined} />
                  <small className={"emu-hint" + (note.error ? " bad" : "")}>{note.text}</small>
                </label>
              );
            })}
            <div className="emu-actions">
              <button type="button" className="emu-link" onClick={() => setArgs((list) => [...list, { kind: "auto", text: "" }])} disabled={args.length >= 16}>+ Argument</button>
              <span className="cp-spacer" />
              {!busy && <button type="submit" className="primary">Run</button>}
            </div>
          </form>
          {status}
          {error && <div className="notice error emu-error">{error}</div>}
          {!busy && shown?.mode === "run" && <RunResult result={shown.result} buffers={shown.buffers} args={args} onBytes={onBytes} canHex={(va) => image?.vaToOff(va) != null} />}
        </>
      )}
      <p className="fine emu-note">Sandboxed. API calls are faked, never made.</p>
    </div>
  );
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return <button type="button" className="emu-copy" onClick={(e) => {
    e.stopPropagation();
    void navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); });
  }}>{done ? "Copied" : label}</button>;
}

/** A decoded string, large, with where it was written and its actions. */
function Decoded({ out, name, onBytes, canHex }: { out: Output; name?: string; onBytes?: (va: number, len: number) => void; canHex: (va: number) => boolean }) {
  const at = addressOf(out.address);
  const text = out.text?.text;
  return (
    <div className="emu-out">
      {text !== undefined ? <div className="emu-text">{text}</div> : <code className="emu-bytes">{bytesHex(out.data.slice(0, 64))}{out.data.length > 64 ? " …" : ""}</code>}
      <div className="emu-out-foot">
        <small>{name ?? hexWord(out.address)}{out.text ? " · " + out.text.encoding : ` · ${String(out.size)} bytes`}{out.truncated ? " · cut short" : ""}</small>
        <span className="emu-out-actions">
          <CopyButton text={text ?? bytesHex(out.data)} />
          {onBytes && at !== null && canHex(at) && <button type="button" onClick={() => onBytes(at, Math.min(out.data.length || 1, 4096))}>Hex</button>}
        </span>
      </div>
    </div>
  );
}

/** Raw rows for the details section. */
function RawRow({ out, name }: { out: Output; name?: string }) {
  return (
    <li><code>{hexWord(out.address)}</code><small>{name ? name + " · " : ""}{String(out.size)} bytes</small>
      <code className="emu-bytes">{out.text ? JSON.stringify(out.text.text) : bytesHex(out.data.slice(0, 32)) + (out.data.length > 32 ? " …" : "")}</code></li>
  );
}

function RunResult({ result, buffers, args, onBytes, canHex }: { result: EmulationResult; buffers: Map<number, { address: number; size: number }>; args: ArgInput[]; onBytes?: (va: number, len: number) => void; canHex: (va: number) => boolean }) {
  const sp = stackPointer(result);
  const written = outputs(result.writes, sp);
  const named = new Map([...buffers].map(([i, b]) => [b.address, args[i]?.decl?.match(/(\w+)\s*(\[.*\])?$/)?.[1] ?? `argument ${i + 1}`]));
  const main = written.filter((w) => !w.stack);
  const headline = main.filter((w) => w.text);
  const other = main.filter((w) => !w.text);
  const stack = written.filter((w) => w.stack);
  // Buffers the function read but did not change still show what they hold.
  const unchanged = outputs(result.memory, sp).filter((m) => !main.some((w) => big(w.address) <= big(m.address) && big(m.address) < big(w.address) + big(w.size)));
  const ok = result.stop.kind === "returned";
  return (
    <section className="emu-result" aria-label="Emulation result">
      {headline.map((w) => <Decoded key={String(w.address)} out={w} name={named.get(Number(w.address))} onBytes={onBytes} canHex={canHex} />)}
      {headline.length === 0 && other.length > 0 && other.slice(0, 1).map((w) => <Decoded key={String(w.address)} out={w} name={named.get(Number(w.address))} onBytes={onBytes} canHex={canHex} />)}
      <div className={"emu-stop" + (ok ? "" : " warn")}>
        <span><b>{stopText(result.stop.kind)}</b>{ok ? "" : " at " + hexWord(result.stop.address)}</span>
        <span className="emu-ret">returns <code>{hexWord(result.return_value)}</code><CopyButton text={hexWord(result.return_value)} /></span>
      </div>
      {!ok && result.stop.detail && <p className="fine">{result.stop.detail}</p>}
      {main.length === 0 && <p className="fine">Wrote nothing outside the stack.</p>}
      <details className="emu-more">
        <summary>Details</summary>
        <p className="fine">{result.steps.toLocaleString()} steps{result.calls.length ? ` · ${result.calls.length} API call${result.calls.length === 1 ? "" : "s"}, each returning 0` : ""}</p>
        {result.calls.length > 0 && <><h3>API calls</h3><ul className="emu-calls">{result.calls.map((c, i) => <li key={i}><code>{c.name}</code><small>({c.args.map(hexWord).join(", ")})</small></li>)}</ul></>}
        {(headline.length ? other : other.slice(1)).length > 0 && <><h3>Other writes</h3><ul className="emu-calls">{(headline.length ? other : other.slice(1)).map((w) => <RawRow key={String(w.address)} out={w} name={named.get(Number(w.address))} />)}</ul></>}
        {unchanged.length > 0 && <><h3>Unchanged inputs</h3><ul className="emu-calls">{unchanged.map((w) => <RawRow key={String(w.address)} out={w} name={named.get(Number(w.address))} />)}</ul></>}
        {stack.length > 0 && <><h3>Stack writes</h3><ul className="emu-calls">{stack.map((w) => <RawRow key={String(w.address)} out={w} />)}</ul></>}
        <h3>Registers</h3>
        <dl className="emu-kv emu-regs">{Object.entries(result.registers).map(([r, v]) => <div key={r}><dt>{r}</dt><dd><code>{hexWord(v)}</code></dd></div>)}</dl>
        {result.warnings.length > 1 && <><h3>Approximations</h3><ul className="emu-calls">{result.warnings.slice(1).map((w) => <li key={w}><small>{w}</small></li>)}</ul></>}
      </details>
    </section>
  );
}

const big = (w: number | string) => BigInt(w);

function SiteResults({ result, label, onSite, onAgain }: { result: CallSitesResult; label: (ad: number) => string; onSite: (fn: number, at: number) => void; onAgain: () => void }) {
  const rows = result.sites.map((s) => ({ s, out: siteOutput(s), caller: addressOf(s.caller), at: addressOf(s.site) }));
  const texts = rows.map((r) => r.out?.text?.text).filter((t): t is string => !!t);
  if (!result.total_sites) return <section className="emu-result" aria-label="Call site results"><p className="fine">No direct calls to decode.</p></section>;
  return (
    <section className="emu-result" aria-label="Call site results">
      <ul className="emu-sites">
        {rows.map(({ s, out, caller, at }) => {
          const ok = s.reached && s.result.stop.kind === "returned";
          const text = out?.text?.text;
          return (
            <li key={`${s.caller}:${s.site}`}>
              <button type="button" className="emu-site" disabled={caller === null || at === null} data-site={at ?? undefined}
                onClick={() => caller !== null && at !== null && onSite(caller, at)} title="Show this call">
                {text !== undefined ? <span className="emu-text">{text}</span>
                  : out ? <code className="emu-bytes">{bytesHex(out.data.slice(0, 24))}{out.data.length > 24 ? " …" : ""}</code>
                  : <span className="emu-none">{ok ? "No output" : !s.reached ? "Not reached" : stopText(s.result.stop.kind)}</span>}
                <span className="emu-site-where">{caller !== null ? label(caller) : hexWord(s.caller)} · {hexWord(s.site)}{s.reached && !ok && out ? " · " + stopText(s.result.stop.kind).toLowerCase() : ""}</span>
              </button>
              {out && <CopyButton text={text ?? bytesHex(out.data)} />}
            </li>
          );
        })}
      </ul>
      <div className="emu-stop">
        <small>{result.truncated ? `First ${result.sites.length} of ${result.total_sites} calls` : `${result.total_sites} call${result.total_sites === 1 ? "" : "s"}`}</small>
        <span className="emu-ret">
          {texts.length > 1 && <CopyButton text={texts.join("\n")} label="Copy all" />}
          <button type="button" className="emu-copy" onClick={onAgain}>Run again</button>
        </span>
      </div>
    </section>
  );
}
