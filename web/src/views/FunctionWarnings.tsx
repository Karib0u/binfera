import type { DecompiledFunction } from "../types";

const UNCERTAINTY = {
  arguments: "uncertain arguments",
  return: "uncertain return value",
  "arguments, return": "uncertain arguments and return value",
} as const;

function uncertainCalls(warning: string) {
  const match = /^(Unknown callee prototype: .*?) Uncertain calls \((\d+)\): (.+)$/.exec(warning);
  if (!match) return null;

  const [, message, total, details] = match;
  const entries = details.split(/; (?=0x[\da-f]+ -> |\d+ more calls$)/i);
  const more = /^(\d+) more calls$/.exec(entries.at(-1) ?? "");
  const omitted = more ? Number(more[1]) : 0;
  if (more) entries.pop();
  if (entries.length + omitted !== Number(total)) return null;

  const calls = [];
  for (const entry of entries) {
    const call = /^(0x[\da-f]+) -> (.+) \((arguments|return|arguments, return)\)$/i.exec(entry);
    if (!call) return null;
    const [, site, target, flags] = call;
    calls.push({ site, target, uncertainty: UNCERTAINTY[flags.toLowerCase() as keyof typeof UNCERTAINTY] });
  }
  return { message, calls, omitted };
}

export function FunctionWarnings({ f, onShowAsm }: { f: DecompiledFunction; onShowAsm?: (va: number) => void }) {
  if (!f.incomplete && !f.warnings?.length) return null;
  return <details className="warn">
    <summary>Output may be incomplete{f.unknown_callees ? " · unknown callees" : ""}</summary>
    <ul>{f.warnings?.map((warning, i) => {
      const parsed = uncertainCalls(warning);
      if (!parsed) return <li key={i}>{warning}</li>;
      return <li key={i}>{parsed.message}
        <ul>{parsed.calls.map(({ site, target, uncertainty }, j) => {
          const va = Number(site);
          const linked = onShowAsm && Number.isSafeInteger(va) && f.asm?.some(([ad]) => ad === va);
          return <li key={j}>
            {linked ? <a className="xref" href={"#" + site} title="Show this call site in Asm" onClick={(e) => { e.preventDefault(); onShowAsm(va); }}><code>{site}</code></a> : <code>{site}</code>}
            {" → "}<code>{target}</code>{" · "}{uncertainty}
          </li>;
        })}
          {parsed.omitted > 0 && <li>{parsed.omitted} more {parsed.omitted === 1 ? "call" : "calls"}</li>}
        </ul>
      </li>;
    })}</ul>
  </details>;
}
