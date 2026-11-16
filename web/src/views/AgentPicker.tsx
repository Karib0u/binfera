import { useEffect, useMemo, useRef, useState } from "react";
import { agent } from "../agent/client";
import type { AgentId, AgentInfo, ModelInfo } from "../agent/types";

/** The models an agent lists change rarely, so the last list shows at once and a fresh one replaces it. */
function useModels(provider: AgentId | null) {
  const [models, setModels] = useState<ModelInfo[] | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!agent || !provider) return;
    const key = "binfera-ui:agent-models:" + provider;
    try { const cached = localStorage.getItem(key); setModels(cached ? (JSON.parse(cached) as ModelInfo[]) : null); } catch { setModels(null); }
    setFailed(false);
    let live = true;
    agent.models(provider)
      .then((list) => { if (!live) return; setModels(list); try { localStorage.setItem(key, JSON.stringify(list)); } catch { /* lasts for this window */ } })
      .catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [provider]);
  return { models, failed };
}

const AGENT_NAMES: Record<AgentId, string> = { claude: "Claude Code", codex: "Codex" };

/**
 * One chip in the composer that says which agent, model and reasoning level answer, and opens a menu to
 * change them. The models and levels are the ones the agent itself lists, so they are never out of date.
 */
export default function Picker({ agents, provider, onProvider, model, effort, onModel, onEffort, switchStartsNewChat, disabled }: {
  agents: AgentInfo[]; provider: AgentId; onProvider: (p: AgentId) => void;
  model: string; effort: string; onModel: (m: string) => void; onEffort: (e: string) => void;
  /** A conversation belongs to one agent, so choosing the other one starts a new chat. */
  switchStartsNewChat: boolean; disabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [custom, setCustom] = useState("");
  const root = useRef<HTMLDivElement>(null);
  const { models, failed } = useModels(provider);

  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => { if (!root.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); setOpen(false); } };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc, true);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc, true); };
  }, [open]);

  const chosen = models?.find((m) => m.id === model);
  // The levels to offer: the chosen model's, else the agent's default model's, else the first listed.
  const shown = chosen ?? models?.find((m) => m.isDefault) ?? models?.[0];
  const efforts = shown?.efforts ?? [];
  const label = [AGENT_NAMES[provider], model ? (chosen?.name ?? model) : null, effort || null].filter(Boolean).join(" · ");
  const known = useMemo(() => new Set((models ?? []).map((m) => m.id)), [models]);

  const pick = (m: ModelInfo | null) => {
    onModel(m?.id ?? "");
    // A level the new model does not have would be refused by the agent.
    if (m && effort && m.efforts.length && !m.efforts.includes(effort)) onEffort("");
  };
  const submitCustom = () => { const v = custom.trim(); if (v) { onModel(v); setCustom(""); setOpen(false); } };

  return (
    <div className="ag-pick" ref={root}>
      <button type="button" className="ag-pick-btn" aria-haspopup="dialog" aria-expanded={open} disabled={disabled} onClick={() => setOpen(!open)} title="Agent, model and reasoning">
        <span>{label}</span>
        <svg viewBox="0 0 24 24" aria-hidden><path d="M6 9l6 6 6-6" /></svg>
      </button>
      {open && (
        <div className="ag-pop" role="dialog" aria-label="Agent, model and reasoning">
          {agents.length > 1 && (
            <section>
              <h5>Agent</h5>
              {agents.map((a) => (
                <button key={a.id} type="button" className={"ag-opt" + (a.id === provider ? " on" : "")} onClick={() => { onProvider(a.id); setOpen(false); }}>
                  <b>{AGENT_NAMES[a.id]}</b>
                  {switchStartsNewChat && a.id !== provider && <span>Starts a new chat</span>}
                  {a.id === provider && <i aria-hidden>✓</i>}
                </button>
              ))}
            </section>
          )}
          <section>
            <h5>Model</h5>
            <div className="ag-opts">
              <button type="button" className={"ag-opt" + (!model ? " on" : "")} onClick={() => pick(null)}>
                <b>Default</b><span>What {AGENT_NAMES[provider]} is set to</span>{!model && <i aria-hidden>✓</i>}
              </button>
              {(models ?? []).map((m) => (
                <button key={m.id} type="button" className={"ag-opt" + (m.id === model ? " on" : "")} onClick={() => pick(m)} title={m.id}>
                  <b>{m.name}</b><span>{m.description}</span>{m.id === model && <i aria-hidden>✓</i>}
                </button>
              ))}
              {model && !known.has(model) && (
                <button type="button" className="ag-opt on"><b>{model}</b><span>Custom</span><i aria-hidden>✓</i></button>
              )}
            </div>
            {models === null && !failed && <p className="ag-pop-note">Asking {AGENT_NAMES[provider]} for its models…</p>}
            {failed && !models && <p className="ag-pop-note">Could not read the model list. Type a model name below.</p>}
            <input className="ag-custom" value={custom} placeholder="Other model name, then Enter" spellCheck={false}
              onChange={(e) => setCustom(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); submitCustom(); } }} />
          </section>
          {efforts.length > 0 && (
            <section>
              <h5>Reasoning</h5>
              <div className="ag-seg" role="radiogroup" aria-label="Reasoning">
                <button type="button" role="radio" aria-checked={!effort} className={!effort ? "on" : ""} onClick={() => onEffort("")}>Default</button>
                {efforts.map((x) => <button key={x} type="button" role="radio" aria-checked={effort === x} className={effort === x ? "on" : ""} onClick={() => onEffort(x)}>{x}</button>)}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
