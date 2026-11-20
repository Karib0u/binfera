import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { agent } from "../agent/client";
import { project } from "../project/client";
import { buildPrompt, TRIAGE, type AgentContext } from "../agent/prompt";
import { AGENT_NAMES, type AgentId, type AgentInfo, type AgentRun } from "../agent/types";
import { apply, ARTIFACT_TOOLS, blocks, brief, callsThisTurn, toolSummary, type Item, type Tool } from "../agent/transcript";
import { slim, titleOf, upsert, type Conversation } from "../agent/history";
import { EFFECTS, FULL, GROUPS, request } from "./aiWorkflows";
import type { Notes } from "../names";
import Markdown from "../markdown";
import { useStored } from "../workspace/panels";
import Composer, { type SlashItem, type SymbolRef } from "./AgentComposer";
import Artifacts from "./AgentArtifacts";
import Picker from "./AgentPicker";

// ---- the transcript ---------------------------------------------------------------------------

function ToolRow({ item }: { item: Tool }) {
  const [open, setOpen] = useState(false);
  const args = brief(item.input);
  return (
    <li className={"ag-tool " + item.status}>
      <button type="button" className="ag-tool-line" aria-expanded={open} onClick={() => setOpen(!open)}>
        <i aria-hidden />
        <b>{item.name}</b>
        {args && <span>{args}</span>}
      </button>
      {open && (
        <div className="ag-tool-body">
          <pre>{JSON.stringify(item.input, null, 2)}</pre>
          {item.output && <pre>{item.output}</pre>}
        </div>
      )}
    </li>
  );
}

/** A run of tool calls as one line while it is history, and open while it is happening. */
function ToolGroup({ tools, live, onArtifact }: { tools: Tool[]; live: boolean; onArtifact: (where: "reports" | "changes") => void }) {
  const [open, setOpen] = useState<boolean | null>(null);
  const shown = open ?? live;
  const failed = tools.filter((t) => t.status === "error").length;
  const saved = tools.filter((t) => t.status === "done" && ARTIFACT_TOOLS[t.name]);
  return (
    <li className="ag-group">
      <button type="button" className="ag-group-head" aria-expanded={shown} onClick={() => setOpen(!shown)}>
        <i aria-hidden>{shown ? "▾" : "▸"}</i>
        <b>{tools.length} {tools.length === 1 ? "tool call" : "tool calls"}</b>
        <span>{toolSummary(tools)}</span>
        {failed > 0 && <em>{failed} failed</em>}
      </button>
      {shown && <ul>{tools.map((t) => <ToolRow key={t.id} item={t} />)}</ul>}
      {saved.map((t) => (
        <button key={t.id} type="button" className="ag-artifact" onClick={() => onArtifact(ARTIFACT_TOOLS[t.name].tab)}>
          <span>{ARTIFACT_TOOLS[t.name].label}</span><em>Open in Artifacts →</em>
        </button>
      ))}
    </li>
  );
}

const formatTokens = (n: number) => (n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(n));
const ago = (ms: number) => {
  const d = Math.max(0, (Date.now() - ms) / 1000);
  if (d < 90) return "just now";
  if (d < 5400) return `${Math.round(d / 60)} min ago`;
  if (d < 129600) return `${Math.round(d / 3600)} h ago`;
  return new Date(ms).toLocaleDateString(undefined, { day: "numeric", month: "short" });
};
const newId = () => (typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : String(Date.now()));

type Tab = "chat" | "artifacts";
type Usage = { input: number; output: number; cost: number };

/**
 * The agent dock: a chat with the analyst's own Claude Code or Codex beside the code, and the artifacts it
 * leaves behind (reports, names and comments). Binfera's tools are attached to the agent for each turn, so
 * what it reads and writes is the project this window shows.
 */
export default function AgentDock({ context, notes, tick, symbols, onBusy, onOpen, onClose }: {
  context: Omit<AgentContext, "path">; notes: Notes; tick: number; symbols: () => SymbolRef[];
  onBusy: (busy: boolean) => void; onOpen: (address: number) => void; onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>("chat");
  const [showHistory, setShowHistory] = useState(false);
  const [focus, setFocus] = useState<{ tab: "reports" | "changes"; n: number } | null>(null);
  const [agents, setAgents] = useState<AgentInfo[] | null>(null);
  const [pref, setPref] = useStored<AgentId>("agent-provider", "claude");
  // Per agent, so switching agents keeps each one's choice. Blank is the agent's own default.
  const [options, setOptions] = useStored<Partial<Record<AgentId, { model: string; effort: string }>>>("agent-options", {});
  const [history, setHistory] = useStored<Conversation[]>("agent-history:" + context.sha, []);
  const [items, setItems] = useState<Item[]>([]);
  const [text, setText] = useState("");
  const [busy, setBusyState] = useState(false);
  const [queue, setQueueState] = useState<string[]>([]);
  const [usage, setUsage] = useState<Usage>({ input: 0, output: 0, cost: 0 });
  const [started, setStarted] = useState(0);
  const [, tickClock] = useState(0);
  const [path, setPath] = useState<string | null>(null);
  const [artifactTick, bumpArtifacts] = useState(0);

  const run = useRef<{ handle: AgentRun | null; token: number }>({ handle: null, token: 0 });
  const sessions = useRef<Partial<Record<AgentId, string>>>({});
  const conv = useRef<{ id: string; provider: AgentId } | null>(null);
  const busyRef = useRef(false);
  const queueRef = useRef<string[]>([]);
  const stopped = useRef(false);
  const end = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const sendRef = useRef<(m: string, shown?: string) => void>(() => {});

  const setBusy = (b: boolean) => { busyRef.current = b; setBusyState(b); };
  const setQueue = (q: string[]) => { queueRef.current = q; setQueueState(q); };

  useEffect(() => { agent?.detect().then(setAgents).catch(() => setAgents([])); }, []);
  useEffect(() => { project?.path(context.sha).then(setPath).catch(() => setPath(null)); }, [context.sha]);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [items, tab, showHistory]);
  // The top bar shows a dot while a turn runs, also when this panel is hidden.
  useEffect(() => { onBusy(busy); return () => onBusy(false); }, [busy]); // eslint-disable-line react-hooks/exhaustive-deps
  // One second clock for "Working · 12s" while a turn runs.
  useEffect(() => { if (!busy) return; const id = setInterval(() => tickClock((n) => n + 1), 1000); return () => clearInterval(id); }, [busy]);
  // Opening another file, or leaving, stops the run rather than leaving it working unseen.
  useEffect(() => () => { run.current.handle?.cancel(); }, []);
  // Ctrl/Cmd L (from the workspace) puts the cursor in the message box.
  useEffect(() => {
    const h = () => { setTab("chat"); setShowHistory(false); setTimeout(() => input.current?.focus(), 0); };
    window.addEventListener("binfera-agent-focus", h);
    return () => window.removeEventListener("binfera-agent-focus", h);
  }, []);
  // The conversation is kept as it grows, so it can be read again and resumed.
  useEffect(() => {
    if (!items.length || !conv.current) return;
    const { id, provider } = conv.current;
    const first = items.find((i) => i.k === "user");
    setHistory(upsert(history, { id, provider, session: sessions.current[provider] ?? null, title: titleOf(first && first.k === "user" ? first.text : "Conversation"), updated: Date.now(), items: slim(items) }));
  }, [items]); // eslint-disable-line react-hooks/exhaustive-deps

  // The function open in the code view comes first when the analyst types @.
  const mentionable = useCallback(() => {
    const all = symbols();
    const at = context.address;
    if (at === null) return all;
    const open = all.find((s) => s.address === at) ?? { address: at, name: context.functionName ?? "0x" + at.toString(16) };
    return [open, ...all.filter((s) => s.address !== at)];
  }, [symbols, context.address, context.functionName]);

  const installed = useMemo(() => (agents ?? []).filter((a) => a.path), [agents]);
  const provider: AgentId | null = installed.find((a) => a.id === pref)?.id ?? installed[0]?.id ?? null;
  const name = installed.find((a) => a.id === provider)?.name ?? "agent";
  const choice = (provider && options[provider]) || { model: "", effort: "" };
  const setChoice = (patch: Partial<{ model: string; effort: string }>) => provider && setOptions({ ...options, [provider]: { ...choice, ...patch } });

  const send = (message: string, shown?: string) => {
    const msg = message.trim();
    if (!agent || !provider || !msg) return;
    // While the agent works, a message waits its turn.
    if (busyRef.current) { setQueue([...queueRef.current, msg]); setText(""); return; }
    // Another agent cannot resume this one's session, so it starts its own conversation; the
    // earlier one stays in the history.
    const newConversation = conv.current?.provider !== provider;
    if (newConversation) {
      conv.current = { id: newId(), provider };
      sessions.current = {};
      setUsage({ input: 0, output: 0, cost: 0 });
    }
    const prompt = buildPrompt(msg, { ...context, path }, !sessions.current[provider]);
    const token = ++run.current.token;
    stopped.current = false;
    setItems((prev) => [...(newConversation ? [] : prev), { k: "user", text: shown ?? msg }]);
    setText("");
    setBusy(true);
    setStarted(Date.now());
    setTab("chat");
    setShowHistory(false);
    // Asks once, from this click, to be told when a long run ends behind another window.
    try { if (typeof Notification !== "undefined" && Notification.permission === "default") void Notification.requestPermission(); } catch { /* not available here */ }
    const live = () => run.current.token === token;
    let failed = false;
    const handle = agent.run({ provider, prompt, session: sessions.current[provider] ?? null, model: choice.model, effort: choice.effort }, (e) => {
      if (!live()) return;
      if (e.kind === "session") sessions.current[provider] = e.id;
      else if (e.kind === "usage") setUsage((u) => ({ input: u.input + e.input, output: u.output + e.output, cost: u.cost + (e.cost ?? 0) }));
      else setItems((prev) => apply(prev, e));
      if (e.kind === "tool" && e.status === "done" && ARTIFACT_TOOLS[e.name]) bumpArtifacts((n) => n + 1);
      if (e.kind === "error") failed = true;
      if (e.kind !== "done" && e.kind !== "error") return;
      setBusy(false);
      if (e.kind === "done" && !stopped.current) {
        try { if (!document.hasFocus() && typeof Notification !== "undefined" && Notification.permission === "granted") new Notification("Binfera", { body: `${name} finished.` }); } catch { /* not available here */ }
      }
      // The next queued message goes out when a turn ends on its own, not after a stop or a failure.
      if (!stopped.current && !failed && queueRef.current.length) {
        const [next, ...rest] = queueRef.current;
        setQueue(rest);
        setTimeout(() => sendRef.current(next), 0);
      }
    });
    run.current.handle = handle;
    handle.started.catch((err) => { if (live()) { setItems((prev) => [...prev, { k: "error", text: String(err) }]); setBusy(false); } });
  };
  sendRef.current = send;

  const interrupt = () => { stopped.current = true; run.current.handle?.cancel(); };
  const reset = useCallback(() => {
    run.current.handle?.cancel(); run.current.token++; sessions.current = {}; conv.current = null;
    setItems([]); setBusy(false); setQueue([]); setUsage({ input: 0, output: 0, cost: 0 }); setShowHistory(false); setTab("chat");
  }, []);
  const resume = (c: Conversation) => {
    run.current.handle?.cancel(); run.current.token++;
    sessions.current = c.session ? { [c.provider]: c.session } : {};
    conv.current = { id: c.id, provider: c.provider };
    setPref(c.provider); setItems(c.items); setBusy(false); setQueue([]); setUsage({ input: 0, output: 0, cost: 0 }); setShowHistory(false); setTab("chat");
  };
  const showArtifact = (where: "reports" | "changes") => { setFocus({ tab: where, n: (focus?.n ?? 0) + 1 }); setTab("artifacts"); };

  const slash: SlashItem[] = useMemo(() => [
    { id: "new", title: "New chat", about: "Forget this conversation", run: () => { reset(); } },
    { id: "history", title: "History", about: "Earlier conversations about this file", run: () => { setShowHistory(true); } },
    ...[FULL, ...GROUPS.flatMap((g) => g.items)].map((w) => ({ id: w.id, title: w.title, about: `${w.about} (${EFFECTS[w.effect].label.toLowerCase()})`, run: () => request(w, context.name) })),
  ], [context.name, reset]);

  const blocksNow = blocks(items);
  const lastUser = items.map((i) => i.k).lastIndexOf("user");
  const empty = items.length === 0;
  const calls = callsThisTurn(items);
  const secs = Math.max(0, Math.round((Date.now() - started) / 1000));

  return (
    <div className="ag">
      <header className="ag-head">
        <div className="ag-tabs" role="tablist">
          <button role="tab" aria-selected={tab === "chat"} className={tab === "chat" ? "on" : ""} onClick={() => { setTab("chat"); setShowHistory(false); }}>Chat</button>
          <button role="tab" aria-selected={tab === "artifacts"} className={tab === "artifacts" ? "on" : ""} onClick={() => setTab("artifacts")}>Artifacts</button>
        </div>
        <span className="ag-gap" />
        {tab === "chat" && history.length > 0 && <button type="button" className={"ag-quiet" + (showHistory ? " on" : "")} onClick={() => setShowHistory(!showHistory)} title="Earlier conversations about this file">History</button>}
        {tab === "chat" && !empty && <button type="button" className="ag-quiet" onClick={reset} title="Start a new conversation">New chat</button>}
        <button type="button" className="ag-quiet ag-x" onClick={onClose} aria-label="Hide the agent panel">✕</button>
      </header>

      <div className="ag-body" hidden={tab !== "chat"}>
        <div className="ag-scroll" role="log" aria-live="polite">
          {showHistory ? (
            <div className="ag-history">
              <h4>Conversations about this file</h4>
              {history.length === 0 && <p className="ag-empty">None yet.</p>}
              <ul className="ag-list">
                {history.map((c) => (
                  <li key={c.id} className="has-act">
                    <button type="button" className="ag-hist" onClick={() => resume(c)}>
                      <b>{c.title}</b>
                      <span>{AGENT_NAMES[c.provider]} · {c.items.filter((i) => i.k === "user").length} messages · {c.id === conv.current?.id ? "current" : ago(c.updated)}</span>
                    </button>
                    <button type="button" className="ag-link" aria-label="Delete this conversation" onClick={() => setHistory(history.filter((h) => h.id !== c.id))}>Delete</button>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <>
              {agents === null && <p className="ag-empty">Looking for installed agents…</p>}
              {agents && !provider && (
                <div className="ag-empty">
                  <p><b>No agent found.</b> Install one of the supported agents and sign in from a terminal, then reopen this panel.</p>
                  <p><code>claude auth login</code>  <code>codex login</code></p>
                  <p><code>vibe --setup</code></p>
                </div>
              )}
              {provider && empty && (
                <div className="ag-hello">
                  <h3>{context.name}</h3>
                  <p>Ask {name} about this file. It reads the analysis through Binfera, and whatever it saves shows up in Artifacts, where every run can be undone.</p>
                  <button type="button" className="ag-suggest" onClick={() => send(TRIAGE, "Triage this binary")}><b>Triage this binary</b><span>What it is, what it does, how worried to be</span></button>
                  <p className="ag-tips"><kbd>/</kbd> commands and requests · <kbd>@</kbd> a function · <kbd>Esc</kbd> stops · type while it works to queue</p>
                </div>
              )}
              <ul className="ag-items">
                {blocksNow.map((b, n) => {
                  if (b.k === "tools") return <ToolGroup key={b.index} tools={b.tools} live={busy && n === blocksNow.length - 1} onArtifact={showArtifact} />;
                  const item = b.item;
                  if (item.k === "user") {
                    const canRetry = b.index === lastUser || items[b.index + 1]?.k === "error";
                    return (
                      <li key={b.index} className="ag-user">
                        <span>{item.text}</span>
                        {canRetry && !busy && <button type="button" className="ag-act" onClick={() => send(item.text)} title="Ask again">Retry</button>}
                      </li>
                    );
                  }
                  if (item.k === "error") return <li key={b.index} className="ag-error" role="alert">{item.text}</li>;
                  return (
                    <li key={b.index} className="ag-text">
                      <Markdown text={item.text} onAddress={onOpen} />
                      <button type="button" className="ag-act" onClick={() => navigator.clipboard?.writeText(item.text).catch(() => {})}>Copy</button>
                    </li>
                  );
                })}
              </ul>
              {busy && <p className="ag-working" aria-hidden><i />Working · {secs}s{calls > 0 && ` · ${calls} tool ${calls === 1 ? "call" : "calls"}`}<kbd>Esc</kbd> to stop</p>}
              <div ref={end} />
            </>
          )}
        </div>

        {provider && !empty && conv.current && conv.current.provider !== provider && (
          <p className="ag-switch">{AGENT_NAMES[conv.current.provider]} is not available, so your next message starts a new chat with {name}. This one stays in the history.</p>
        )}
        <Composer
          text={text} onText={setText} onSend={(t) => send(t)} onInterrupt={interrupt} busy={busy}
          disabled={!provider} placeholder={provider ? (busy ? "Type to queue the next message…" : `Ask ${name} about this binary…`) : "No agent installed"}
          queue={queue} onUnqueue={(i) => setQueue(queue.filter((_, n) => n !== i))} symbols={mentionable} slash={slash} inputRef={input}
          bar={
            <div className="ag-bar">
              {provider && <Picker agents={installed} provider={provider} onProvider={(p) => { if (p === provider) return; if (!empty) reset(); setPref(p); }} model={choice.model} effort={choice.effort} onModel={(model) => setChoice({ model })} onEffort={(effort) => setChoice({ effort })} switchStartsNewChat={!empty} disabled={busy} />}
              <span className="ag-gap" />
              {busy && <button type="button" className="ag-send stop" onClick={interrupt} aria-label="Stop"><i /></button>}
              <button type="submit" className="ag-send" disabled={!provider || !text.trim()} aria-label={busy ? "Queue this message" : "Send"}><svg viewBox="0 0 24 24" aria-hidden><path d="M12 19V5M5 12l7-7 7 7" /></svg></button>
            </div>
          }
        />
        <p className="ag-status" aria-live="off">
          <span />
          {(usage.input > 0 || usage.output > 0) && <span title="Tokens read and written in this conversation">↑ {formatTokens(usage.input)} ↓ {formatTokens(usage.output)}{usage.cost > 0 && ` · $${usage.cost.toFixed(2)}`}</span>}
        </p>
      </div>

      <div className="ag-body" hidden={tab !== "artifacts"}>
        <Artifacts sha={context.sha} notes={notes} tick={tick + artifactTick} focus={focus} onOpen={onOpen} />
      </div>
    </div>
  );
}
