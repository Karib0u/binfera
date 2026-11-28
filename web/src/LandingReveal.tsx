import { useEffect, useRef, useState } from "react";
import { REVEAL } from "./revealSample";

/** The three ways the page shows one function: what the file holds, what the CPU runs, what it means. */
const STAGES = ["Bytes", "Assembly", "C"] as const;
type Stage = 0 | 1 | 2;
/** When each stage takes over, in ms after the panel comes into view. */
const AT = [0, 1300, 2700];

const hex8 = (n: number) => n.toString(16).padStart(8, "0");
const start = REVEAL.asm[0][0];
const allBytes = REVEAL.asm.flatMap(([, h]) => h.match(/../g)!);
const PER_ROW = 8;
const ROWS = Array.from({ length: Math.ceil(allBytes.length / PER_ROW) }, (_, i) => {
  const row = allBytes.slice(i * PER_ROW, (i + 1) * PER_ROW);
  const ascii = row.map((b) => { const c = parseInt(b, 16); return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : "."; }).join("");
  return { addr: hex8(start + i * PER_ROW), bytes: row.join(" ").padEnd(PER_ROW * 3 - 1), ascii };
});
const C_LINES = REVEAL.c.split("\n");

const KEYWORDS = new Set(["if", "else", "do", "while", "for", "return", "break", "continue"]);
const TYPES = new Set(["unsigned", "int", "char", "void", "bool", "short", "long", "size_t", "wchar_t"]);
const TOKEN = /"(?:\\.|[^"\\])*"|\b0x[0-9a-fA-F]+\b|\b\d+\b|[A-Za-z_]\w*/g;

/** Just enough colour to read as code: keywords, types, calls, literals. */
function paintC(line: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  let last = 0;
  for (const m of line.matchAll(TOKEN)) {
    const w = m[0], i = m.index!;
    if (i > last) out.push(line.slice(last, i));
    const cls = w.startsWith('"') ? "tk-s"
      : /^\d|^0x/.test(w) ? "tk-n"
      : KEYWORDS.has(w) ? "tk-k"
      : TYPES.has(w) || /^[A-Z][A-Z0-9_]+$/.test(w) ? "tk-t"
      : line[i + w.length] === "(" ? (w.includes("_") && /^[a-z0-9]+_[A-Z]/.test(w) ? "tk-f lp-rv-api" : "tk-f")
      : null;
    out.push(cls ? <span key={i} className={cls}>{w}</span> : w);
    last = i + w.length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}

function paintAsm(text: string): React.ReactNode[] {
  const [op, ...rest] = text.split(" ");
  const args = rest.join(" ");
  return [<span key="op" className="tk-k">{op.padEnd(6)}</span>, " ", ...args.split(/(\b(?:0x)?[0-9a-fA-F]+h?\b)/).map((p, i) =>
    i % 2 && /^(?:0x[0-9a-f]+|[0-9][0-9a-f]*h|\d+)$/i.test(p) ? <span key={i} className="tk-n">{p}</span> : p)];
}

/** One line of a stage, fading in after the ones above it. */
const Line = ({ i, children }: { i: number; children: React.ReactNode }) => (
  <span className="lp-rv-line" style={{ "--i": i } as React.CSSProperties}>{children}</span>
);

const reduced = () => typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

/**
 * The hero's demonstration: one real WannaCry function shown as raw bytes, then assembly, then C,
 * which is what the page promises. It plays once when it comes into view and ends on the C; the stage
 * buttons show any of the three again.
 */
export default function LandingReveal({ onOpen, busy }: { onOpen: () => void; busy: boolean }) {
  const [stage, setStage] = useState<Stage>(() => (reduced() ? 2 : 0));
  const [play, setPlay] = useState(0);
  const [visible, setVisible] = useState(false);
  const [auto, setAuto] = useState(false);
  const box = useRef<HTMLElement>(null);
  const timers = useRef<number[]>([]);
  const stop = () => { timers.current.forEach(clearTimeout); timers.current = []; };

  useEffect(() => {
    const el = box.current;
    if (!el || typeof IntersectionObserver !== "function") return setVisible(true);
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setVisible(true); io.disconnect(); } }, { threshold: 0.35 });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!visible || reduced()) return;
    stop();
    setStage(0);
    setAuto(true);
    timers.current = AT.slice(1).map((ms, i) => window.setTimeout(() => {
      setStage((i + 1) as Stage);
      if (i === AT.length - 2) setAuto(false);
    }, ms));
    return stop;
  }, [visible, play]);

  const choose = (s: Stage) => { stop(); setAuto(false); setStage(s); };

  return (
    <figure ref={box} className="lp-reveal" aria-label={`${REVEAL.name} from ${REVEAL.file}, shown as bytes, assembly and decompiled C`}>
      <div className="lp-rv-bar">
        <span className="lp-rv-title"><b>{REVEAL.file}</b><span aria-hidden> / </span>{REVEAL.name}</span>
        <div className="lp-rv-stages" role="tablist" aria-label="View">
          {STAGES.map((name, i) => (
            <button key={name} type="button" role="tab" aria-selected={stage === i} onClick={() => choose(i as Stage)}>
              {name}
              {auto && stage === i && i < 2 && <i className="lp-rv-progress" style={{ animationDuration: `${AT[i + 1] - AT[i]}ms` }} />}
            </button>
          ))}
        </div>
      </div>

      <pre key={`${stage}-${play}`} className="lp-rv-code" data-stage={STAGES[stage]} tabIndex={0}>
        {stage === 0 && ROWS.map((r, i) => (
          <Line key={i} i={i}><span className="tk-c">{r.addr}</span>  {r.bytes}  <span className="tk-c">{r.ascii}</span></Line>
        ))}
        {stage === 1 && REVEAL.asm.map(([addr, bytes, text], i) => (
          <Line key={addr} i={i}><span className="tk-c">{hex8(addr)}</span>  <span className="lp-rv-dim">{bytes.padEnd(12)}</span>  {paintAsm(text)}</Line>
        ))}
        {stage === 2 && C_LINES.map((l, i) => <Line key={i} i={i}>{paintC(l)}</Line>)}
      </pre>

      <figcaption className="lp-rv-foot">
        <span className="lp-rv-caption">Real output for WannaCry's mutex check, decompiled in your browser.</span>
        <span className="lp-rv-actions">
          {/* Always laid out, so the panel keeps its size when the button appears. */}
          {!reduced() && <button type="button" onClick={() => setPlay((n) => n + 1)} hidden={stage !== 2} className="lp-rv-replay">Replay</button>}
          <button type="button" className="lp-rv-open" onClick={onOpen} disabled={busy}>{busy ? "Opening…" : "Open it →"}</button>
        </span>
      </figcaption>
    </figure>
  );
}
