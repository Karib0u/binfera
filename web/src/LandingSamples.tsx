import { useEffect, useRef, useState } from "react";
import type { DemoSample } from "./demos";

/** A sample as the roster shows it: one of the packed malware samples, or the bundled harmless program. */
interface Fighter {
  id: string;
  name: string;
  short: string;
  kind: string;
  tags: string[];
  note: string;
  /** Seeds the sprite; the harmless program has the puffin instead. */
  sha256?: string;
  sample?: DemoSample;
}

/** Names that fit under a tile. */
const SHORT: Record<string, string> = {
  stuxnet: "Stuxnet", "3cx": "3CX", rustbucket: "RustBucket", cloudsnooper: "Snooper",
};

const PUFFIN: Fighter = {
  id: "harmless", name: "The Puffin", short: "Puffin", kind: "Harmless practice program",
  tags: ["Windows", "PE", "x64", "Rust"],
  note: "A small program bundled with Binfera. Start here if you'd rather not open real malware.",
};

const fighter = (s: DemoSample): Fighter => ({ id: s.id, name: s.name, short: SHORT[s.id] ?? s.name, kind: s.kind, tags: s.tags, note: s.note, sha256: s.sha256, sample: s });

/** A symmetric 9x9 creature drawn from the file's hash, so each sample always looks the same. */
function Sprite({ who }: { who: Fighter }) {
  if (!who.sha256) return <img src="/mark.png" alt="" />;
  const bits = [...who.sha256].flatMap((c) => { const n = parseInt(c, 16); return [8, 4, 2, 1].map((b) => n & b); });
  const cells: React.ReactNode[] = [];
  const dark = "#141211";
  for (let y = 0; y < 9; y++) for (let x = 0; x < 5; x++) {
    const on = bits[y * 5 + x];
    const core = y >= 2 && y <= 5 && x >= 2;
    if (!core && !(x === 0 ? on && bits[64 + y] : on)) continue;
    const eye = y === 3 && x === 2;
    const mouth = y === 5 && (bits[60] ? x === 3 : x === 4);
    const fill = eye || mouth ? dark : "currentColor";
    cells.push(<rect key={`${x},${y}`} x={x} y={y} width="1.02" height="1.02" fill={fill} />);
    if (x !== 4) cells.push(<rect key={`${8 - x},${y}`} x={8 - x} y={y} width="1.02" height="1.02" fill={fill} />);
  }
  return <svg viewBox="0 0 9 9" shapeRendering="crispEdges" aria-hidden>{cells}</svg>;
}

// A mystery creature with a question mark cut out of its face.
const MYSTERY_PIXELS = [
  ".##...##.",
  ".#######.",
  ".##...##.",
  "#####.###",
  "####..###",
  ".###.###.",
  ".#######.",
  ".###.###.",
  "..##.##..",
];

function MysterySprite() {
  return <span className="lp-mystery" aria-hidden>{MYSTERY_PIXELS.flatMap((row, y) => Array.from(row, (pixel, x) => (
    <span key={`${x},${y}`} data-filled={pixel === "#" || undefined} style={{ "--pixel-x": x, "--pixel-y": y } as React.CSSProperties} />
  )))}</span>;
}

/** The character select: pick a sample on the roster, read what it is, open it. */
export default function LandingSamples({ samples, loading, onSample, onHarmless }: {
  samples: DemoSample[];
  loading: string | null;
  onSample: (s: DemoSample) => void;
  onHarmless: () => void;
}) {
  const [current, setCurrent] = useState(0);
  const [rolling, setRolling] = useState<number | null>(null);
  const roster = useRef<HTMLDivElement>(null);
  const spinTimer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(spinTimer.current), []);

  // The site can be built without the malware samples; the harmless program is always there.
  if (!samples.length) return (
    <section className="lp-section">
      <div className="lp-head">
        <h2>No file? Try a <span className="lp-o">harmless demo</span>.</h2>
        <p>A small program bundled with Binfera.</p>
      </div>
      <button type="button" className="lp-cta" onClick={onHarmless} disabled={loading !== null}>{loading === "harmless" ? "Loading…" : "Open the demo →"}</button>
    </section>
  );

  const fighters = [...samples.map(fighter), PUFFIN];
  const who = fighters[Math.min(current, fighters.length - 1)];
  const spinning = rolling !== null;
  const busy = spinning || loading !== null;
  const start = (f: Fighter) => { if (busy) return; if (f.sample) onSample(f.sample); else onHarmless(); };
  const [platform, format, arch, ...rest] = who.tags;

  const move = (to: number) => {
    setCurrent(to);
    (roster.current?.children[to] as HTMLElement | undefined)?.focus();
  };
  const onKey = (e: React.KeyboardEvent) => {
    if (spinning) return;
    const tiles = [...(roster.current?.children ?? [])] as HTMLElement[];
    const at = tiles.indexOf(document.activeElement as HTMLElement);
    if (at < 0 || at >= fighters.length) return;
    const cols = tiles.filter((t) => t.offsetTop === tiles[0].offsetTop).length;
    const step = ({ ArrowLeft: -1, ArrowRight: 1, ArrowUp: -cols, ArrowDown: cols } as Record<string, number>)[e.key];
    if (step) {
      e.preventDefault();
      if (at + step >= 0 && at + step < fighters.length) move(at + step);
    } else if (e.key === "Enter") {
      e.preventDefault();
      start(fighters[at]);
    }
  };
  const random = () => {
    if (busy) return;
    const choices = samples.map((_, i) => i).filter(i => i !== current);
    if (!choices.length) return;
    const winner = choices[Math.floor(Math.random() * choices.length)];
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setCurrent(winner);
      return;
    }

    const count = samples.length;
    const from = Math.min(current, count - 1);
    const steps = count + (winner - from + count) % count;
    let step = 0;
    const advance = () => {
      step += 1;
      if (step === steps) {
        setCurrent(winner);
        setRolling(null);
        return;
      }
      setRolling((from + step) % count);
      spinTimer.current = window.setTimeout(advance, 45 + 240 * (step / steps) ** 3);
    };
    advance();
  };

  return (
    <section className="lp-section" aria-labelledby="lp-pick-title">
      <div className="lp-head">
        <h2 id="lp-pick-title">No file? Choose your <span className="lp-o">malware</span>.</h2>
        <p>Real samples, stored encoded and only read, never run. The puffin is harmless.</p>
      </div>
      <div className="lp-cabinet lp-select">
        <div className="lp-roster-panel">
          <div className="lp-roster" ref={roster} role="radiogroup" aria-labelledby="lp-pick-title" data-spinning={spinning || undefined} onKeyDown={onKey}>
            {fighters.map((f, i) => (
              <button key={f.id} type="button" role="radio" className="lp-tile" aria-checked={f === who} aria-disabled={spinning || undefined}
                data-rolling={rolling === i || undefined} tabIndex={f === who ? 0 : -1} title={f.name} onClick={() => { if (!spinning) setCurrent(i); }}>
                <span className="lp-sp"><Sprite who={f} /></span>
                <span className="lp-nm">{f.short}</span>
              </button>
            ))}
          </div>
          <button type="button" className="lp-tile lp-random" onClick={random} aria-disabled={busy}>
            <span className="lp-sp"><MysterySprite /></span>
            <span className="lp-nm">Random sample</span>
          </button>
        </div>

        <div className="lp-spot">
          <div className="lp-stage"><div className="lp-sprite"><Sprite who={who} /></div></div>
          <div className="lp-bio">
            <h3 aria-live="polite">{who.name}</h3>
            <p className="lp-kind">{who.kind}</p>
            <dl className="lp-stats">
              <div><dt>Platform</dt><dd>{platform}</dd></div>
              <div><dt>Format</dt><dd>{format}</dd></div>
              <div><dt>Arch</dt><dd>{arch}</dd></div>
              <div><dt>{rest[0] === "Driver" ? "Type" : "Language"}</dt><dd>{rest.join(", ")}</dd></div>
            </dl>
            <p className="lp-look"><b>What to look for</b>{who.note}</p>
            <button type="button" className="lp-start" onClick={() => start(who)} disabled={busy}>{loading === who.id ? "Loading…" : `Analyze ${who.short} →`}</button>
          </div>
        </div>
      </div>
    </section>
  );
}
