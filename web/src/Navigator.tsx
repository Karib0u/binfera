import { useEffect, useMemo, useRef, useState } from "react";
import type { Analysis } from "./types";

const BINS = 2400;
// What a stretch of the file holds, in drawing order of precedence.
const DATA = 1, PAD = 2, CODE = 3, STR = 4, IMP = 5;
const hex = (n: number) => "0x" + n.toString(16);

interface Seg { name: string; va: number; span: number; exec: boolean; from: number; to: number }

/** The whole file in one strip, like IDA's navigator: sections side by side, coloured by what is in them, with a marker where you are. */
export default function Navigator({ a, position, onNavigate, compact, range }: { a: Analysis; position: number | null; onNavigate: (va: number) => void; compact?: boolean; range?: { from: number; to: number } | null }) {
  const image = a.image;
  const box = useRef<HTMLDivElement>(null), canvas = useRef<HTMLCanvasElement>(null);
  const [width, setWidth] = useState(0);
  const [theme, setTheme] = useState(0);
  const [hover, setHover] = useState<{ x: number; text: string; kind: number } | null>(null);

  const segs = useMemo<Seg[]>(() => {
    if (!image) return [];
    const secs = image.sections.filter((s) => s.size > 0 && image.vaToOff(s.va) !== null).sort((x, y) => x.va - y.va);
    const total = secs.reduce((n, s) => n + s.size, 0);
    if (!secs.length || !total) return [];
    // A tiny section (the resources, a stub) still gets a visible slice.
    const weight = secs.map((s) => Math.max(s.size, total * 0.015));
    const sum = weight.reduce((n, w) => n + w, 0);
    let at = 0;
    return secs.map((s, i) => {
      const from = at / sum;
      at += weight[i];
      return { name: s.name, va: s.va, span: s.size, exec: s.perms.endsWith("x"), from, to: at / sum };
    });
  }, [image]);

  const unitOf = (va: number) => {
    for (const s of segs) if (va >= s.va && va < s.va + s.span) return s.from + ((va - s.va) / s.span) * (s.to - s.from);
    return null;
  };

  const bins = useMemo(() => {
    const b = new Uint8Array(BINS);
    if (!image || !segs.length) return b;
    for (const s of segs) b.fill(s.exec ? PAD : DATA, Math.floor(s.from * BINS), Math.max(Math.floor(s.from * BINS) + 1, Math.ceil(s.to * BINS)));
    const mark = (va: number, len: number, kind: number) => {
      const u0 = unitOf(va), u1 = unitOf(va + Math.max(len - 1, 0));
      if (u0 === null) return;
      for (let i = Math.floor(u0 * BINS); i <= Math.floor((u1 ?? u0) * BINS) && i < BINS; i++) b[i] = kind;
    };
    for (const x of a.strings) mark(x.a, x.s.length * (x.w ? 2 : 1), STR);
    for (const i of image.imports) if (i.va) mark(i.va, image.ptrSize, IMP);
    if (a.done) for (const f of a.functions.values()) for (const [at, bytesHex] of f.asm ?? []) mark(at, bytesHex.replace(/\s/g, "").length / 2, CODE);
    return b;
  }, [image, segs, a.done, a.functions, a.strings]);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => setWidth(el.clientWidth);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    const mq = matchMedia("(prefers-color-scheme: dark)"), onTheme = () => setTheme((n) => n + 1);
    mq.addEventListener("change", onTheme);
    window.addEventListener("binfera-theme", onTheme);
    return () => { ro.disconnect(); mq.removeEventListener("change", onTheme); window.removeEventListener("binfera-theme", onTheme); };
  }, [segs.length]);

  useEffect(() => {
    const c = canvas.current;
    if (!c || !width) return;
    const dpr = window.devicePixelRatio || 1, h = 16;
    c.width = Math.round(width * dpr); c.height = Math.round(h * dpr);
    const g = c.getContext("2d")!;
    g.scale(dpr, dpr);
    const css = getComputedStyle(document.documentElement);
    const color = (v: string) => css.getPropertyValue(v).trim() || "#888";
    const palette: Record<number, string> = {
      0: "transparent", [DATA]: color("--line"), [PAD]: `color-mix(in srgb, ${color("--c-fn")} 22%, ${color("--panel")})`,
      [CODE]: color("--c-fn"), [STR]: color("--c-str"), [IMP]: color("--c-num"),
    };
    g.clearRect(0, 0, width, h);
    const w = width / BINS;
    for (let i = 0; i < BINS; i++) {
      if (!bins[i]) continue;
      g.fillStyle = palette[bins[i]];
      g.fillRect(i * w, 0, Math.ceil(w) + 0.5, h);
    }
  }, [bins, width, theme]);

  if (!segs.length) return null;
  const at = (clientX: number) => {
    const r = box.current!.getBoundingClientRect();
    return Math.min(1, Math.max(0, (clientX - r.left) / r.width));
  };
  const vaAt = (u: number) => {
    const s = segs.find((x) => u >= x.from && u <= x.to) ?? segs[segs.length - 1];
    return { s, va: Math.floor(s.va + Math.min(1, Math.max(0, (u - s.from) / (s.to - s.from))) * (s.span - 1)) };
  };
  const pos = position === null ? null : unitOf(position);
  const r0 = range ? unitOf(range.from) : null, r1 = range ? unitOf(range.to) : null;
  const kindAt = (u: number) => bins[Math.min(BINS - 1, Math.floor(u * BINS))];
  const KIND_NAME = ["empty", "data", "not disassembled", "code", "string", "import slot"];
  /** The legend, in the readout: what the colour under the pointer means, where it is, and its file offset. */
  const readout = (u: number) => {
    const { s, va } = vaAt(u), kind = kindAt(u), off = image?.vaToOff(va);
    return { x: u * 100, kind, text: [hex(va), s.name, KIND_NAME[kind] ?? "", off != null ? "file offset " + hex(off) : ""].filter(Boolean).join(" · ") };
  };

  return (
    <div className={"nav" + (compact ? " compact" : "")} ref={box} role="slider" tabIndex={0} aria-label="File map" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round((pos ?? 0) * 100)} aria-valuetext={position === null ? "no position" : hex(position)}
      onClick={(e) => onNavigate(vaAt(at(e.clientX)).va)}
      onKeyDown={(e) => {
        if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
        e.preventDefault();
        onNavigate(vaAt(Math.min(1, Math.max(0, (pos ?? 0) + (e.key === "ArrowRight" ? 0.01 : -0.01)))).va);
      }}
      onMouseMove={(e) => setHover(readout(at(e.clientX)))}
      onMouseLeave={() => setHover(null)} title={a.done ? "File map: the whole file, left to right. Click to jump." : "File map. Code coverage fills in as decompilation finishes."}>
      <canvas ref={canvas} style={{ width: "100%", height: "100%" }} />
      {segs.map((s) => (
        <div className="nav-sec" key={s.name + s.va} style={{ left: `${s.from * 100}%`, width: `${(s.to - s.from) * 100}%` }}>
          {(s.to - s.from) > 0.05 && <span>{s.name}</span>}
        </div>
      ))}
      {r0 !== null && r1 !== null && <i className="nav-range" style={{ left: `${r0 * 100}%`, width: `${Math.max(r1 - r0, 0) * 100}%` }} />}
      {pos !== null && <i className="nav-cur" style={{ left: `${pos * 100}%` }} />}
      {hover && <div className="nav-tip" style={{ left: `${Math.min(hover.x, 72)}%` }}><i className={"nav-swatch k" + hover.kind} aria-hidden />{hover.text}</div>}
    </div>
  );
}
