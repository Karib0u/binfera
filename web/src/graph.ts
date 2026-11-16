import type { FunctionGraph, Arch, AsmRow } from "./types";
// The Graph view lays out structured recovery blocks from the engine. IL and extra functions
// without a recovery graph fall back to the instruction listing. Layout runs in the page.

export type { Arch, AsmRow } from "./types";

/**
 * An address in an instruction's operands: x86 listings print `00401000h`, AArch64 ones `0x401000`.
 * An immediate (`#0x10`) is not one. The address is group 1 or group 2; see `asmAddress`.
 */
export const ADDR_IN_ASM = /(?<![#\w.])(?:0x([0-9a-f]{4,16})\b|\b([0-9A-F]{6,16})h\b)/g;
export const asmAddress = (m: RegExpMatchArray) => parseInt(m[1] ?? m[2], 16);
export type EdgeKind = "true" | "false" | "jump";

/**
 * The string to note beside an address operand: a listed one, or else the text at an address the instruction
 * takes (`push 41EA50h`, `lea eax,[41EA50h]`). One it loads from (`mov eax,ds:[41EA50h]`) holds a value, whatever its bytes look like.
 */
export function operandNote(text: string, index: number, va: number, strAt: (va: number) => string | undefined, textAt?: (va: number) => string | undefined) {
  const listed = strAt(va);
  if (listed !== undefined) return listed;
  const loaded = text.lastIndexOf("[", index) > text.lastIndexOf("]", index) && !text.startsWith("lea ");
  return loaded ? undefined : textAt?.(va);
}

export interface Block {
  id: number;
  addr: number;
  rows: AsmRow[];
}
export interface CfgEdge {
  from: number;
  to: number;
  kind: EdgeKind;
}
export interface Cfg {
  blocks: Block[];
  edges: CfgEdge[];
}

const DIRECT = /^(?:(?:short|near ptr|far ptr)\s+)?([0-9A-F]{2,16})h$/i;

/** How an instruction leaves its block. `target` is a direct branch or call destination. */
export type Flow = { kind: "jump" | "cond" | "ret" | "halt" | "call" | "none"; target?: number; delay?: boolean; likely?: boolean; fallthrough?: number };

const split = (text: string): [string, string] => {
  const sp = text.indexOf(" ");
  return sp < 0 ? [text.toLowerCase(), ""] : [text.slice(0, sp).toLowerCase(), text.slice(sp + 1).trim()];
};

function x86Flow(text: string): Flow {
  const [m, ops] = split(text);
  const d = DIRECT.exec(ops);
  const target = d ? parseInt(d[1], 16) : undefined;
  if (m.startsWith("ret") || m === "iret" || m === "iretd" || m === "iretq" || m === "sysret") return { kind: "ret" };
  if (m === "hlt" || m === "ud2" || m === "int3" || m === "ud1") return { kind: "halt" };
  if (m === "jmp") return { kind: "jump", target };
  if (m.startsWith("j") || m.startsWith("loop")) return { kind: "cond", target };
  if (m === "call") return { kind: "call", target };
  return { kind: "none" };
}

/** CIL branches name their target as an `IL_xxxx` label, and a row's address is its IL offset. */
function cilFlow(text: string): Flow {
  const [m, ops] = split(text);
  const label = /^IL_([0-9a-f]+)$/.exec(ops);
  const target = label ? parseInt(label[1], 16) : undefined;
  if (m === "ret" || m === "endfinally" || m === "endfilter") return { kind: "ret" };
  if (m === "throw" || m === "rethrow") return { kind: "halt" };
  if (m === "br" || m === "br.s" || m === "leave" || m === "leave.s") return { kind: "jump", target };
  if (/^(?:b(?:rtrue|rfalse|eq|ge|gt|le|lt|ne\.un|ge\.un|gt\.un|le\.un|lt\.un)|brtrue|brfalse)(?:\.s)?$/.test(m)) return { kind: "cond", target };
  return { kind: "none" };
}

/** Sign-extends the `bits`-wide field of `w` at `shift`, in instructions (4 bytes each). */
const offset = (w: number, shift: number, bits: number) => (((w >>> shift) & ((1 << bits) - 1)) << (32 - bits)) >> (32 - bits) << 2;

/** AArch64 branches, decoded from the instruction word rather than parsed from the text. */
function a64Flow(address: number, hex: string): Flow {
  const b = hex.match(/../g)!.map((x) => parseInt(x, 16));
  const w = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  if ((w & 0xfc000000) >>> 0 === 0x14000000) return { kind: "jump", target: address + offset(w, 0, 26) }; // B
  if ((w & 0xfc000000) >>> 0 === 0x94000000) return { kind: "call", target: address + offset(w, 0, 26) }; // BL
  if ((w & 0xff000010) >>> 0 === 0x54000000) { // B.cond; AL and NV always branch
    const target = address + offset(w, 5, 19);
    return { kind: (w & 0xf) >= 0xe ? "jump" : "cond", target };
  }
  if ((w & 0x7e000000) >>> 0 === 0x34000000) return { kind: "cond", target: address + offset(w, 5, 19) }; // CBZ, CBNZ
  if ((w & 0x7e000000) >>> 0 === 0x36000000) return { kind: "cond", target: address + offset(w, 5, 14) }; // TBZ, TBNZ
  if ((w & 0xfffffc1f) >>> 0 === 0xd65f0000 || w === 0xd65f0bff || w === 0xd65f0fff) return { kind: "ret" }; // RET, RETAA, RETAB
  if ((w & 0xfffffc1f) >>> 0 === 0xd61f0000) return { kind: "jump" }; // BR
  if ((w & 0xffe0001f) >>> 0 === 0xd4200000 || (w & 0xffff0000) >>> 0 === 0) return { kind: "halt" }; // BRK, UDF
  return { kind: "none" };
}

/** Control flow of one listing row. */
export function rowFlow([address, hex, text]: AsmRow, arch: Arch): Flow {
  if (arch === "cil") return cilFlow(text);
  if (arch === "arm" || arch === "mips" || arch === "mipsel") return riscFlow(text, arch);
  return arch === "aarch64" && hex.length === 8 ? a64Flow(address, hex) : x86Flow(text);
}

function riscFlow(text: string, arch: Arch): Flow {
  const [mnemonic, ops] = split(text);
  const m = mnemonic.replace(/\.w$/, "");
  const match = /(?:#)?0x([0-9a-f]+)$/.exec(ops);
  const target = match ? parseInt(match[1], 16) : undefined;
  if (arch === "arm") {
    const transfer = /^(bx|pop|ldm(?:ia|fd)?|mov|ldr)(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)?$/.exec(m);
    if (transfer) {
      const base = transfer[1];
      const pcWrite = base === "bx" || (base === "pop" || base.startsWith("ldm") ? /\bpc\b/.test(ops) : /^pc,/.test(ops));
      if (pcWrite) {
        const returns = base === "bx" && ops === "lr" || base === "pop" || base.startsWith("ldm") || base === "mov" && ops === "pc, lr";
        return { kind: transfer[2] ? "cond" : returns ? "ret" : "jump", target };
      }
    }
    if (/^b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)$/.test(m) || m === "cbz" || m === "cbnz") return { kind: "cond", target };
    if (/^blx?(?:eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)?$/.test(m)) return { kind: "call", target };
    if (m === "b" || m === "bx" || m === "tbb" || m === "tbh") return { kind: "jump", target };
    if (m === "bkpt" || m === "udf") return { kind: "halt" };
  } else {
    if (m === "jr" && ops === "$ra") return { kind: "ret", delay: true };
    if (["jal", "jalr", "bal", "bgezal", "bltzal", "bgezall", "bltzall"].includes(m)) return { kind: "call", target, delay: true };
    if (["b", "j", "jr"].includes(m)) return { kind: "jump", target, delay: true };
    if (/^b(?:eq|ne|gez|gtz|lez|ltz|c[012])/.test(m)) return { kind: "cond", target, delay: true, likely: m.endsWith("l") };
    if (m === "break") return { kind: "halt" };
  }
  return { kind: "none" };
}

/** Splits a function's listing into basic blocks. Branch targets outside the listing (tail calls) get no edge. */
/**
 * The instructions behind each C line, including those the decompiler folds away. Its markup names only the
 * operations that survive, so a call's line names the `call` and not the pushes before it. An instruction with
 * no line joins the next one in its block that has one, a push the next call, or the last when none follows.
 * This is an estimate: it also gives a statement any saved registers and unrelated setup that come just before it.
 */
export function linesWithSetup(lines: number[][], rows: AsmRow[], arch: Arch, recovered?: FunctionGraph): number[][] {
  const linesOf = new Map<number, number[]>();
  lines.forEach((addresses, line) => { for (const ad of addresses) linesOf.set(ad, [...(linesOf.get(ad) ?? []), line]); });
  if (!linesOf.size) return lines;
  const out = lines.map((addresses) => new Set(addresses));
  for (const block of buildCfg(rows, arch, recovered).blocks) {
    let pending: number[] = [], pushes: number[] = [], latest: number[] = [];
    const settle = (withPushes: boolean) => {
      for (const line of latest) for (const ad of withPushes ? [...pending, ...pushes] : pending) out[line].add(ad);
      pending = [];
      if (withPushes) pushes = [];
    };
    for (const row of block.rows) {
      const own = linesOf.get(row[0]);
      if (!own) { (row[2].startsWith("push ") ? pushes : pending).push(row[0]); continue; }
      latest = own;
      settle(rowFlow(row, arch).kind === "call");
    }
    settle(true);
  }
  return out.map((addresses) => [...addresses].sort((x, y) => x - y));
}

export function buildCfg(rows: AsmRow[], arch: Arch, recovered?: FunctionGraph): Cfg {
  if (recovered) {
    const byAddress = new Map(rows.map(row => [row[0], row]));
    const blocks = recovered.blocks.map((block, id) => ({
      id, addr: block.address,
      rows: block.instructions.map(ad => byAddress.get(ad)).filter((row): row is AsmRow => row !== undefined),
    })).filter(block => block.rows.length > 0);
    const byBlock = new Map(blocks.map(block => [block.addr, block.id]));
    const edges: CfgEdge[] = [];
    for (const edge of recovered.edges) {
      const from = byBlock.get(edge.from), to = byBlock.get(edge.to);
      if (from !== undefined && to !== undefined) edges.push({ from, to, kind: edge.kind });
    }
    // Layout indexes blocks by ID, so compact IDs if a stream omitted a block's rows.
    const ids = new Map(blocks.map((block, id) => [block.id, id]));
    return { blocks: blocks.map((block, id) => ({ ...block, id })), edges: edges.map(edge => ({ ...edge, from: ids.get(edge.from)!, to: ids.get(edge.to)! })) };
  }
  const sorted = [...rows].sort((x, y) => x[0] - y[0]);
  if (!sorted.length) return { blocks: [], edges: [] };
  const known = new Set(sorted.map((r) => r[0]));
  const flows = new Map(sorted.map((r) => [r[0], rowFlow(r, arch)]));
  if (arch === "mips" || arch === "mipsel") {
    // A normal branch executes its slot on both paths. A branch-likely skips it
    // on the false path. Prefer the engine's structured graph whenever available.
    for (let i = 0; i + 1 < sorted.length; i++) {
      const address = sorted[i][0], slot = sorted[i + 1][0];
      const flow = rowFlow(sorted[i], arch);
      if (!flow.delay || slot !== address + 4) continue;
      if (flow.likely) {
        flows.set(address, { kind: "cond", target: slot, fallthrough: address + 8 });
        flows.set(slot, { kind: "jump", target: flow.target });
      } else {
        flows.set(address, { kind: "none" });
        flows.set(slot, flow);
      }
    }
  }
  const inside = (t?: number) => (t !== undefined && known.has(t) ? t : undefined);
  const ends = (f: Flow) => f.kind === "jump" || f.kind === "cond" || f.kind === "ret" || f.kind === "halt";

  const leaders = new Set<number>([sorted[0][0]]);
  sorted.forEach((r, i) => {
    const f = flows.get(r[0])!;
    if (f.kind === "jump" || f.kind === "cond") {
      const t = inside(f.target);
      if (t !== undefined) leaders.add(t);
    }
    if (ends(f) && i + 1 < sorted.length) leaders.add(sorted[i + 1][0]);
    if (f.fallthrough !== undefined && known.has(f.fallthrough)) leaders.add(f.fallthrough);
  });

  const blocks: Block[] = [];
  for (const r of sorted) {
    if (leaders.has(r[0]) || !blocks.length) blocks.push({ id: blocks.length, addr: r[0], rows: [] });
    blocks[blocks.length - 1].rows.push(r);
  }
  const byAddr = new Map(blocks.map((b) => [b.addr, b.id]));

  const edges: CfgEdge[] = [];
  blocks.forEach((b, i) => {
    const f = flows.get(b.rows[b.rows.length - 1][0])!;
    const next = f.fallthrough === undefined ? (i + 1 < blocks.length ? blocks[i + 1].id : undefined) : byAddr.get(f.fallthrough);
    const t = inside(f.target);
    const to = t === undefined ? undefined : byAddr.get(t);
    if (f.kind === "jump") {
      if (to !== undefined) edges.push({ from: b.id, to, kind: "jump" });
    } else if (f.kind === "cond") {
      if (to !== undefined) edges.push({ from: b.id, to, kind: "true" });
      if (next !== undefined) edges.push({ from: b.id, to: next, kind: "false" });
    } else if (f.kind !== "ret" && f.kind !== "halt" && next !== undefined) {
      edges.push({ from: b.id, to: next, kind: "jump" });
    }
  });
  return { blocks, edges };
}

export interface Placed { id: number; x: number; y: number; w: number; h: number }
export interface Route { edge: CfgEdge; back: boolean; pts: [number, number][] }
export interface GraphLayout { nodes: Placed[]; routes: Route[]; width: number; height: number }

const GAP_X = 36, GAP_Y = 56, DUMMY_W = 14, MARGIN = 40, LANE = 18;

/** Layered layout: DFS back edges are routed around the side, the rest flow top to bottom. */
export function layoutCfg(cfg: Cfg, size: (b: Block) => { w: number; h: number }): GraphLayout {
  const n = cfg.blocks.length;
  if (!n) return { nodes: [], routes: [], width: 0, height: 0 };

  const out: CfgEdge[][] = cfg.blocks.map(() => []);
  for (const e of cfg.edges) out[e.from].push(e);

  // 1. Back edges, by iterative DFS from the entry (then from any unreached block).
  const state = new Uint8Array(n); // 0 new, 1 on stack, 2 done
  const post: number[] = [];
  const back = new Set<CfgEdge>();
  for (let root = 0; root < n; root++) {
    if (state[root]) continue;
    const stack: [number, number][] = [[root, 0]];
    state[root] = 1;
    while (stack.length) {
      const top = stack[stack.length - 1];
      const edges = out[top[0]];
      if (top[1] < edges.length) {
        const e = edges[top[1]++];
        if (state[e.to] === 1) back.add(e);
        else if (state[e.to] === 0) { state[e.to] = 1; stack.push([e.to, 0]); }
      } else {
        state[top[0]] = 2;
        post.push(top[0]);
        stack.pop();
      }
    }
  }
  const forward = cfg.edges.filter((e) => !back.has(e));

  // 2. Layers: longest path over forward edges, visiting in reverse post-order (a topological order).
  const layerOf = new Array<number>(n).fill(0);
  const fwdOut: CfgEdge[][] = cfg.blocks.map(() => []);
  for (const e of forward) fwdOut[e.from].push(e);
  for (let i = post.length - 1; i >= 0; i--) {
    const u = post[i];
    for (const e of fwdOut[u]) layerOf[e.to] = Math.max(layerOf[e.to], layerOf[u] + 1);
  }

  // 3. Dummy nodes carry long edges through the intermediate layers.
  const layer = [...layerOf];
  const up: number[][] = cfg.blocks.map(() => []);
  const down: number[][] = cfg.blocks.map(() => []);
  const chains = new Map<CfgEdge, number[]>();
  for (const e of forward) {
    const chain: number[] = [];
    let prev = e.from;
    for (let l = layer[e.from] + 1; l < layer[e.to]; l++) {
      const d = layer.length;
      layer.push(l);
      up.push([]);
      down.push([]);
      chain.push(d);
      down[prev].push(d);
      up[d].push(prev);
      prev = d;
    }
    down[prev].push(e.to);
    up[e.to].push(prev);
    chains.set(e, chain);
  }
  const total = layer.length;
  const nlayers = Math.max(...layer) + 1;
  const layers: number[][] = Array.from({ length: nlayers }, () => []);
  // Seed the order by a walk from the entry that visits the "false" (fall-through) side first.
  const seen = new Uint8Array(total);
  const seed: number[] = [];
  const visit = (root: number) => {
    const q = [root];
    while (q.length) {
      const u = q.shift()!;
      if (seen[u]) continue;
      seen[u] = 1;
      seed.push(u);
      for (const v of down[u]) q.push(v);
    }
  };
  for (let r = 0; r < total; r++) if (!up[r].length) visit(r);
  for (let r = 0; r < total; r++) visit(r);
  for (const u of seed) layers[layer[u]].push(u);

  // 4. Crossing reduction: barycenter sweeps.
  const index = new Array<number>(total).fill(0);
  const reindex = () => layers.forEach((l) => l.forEach((u, i) => (index[u] = i)));
  reindex();
  const sweep = (l: number, nbr: number[][]) => {
    const key = new Map<number, number>();
    for (const u of layers[l]) {
      const ns = nbr[u];
      key.set(u, ns.length ? ns.reduce((s, v) => s + index[v], 0) / ns.length : index[u]);
    }
    layers[l].sort((x, y) => key.get(x)! - key.get(y)! || index[x] - index[y]);
    layers[l].forEach((u, i) => (index[u] = i));
  };
  for (let pass = 0; pass < 6; pass++) {
    for (let l = 1; l < nlayers; l++) sweep(l, up);
    for (let l = nlayers - 2; l >= 0; l--) sweep(l, down);
  }

  // 5. Coordinates. Real nodes use their measured size; dummies are thin pass-through points.
  const w = new Array<number>(total), h = new Array<number>(total);
  for (let u = 0; u < total; u++) {
    if (u < n) { const s = size(cfg.blocks[u]); w[u] = s.w; h[u] = s.h; } else { w[u] = DUMMY_W; h[u] = 0; }
  }
  const cx = new Array<number>(total).fill(0);
  for (const l of layers) {
    let x = 0;
    for (const u of l) { cx[u] = x + w[u] / 2; x += w[u] + GAP_X; }
  }
  const place = (l: number[], want: number[]) => {
    // Left-packed and right-packed placements both keep the spacing; their mean does too.
    const left: number[] = [], right: number[] = [];
    l.forEach((u, i) => {
      const min = i ? left[i - 1] + (w[l[i - 1]] + w[u]) / 2 + GAP_X : -Infinity;
      left.push(Math.max(want[i], min));
    });
    for (let i = l.length - 1; i >= 0; i--) {
      const u = l[i];
      const max = i < l.length - 1 ? right[i + 1] - (w[l[i + 1]] + w[u]) / 2 - GAP_X : Infinity;
      right[i] = Math.min(want[i], max);
    }
    l.forEach((u, i) => (cx[u] = (left[i] + right[i]) / 2));
  };
  const pull = (l: number, nbr: number[][]) =>
    place(layers[l], layers[l].map((u) => (nbr[u].length ? nbr[u].reduce((s, v) => s + cx[v], 0) / nbr[u].length : cx[u])));
  for (let pass = 0; pass < 8; pass++) {
    for (let l = 1; l < nlayers; l++) pull(l, up);
    for (let l = nlayers - 2; l >= 0; l--) pull(l, down);
  }
  let minX = Infinity;
  for (let u = 0; u < total; u++) minX = Math.min(minX, cx[u] - w[u] / 2);
  for (let u = 0; u < total; u++) cx[u] += MARGIN - minX;

  const layerTop: number[] = [], layerH: number[] = [];
  let y = MARGIN;
  layers.forEach((l, i) => {
    layerTop[i] = y;
    layerH[i] = Math.max(0, ...l.map((u) => h[u]));
    y += layerH[i] + GAP_Y;
  });
  const top = (u: number) => layerTop[layer[u]];
  const bottom = (u: number) => layerTop[layer[u]] + (u < n ? h[u] : layerH[layer[u]]);

  // 6. Edge routes. Edges sharing a block side are spread along it, ordered left to right so they do not cross.
  const slot = (u: number, k: number, count: number) => {
    const span = Math.min(w[u] - 24, Math.max(0, (count - 1) * 22));
    return count > 1 ? cx[u] - span / 2 + (span * k) / (count - 1) : cx[u];
  };
  const firstHop = (e: CfgEdge) => (chains.get(e)?.[0] ?? e.to);
  const lastHop = (e: CfgEdge) => { const c = chains.get(e); return c?.length ? c[c.length - 1] : e.from; };
  const outSlots = new Map<CfgEdge, number>(), inSlots = new Map<CfgEdge, number>();
  const incoming: CfgEdge[][] = cfg.blocks.map(() => []);
  for (const e of cfg.edges) incoming[e.to].push(e);
  cfg.blocks.forEach((b) => {
    const fw = out[b.id].filter((e) => !back.has(e)).sort((p, q) => cx[firstHop(p)] - cx[firstHop(q)]);
    fw.forEach((e, k) => outSlots.set(e, slot(b.id, k, fw.length)));
    const bk = out[b.id].filter((e) => back.has(e));
    bk.forEach((e, k) => outSlots.set(e, slot(b.id, k, bk.length)));
    const ins = incoming[b.id].filter((e) => !back.has(e)).sort((p, q) => cx[lastHop(p)] - cx[lastHop(q)]);
    ins.forEach((e, k) => inSlots.set(e, slot(b.id, k, ins.length)));
    const bin = incoming[b.id].filter((e) => back.has(e));
    bin.forEach((e, k) => inSlots.set(e, slot(b.id, k, bin.length)));
  });

  let right = 0;
  for (let u = 0; u < total; u++) right = Math.max(right, cx[u] + w[u] / 2);
  const routes: Route[] = [];
  let lane = 0;
  for (const e of cfg.edges) {
    const sx = outSlots.get(e)!, tx = inSlots.get(e)!;
    const sb = bottom(e.from), tt = top(e.to);
    if (back.has(e)) {
      const lx = right + MARGIN / 2 + LANE * lane++;
      const a = sb + 12 + (lane % 3) * 4, b = tt - 12 - (lane % 3) * 4;
      routes.push({ edge: e, back: true, pts: [[sx, sb], [sx, a], [lx, a], [lx, b], [tx, b], [tx, tt]] });
      continue;
    }
    const pts: [number, number][] = [[sx, sb]];
    let px = sx, py = sb;
    const go = (x: number, yTop: number) => {
      if (x !== px) { const ym = (py + yTop) / 2; pts.push([px, ym], [x, ym]); }
      pts.push([x, yTop]);
      px = x; py = yTop;
    };
    for (const d of chains.get(e) ?? []) {
      go(cx[d], top(d));
      pts.push([cx[d], bottom(d)]);
      px = cx[d]; py = bottom(d);
    }
    go(tx, tt);
    routes.push({ edge: e, back: false, pts });
  }
  const laneRight = right + MARGIN / 2 + LANE * lane;
  const nodes: Placed[] = cfg.blocks.map((b) => ({ id: b.id, x: cx[b.id] - w[b.id] / 2, y: top(b.id), w: w[b.id], h: h[b.id] }));
  return { nodes, routes, width: Math.max(right, laneRight) + MARGIN, height: y - GAP_Y + MARGIN };
}
