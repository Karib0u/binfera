// Line and word differences for display, in the manner of `git diff`. Which functions pair up and
// which instructions differ is decided by the engine; this only lines up text it has already
// produced, such as decompiled C, for reading.

export type LineStatus = "same" | "changed" | "added" | "removed";
export interface LineRow { status: LineStatus; a?: string; b?: string; aLine?: number; bLine?: number }
export interface Piece { text: string; changed: boolean }

/** Past this many table cells, only the common start and end of the two texts are lined up. */
const MAX_CELLS = 4_000_000;

/** The steps from `a` to `b`, longest common subsequence first, as [index in a, index in b]. */
function align(a: string[], b: string[]): [number | null, number | null][] {
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let tail = 0;
  while (tail < a.length - start && tail < b.length - start && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++;
  const n = a.length - start - tail, m = b.length - start - tail;
  const out: [number | null, number | null][] = [];
  for (let i = 0; i < start; i++) out.push([i, i]);
  if (n * m > MAX_CELLS) {
    for (let i = 0; i < n; i++) out.push([start + i, null]);
    for (let j = 0; j < m; j++) out.push([null, start + j]);
  } else {
    const width = m + 1;
    const table = new Uint32Array((n + 1) * width);
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        table[i * width + j] = a[start + i] === b[start + j]
          ? table[(i + 1) * width + j + 1] + 1
          : Math.max(table[(i + 1) * width + j], table[i * width + j + 1]);
      }
    }
    let i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && a[start + i] === b[start + j]) out.push([start + i++, start + j++]);
      else if (i < n && (j === m || table[(i + 1) * width + j] >= table[i * width + j + 1])) out.push([start + i++, null]);
      else out.push([null, start + j++]);
    }
  }
  for (let i = 0; i < tail; i++) out.push([a.length - tail + i, b.length - tail + i]);
  return out;
}

const tokens = (line: string) => line.match(/\w+|\s+|[^\w\s]/g) ?? [];

/** Each side of a changed line, split into what it shares with the other side and what it does not. */
export function diffWords(a: string, b: string, keyA: (t: string) => string = (t) => t, keyB: (t: string) => string = (t) => t): [Piece[], Piece[]] {
  const left = tokens(a), right = tokens(b);
  const pieces: [Piece[], Piece[]] = [[], []];
  const add = (side: 0 | 1, text: string, changed: boolean) => {
    const list = pieces[side], last = list[list.length - 1];
    if (last && last.changed === changed) last.text += text; else list.push({ text, changed });
  };
  for (const [x, y] of align(left.map(keyA), right.map(keyB))) {
    if (x !== null && y !== null) { add(0, left[x], false); add(1, right[y], false); }
    else if (x !== null) add(0, left[x], true);
    else if (y !== null) add(1, right[y], true);
  }
  return pieces;
}

/** How much two lines share, from 0 to 1, ignoring white space. */
function likeness(a: string, b: string) {
  const left = tokens(a).filter((t) => t.trim()), right = tokens(b).filter((t) => t.trim());
  const largest = Math.max(left.length, right.length);
  if (!largest) return 1;
  return align(left, right).filter(([x, y]) => x !== null && y !== null).length / largest;
}

/**
 * Compares two texts line by line. `keyA` and `keyB` say what counts as the same line, so names that
 * only differ by address need not read as changes. A removed line and an added line beside it are
 * one changed line when they are mostly alike.
 */
export function diffLines(a: string[], b: string[], keyA: (l: string) => string = (l) => l, keyB: (l: string) => string = (l) => l): LineRow[] {
  const rows: LineRow[] = [];
  let removed: number[] = [], added: number[] = [];
  const flush = () => {
    let i = 0, j = 0;
    while (i < removed.length || j < added.length) {
      const x = removed[i], y = added[j];
      if (i < removed.length && j < added.length && likeness(keyA(a[x]), keyB(b[y])) >= 0.4) {
        rows.push({ status: "changed", a: a[x], b: b[y], aLine: x + 1, bLine: y + 1 }); i++; j++;
      } else if (i < removed.length && (j >= added.length || removed.length - i >= added.length - j)) {
        rows.push({ status: "removed", a: a[x], aLine: x + 1 }); i++;
      } else {
        rows.push({ status: "added", b: b[y], bLine: y + 1 }); j++;
      }
    }
    removed = []; added = [];
  };
  for (const [x, y] of align(a.map(keyA), b.map(keyB))) {
    if (x !== null && y !== null) {
      flush();
      rows.push({ status: "same", a: a[x], b: b[y], aLine: x + 1, bLine: y + 1 });
    } else if (x !== null) removed.push(x);
    else if (y !== null) added.push(y);
  }
  flush();
  return rows;
}

const FUNCTION_NAME = /\b(?:thunk_)?FUN_([0-9a-f]+)\b/g;
const ADDRESS_NAME = /\b(?:DAT|LAB|PTR|UNK|SUB|EXT|switchD|caseD|code_r\w*)_[0-9a-f_x]+\b/g;

/**
 * What a decompiled line means regardless of where things sit. A call counts as the same only when
 * it goes to the function matched with the old callee, so a redirected call still reads as a change.
 */
export function cKey(line: string, side: "a" | "b", forward: Map<number, number>) {
  return line
    .replace(FUNCTION_NAME, (_, hex: string) => {
      const at = parseInt(hex, 16);
      if (side === "b") return `fn_${at}`;
      const peer = forward.get(at);
      return peer === undefined ? `old_${at}` : `fn_${peer}`;
    })
    .replace(ADDRESS_NAME, "ADDR")
    .trimEnd();
}

const LOCAL_NAME = /\b(?:([a-zA-Z]{1,6}Var)\d+|(local|[a-zA-Z]{1,5}Stack)_[0-9a-f]+)\b/g;

/**
 * The decompiler numbers local variables by type, so removing one renumbers the rest. Each name is
 * replaced by its order of first use in the body, which leaves `x - y` and `y - x` different while
 * making the same code with other numbers read as the same.
 */
export function localNames(lines: string[]) {
  const blank = lines.findIndex((l) => !l.trim());
  const body = blank < 0 ? lines : [...lines.slice(blank), ...lines.slice(0, blank)];
  const names = new Map<string, string>(), seen = new Map<string, number>();
  for (const line of body) {
    for (const m of line.matchAll(LOCAL_NAME)) {
      if (names.has(m[0])) continue;
      const kind = m[1] ?? m[2], n = seen.get(kind) ?? 0;
      seen.set(kind, n + 1);
      names.set(m[0], `${kind}#${n}`);
    }
  }
  return names;
}

/** A line with its local variables named by `localNames`. */
export const withLocals = (line: string, names: Map<string, string>) => line.replace(LOCAL_NAME, (name) => names.get(name) ?? name);

export type Foldable<T> = { row: T } | { fold: number; from: number };

/** Keeps `context` unchanged rows around each change and folds longer unchanged runs. */
export function folded<T>(rows: T[], same: (row: T) => boolean, open: Set<number>, context = 3): Foldable<T>[] {
  const out: Foldable<T>[] = [];
  let i = 0;
  while (i < rows.length) {
    if (!same(rows[i])) { out.push({ row: rows[i++] }); continue; }
    let end = i;
    while (end < rows.length && same(rows[end])) end++;
    const lead = i === 0 ? 0 : context, trail = end === rows.length ? 0 : context;
    if (end - i <= lead + trail + 1 || open.has(i)) {
      for (; i < end; i++) out.push({ row: rows[i] });
      continue;
    }
    for (let k = 0; k < lead; k++) out.push({ row: rows[i + k] });
    out.push({ fold: end - i - lead - trail, from: i });
    for (let k = end - trail; k < end; k++) out.push({ row: rows[k] });
    i = end;
  }
  return out;
}
