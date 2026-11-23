// Pairs a reader made by hand, kept in this browser for the two files they join (by SHA-256), so a comparison reopened later has them.

const key = (a: string, b: string) => `binfera:pairs:${a}:${b}`;

/** Address pairs `[a, b]` saved for these two files; anything unreadable is ignored. */
export function loadPairs(a: string, b: string): [number, number][] {
  try {
    const raw = JSON.parse(localStorage.getItem(key(a, b)) ?? "[]");
    return Array.isArray(raw) ? raw.filter((p): p is [number, number] => Array.isArray(p) && p.length === 2 && p.every((n) => Number.isSafeInteger(n))) : [];
  } catch { return []; }
}

export function savePairs(a: string, b: string, pairs: [number, number][]) {
  try {
    if (pairs.length) localStorage.setItem(key(a, b), JSON.stringify(pairs)); else localStorage.removeItem(key(a, b));
  } catch { /* storage unavailable: the pairs last for this tab */ }
}
