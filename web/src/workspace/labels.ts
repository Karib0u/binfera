export const hex = (n: number) => "0x" + n.toString(16);
export const bytes = (n: number) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");
/** Short count for narrow mobile tabs and badges: 5996 -> "6k", 1250 -> "1.3k", 999 -> "999". */
export const compactCount = (n: number) =>
  n >= 10000 ? `${Math.round(n / 1000)}k` : n >= 1000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k` : String(n);
