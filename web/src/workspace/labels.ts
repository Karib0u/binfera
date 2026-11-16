export const hex = (n: number) => "0x" + n.toString(16);
export const bytes = (n: number) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");
