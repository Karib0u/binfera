import type { StringEntry } from "./types";

/** Text in the file's strings that often says where a sample talks to or what it touches. Pattern matches, so candidates, not verdicts. */
export interface Indicator { kind: string; value: string; strings: StringEntry[] }

// Country and common generic domains; anything wider also matches names like `foo.exe` and `a.dat`.
const TLDS = "com|net|org|info|biz|io|co|me|ru|su|cn|de|uk|fr|nl|it|es|pl|br|in|jp|kr|ir|ua|tr|us|eu|ca|au|ch|se|no|cc|tv|ws|to|tk|pw|top|xyz|site|online|club|live|onion|bit|gov|edu|mil";

const plausibleIp = (ip: string) => {
  const parts = ip.split(":")[0].split(".").map(Number);
  // A first octet of 0, or x.0.0.0, is nearly always a version number.
  return parts.every((n) => n <= 255) && parts[0] !== 0 && parts[0] !== 255 && !(parts[1] === 0 && parts[2] === 0 && parts[3] === 0);
};
/** .NET and class names read like domains (`System.Net`); real hostnames are in one case. */
const plausibleDomain = (d: string) => d === d.toLowerCase() || d === d.toUpperCase();

// In order: a match is removed from the text before the next pattern, so a URL's host does not also count as a domain.
const PATTERNS: { kind: string; re: RegExp; ok?: (m: string) => boolean }[] = [
  { kind: "URLs", re: /\b(?:https?|ftps?|wss?|tcp|udp):\/\/[^\s"'<>\\^`{|}]+/gi },
  { kind: "Email addresses", re: /\b[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi },
  { kind: "Registry keys", re: /\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\b[\\\w .{}()$-]*|\b(?:SOFTWARE|Software|SYSTEM\\CurrentControlSet)\\[\\\w .{}()$-]+/g },
  { kind: "Named objects", re: /\\\\[.?]\\[^\s"']+|\\(?:Device|BaseNamedObjects|DosDevices)\\[^\s"']+|\b(?:Global|Local)\\[^\s"'\\]+/g },
  { kind: "File paths", re: /\b[A-Za-z]:\\[^"'<>|*?\r\n]*|%\w+%\\[^"'<>|*?\r\n]+|\\\\[\w.-]+\\[\w$.-][^"'<>|*?\r\n]*|(?<![\w/.])\/(?:etc|tmp|var|usr|bin|sbin|home|root|dev|proc|sys|opt|Library|Users|Applications|System)\/[^\s"':;]+/g },
  { kind: "IP addresses", re: /\b(?:\d{1,3}\.){3}\d{1,3}\b(?::\d{1,5})?/g, ok: plausibleIp },
  { kind: "Domains", re: new RegExp(String.raw`\b(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:${TLDS})\b(?![\w.-])`, "gi"), ok: plausibleDomain },
];
/** These name the whole string, and can contain the other kinds, so they do not remove text. */
const WHOLE: { kind: string; re: RegExp }[] = [
  { kind: "Commands", re: /(?:^|[\s"'])(?:cmd(?:\.exe)?\s+\/[ckr]|powershell(?:\.exe)?\s+-|wmic(?:\.exe)?\s|schtasks(?:\.exe)?\s+\/|vssadmin(?:\.exe)?\s|bcdedit(?:\.exe)?\s|wevtutil(?:\.exe)?\s|rundll32(?:\.exe)?\s|reg(?:\.exe)?\s+(?:add|delete|query)\s|net\s+(?:user|stop|start)\s|sc(?:\.exe)?\s+(?:create|start|stop|config)\s|(?:ba)?sh\s+-c\s|curl\s+-|wget\s|chmod\s)/i },
  { kind: "User agents", re: /Mozilla\/\d/ },
];
const ORDER = ["URLs", "IP addresses", "Domains", "Email addresses", "Commands", "User agents", "Registry keys", "Named objects", "File paths"];
const MAX_LENGTH = 2048;

export function extractIndicators(strings: StringEntry[]): Indicator[] {
  const found = new Map<string, Indicator>();
  const add = (kind: string, value: string, x: StringEntry) => {
    const key = kind + "\0" + value, hit = found.get(key);
    if (!hit) found.set(key, { kind, value, strings: [x] });
    else if (!hit.strings.includes(x)) hit.strings.push(x);
  };
  for (const x of strings) {
    if (x.s.length > MAX_LENGTH) continue;
    for (const { kind, re } of WHOLE) if (re.test(x.s)) add(kind, x.s.trim(), x);
    let rest = x.s;
    for (const { kind, re, ok } of PATTERNS) {
      rest = rest.replace(re, (m) => {
        const value = m.trim().replace(/[.,;:)\]]+$/, "");
        if (!value || (ok && !ok(value))) return m;
        add(kind, value, x);
        return " ".repeat(m.length);
      });
    }
  }
  return [...found.values()].sort((p, q) => ORDER.indexOf(p.kind) - ORDER.indexOf(q.kind) || p.value.localeCompare(q.value));
}
