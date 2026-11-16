import type { ReactNode } from "react";

// A small Markdown renderer for saved reports: headings, paragraphs, lists, tables, quotes, code and
// the usual inline marks. It builds React elements (never HTML), so text an agent copied out of a
// binary cannot inject markup. Links are shown as text with the address in a tooltip: nothing in a
// report opens a page on its own.

const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(__[^_\n]+__)|(\*[^*\s][^*\n]*\*)|(\[[^\]\n]+\]\([^)\s]+\))/g;

/** Called with an address when the reader clicks one in the text. */
export type OnAddress = (address: number) => void;
const ADDRESS = /\b0x[0-9a-fA-F]{3,16}\b/g;

/** Plain text, with each address a button when the caller wants them to be. */
function plain(text: string, onAddress: OnAddress | undefined, k: { n: number }): ReactNode[] {
  if (!onAddress) return [text];
  const out: ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(ADDRESS)) {
    if (m.index! > last) out.push(text.slice(last, m.index));
    const value = parseInt(m[0], 16);
    out.push(<button key={"a" + k.n++} type="button" className="md-addr" title="Go to this address" onClick={() => onAddress(value)}>{m[0]}</button>);
    last = m.index! + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function inline(text: string, onAddress?: OnAddress): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0, k = 0;
  const ids = { n: 0 };
  for (const m of text.matchAll(INLINE)) {
    const i = m.index!;
    if (i > last) out.push(...plain(text.slice(last, i), onAddress, ids));
    const t = m[0];
    if (m[1]) out.push(onAddress && /^`0x[0-9a-fA-F]{3,16}`$/.test(t) ? plain(t.slice(1, -1), onAddress, ids)[0] : <code key={k++}>{t.slice(1, -1)}</code>);
    else if (m[2] || m[3]) out.push(<strong key={k++}>{inline(t.slice(2, -2), onAddress)}</strong>);
    else if (m[4]) out.push(<em key={k++}>{inline(t.slice(1, -1), onAddress)}</em>);
    else {
      const close = t.indexOf("](");
      out.push(<span key={k++} className="md-link" title={t.slice(close + 2, -1)}>{inline(t.slice(1, close), onAddress)}</span>);
    }
    last = i + t.length;
  }
  if (last < text.length) out.push(...plain(text.slice(last), onAddress, ids));
  return out;
}

const cells = (row: string) => row.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
const isRule = (row: string) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(row);
const bullet = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;

export default function Markdown({ text, onAddress }: { text: string; onAddress?: OnAddress }) {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let i = 0, key = 0;

  const list = (indent: number): ReactNode => {
    const ordered = /\d/.test(lines[i].match(bullet)![2]);
    const items: ReactNode[] = [];
    while (i < lines.length) {
      const m = lines[i].match(bullet);
      if (!m || m[1].length < indent) break;
      if (m[1].length > indent) { items.push(<li key={key++} className="md-nested">{list(m[1].length)}</li>); continue; }
      i++;
      items.push(<li key={key++}>{inline(m[3], onAddress)}</li>);
    }
    return ordered ? <ol key={key++}>{items}</ol> : <ul key={key++}>{items}</ul>;
  };

  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    const fence = line.match(/^\s*(```|~~~)/);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith(fence[1])) body.push(lines[i++]);
      i++;
      blocks.push(<pre key={key++} className="md-code"><code>{body.join("\n")}</code></pre>);
      continue;
    }
    const heading = line.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (heading) { const H = `h${Math.min(6, heading[1].length + 1)}` as "h2"; blocks.push(<H key={key++}>{inline(heading[2], onAddress)}</H>); i++; continue; }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { blocks.push(<hr key={key++} />); i++; continue; }
    if (line.includes("|") && i + 1 < lines.length && isRule(lines[i + 1])) {
      const head = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) rows.push(cells(lines[i++]));
      blocks.push(
        <div key={key++} className="md-table"><table>
          <thead><tr>{head.map((c, n) => <th key={n}>{inline(c, onAddress)}</th>)}</tr></thead>
          <tbody>{rows.map((r, n) => <tr key={n}>{head.map((_, c) => <td key={c}>{inline(r[c] ?? "", onAddress)}</td>)}</tr>)}</tbody>
        </table></div>,
      );
      continue;
    }
    if (/^\s*>/.test(line)) {
      const body: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) body.push(lines[i++].replace(/^\s*>\s?/, ""));
      blocks.push(<blockquote key={key++}>{inline(body.join(" "), onAddress)}</blockquote>);
      continue;
    }
    if (bullet.test(line)) { blocks.push(list(line.match(bullet)![1].length)); continue; }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^\s*(```|~~~|#{1,6}\s|>)/.test(lines[i]) && !bullet.test(lines[i]) && !(lines[i].includes("|") && isRule(lines[i + 1] ?? ""))) para.push(lines[i++].trim());
    blocks.push(<p key={key++}>{inline(para.join(" "), onAddress)}</p>);
  }
  return <div className="md">{blocks}</div>;
}
