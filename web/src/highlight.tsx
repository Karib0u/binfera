import { Fragment } from "react";

const KEYWORDS = "if|else|while|for|do|return|goto|break|continue|switch|case|default|sizeof|struct|union|enum|typedef";
const TYPES = "void|char|short|int|long|unsigned|signed|float|double|bool|byte|ushort|uint|ulong|code|undefined\\d*|u?int\\d+|xunknown\\d+|_?_?(?:stdcall|cdecl|fastcall|thiscall)|size_t|ssize_t|wchar_t|u?intptr_t|ptrdiff_t|u?int\\d+_t";

/** Template arguments, nested up to three deep (`<char,std::char_traits<char>>`). */
const TEMPLATE_ARGUMENTS = String.raw`<(?:[^<>()\n]|<(?:[^<>()\n]|<[^<>()\n]*>)*>)*>`;
/** One component of a demangled C++ name: an identifier, a destructor's `~`, template arguments. */
const CPP_PART = String.raw`~?[A-Za-z_]\w*(?:${TEMPLATE_ARGUMENTS})?`;

/** A function name as printed: a C identifier, a demangled C++ name with its namespaces and class
 * (`std::_Lockit::~_Lockit`, `net::Box<int>::FUN_10001220`), or a Go name with its package path
 * and receiver (`os.(*File).Write`, `github.com/pkg/errors.Wrap`, `net/http.(*Server).Serve-fm`). */
export const FUNCTION_NAME = String.raw`(?:[A-Za-z_]\w*(?:${TEMPLATE_ARGUMENTS})?(?:::${CPP_PART})+|[A-Za-z_]\w*(?:[./](?:\(\*?[\w./]+\)|[\w-]+))*)`;

// Order matters: each alternative claims its text before the later ones see it.
const TOKEN = new RegExp(
  [
    String.raw`(\/\*[\s\S]*?\*\/|\/\/[^\n]*)`,                                // 1 comment
    String.raw`(L?"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`,                          // 2 string
    String.raw`\b(0x[0-9a-fA-F]+|\d+)\b`,                                          // 3 number
    String.raw`\b(${KEYWORDS})\b`,                                                // 4 keyword
    String.raw`\b(${TYPES})\b`,                                                   // 5 type
    String.raw`\b((?:param|local|[a-z]{1,3}Var|[a-z]+Stack)_?\w*|(?:in|unaff|extraout)_\w+)\b(?!\s*\()`, // 6 param / local
    String.raw`\b((?:DAT|PTR|LAB|s|u|g|_DAT|_PTR)_[0-9a-fA-F]{5,}|[su]_\w*_[0-9a-fA-F]{6,16}|[A-Za-z]+Stack_[0-9a-f]+)\b`, // 7 global / label
    String.raw`\b(FUN_\w+|${FUNCTION_NAME}(?=\s*\())`,                                     // 8 function call
    String.raw`([+\-*/%&|^~!<>=?:]+|->)`,                                          // 9 operator
    // 10 a type named where only a type can be: a declaration (`HANDLE hFile;`) or a cast (`(LPVOID)0x0`).
    String.raw`\b([A-Z_][A-Z0-9_]*[A-Z0-9]|_[A-Z]\w*)\b(?=\s+\**\s*[A-Za-z_]\w*\s*(?:[;,)\[(]|=(?!=))|\s*\**\s*\)\s*[\w(&*"'~!-])`,
    String.raw`\b([A-Za-z_]\w*)\b`,                                                 // 11 other identifier
  ].join("|"),
  "g",
);
const CLASSES = ["", "tk-c", "tk-s", "tk-n", "tk-k", "tk-t", "tk-v", "tk-g", "tk-f", "tk-o", "tk-t", ""];

/** What one function's code names beyond what its spelling shows: its variables, the types they
 * have, and the imported functions (`kernel32_GetProcessHeap` is one even when not called). */
export interface CodeVocabulary {
  vars: Set<string>;
  types: Set<string>;
  isFunction: (name: string) => boolean;
}

const NOT_TYPE_WORDS = new Set(["const", "struct", "union", "enum", "volatile", "signed", "unsigned"]);
/** The vocabulary of a function from its stack frame: names and the identifiers in their types. */
export function codeVocabulary(frame: { name: string; type: string }[] | undefined, isFunction: (name: string) => boolean, text?: string): CodeVocabulary {
  const vars = new Set<string>(), types = new Set<string>();
  const addType = (type: string) => { for (const word of type.match(/[A-Za-z_]\w*/g) ?? []) if (!NOT_TYPE_WORDS.has(word)) types.add(word); };
  for (const slot of frame ?? []) {
    vars.add(slot.name);
    addType(slot.type);
  }
  // Register locals are not in the frame: take them, and the parameters, from the declarations.
  const lines = text?.split("\n") ?? [];
  const head = lines.findIndex((l) => /^\S.*\(.*\)\s*$/.test(l));
  if (head >= 0) {
    for (const part of /\((.*)\)/.exec(lines[head])![1].split(",")) {
      const m = /^(.*?)\b([A-Za-z_]\w*)\s*(?:\[\w*\])?\s*$/.exec(part.trim());
      if (m && m[1].trim() && part.trim() !== "void") { vars.add(m[2]); addType(m[1]); }
    }
    for (const line of lines.slice(head + 1)) {
      if (/^\s*$/.test(line) && vars.size && line !== lines[head + 1]) break;
      const m = /^\s+((?:[A-Za-z_][\w:]*\s+)+\**\s*)([A-Za-z_]\w*)\s*(?:\[\w*\])?\s*;\s*$/.exec(line);
      if (m && !/^(?:return|goto)\b/.test(m[1].trim())) { vars.add(m[2]); addType(m[1]); }
    }
  }
  return { vars, types, isFunction };
}

/** What identifies a word across C, assembly and the graph: its text, or its value for a number, so 0xc and 0Ch match. */
export function tokKey(word: string) {
  if (/^0x[0-9a-f]+$/i.test(word) || /^[0-9][0-9a-f]*h$/i.test(word)) return "n" + parseInt(word, 16);
  return /^\d+$/.test(word) ? "n" + word : word;
}
/** The key of an imported function, named as the decompiler prints it (`kernel32_CreateFileW`). */
export const importKey = (slot: { name: string; dll: string }) => (slot.dll ? slot.dll.replace(/\.dll$/i, "").toLowerCase() + "_" : "") + slot.name;

const WORD = /\b(?:0x[0-9a-fA-F]+|[0-9][0-9a-fA-F]*h|\d+|[A-Za-z_]\w*)\b/g;
/** Plain text with each word marked, so clicking one can highlight its other uses. */
export function tokenized(text: string): React.ReactNode {
  const out: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(WORD)) {
    if (m.index! > last) out.push(text.slice(last, m.index));
    out.push(<span key={m.index} data-tok={tokKey(m[0])}>{m[0]}</span>);
    last = m.index! + m[0].length;
  }
  if (!out.length) return text;
  out.push(text.slice(last));
  return out;
}

/** The decompiled text with analyst names in place of the original function names. */
export const applyNames = (text: string, display: (token: string) => string | undefined) =>
  text.replace(TOKEN, (...m) => (m[8] || m[6] || m[11] ? display(m[0]) ?? m[0] : m[0]));

/** Turns the C literal as printed by the decompiler back into the string's content. */
export const unescapeLiteral = (lit: string) =>
  lit.replace(/^L?["']|["']$/g, "").replace(/\\(x[0-9a-fA-F]{2}|.)/g, (_, c: string) =>
    c[0] === "x" ? String.fromCharCode(parseInt(c.slice(1), 16)) : ({ n: "\n", r: "\r", t: "\t", "0": "\0" } as Record<string, string>)[c] ?? c);

/** Minimal C-ish highlighter, enough to make decompiler output scannable. One block per source line. */
export function Code({ text, lineOffset = 0, active, onLine, comments, resolve, onGoto, onString, strAt, inlineStrings = true, data, display, vocabulary }: {
  /** Names the spelling does not classify: this function's variables and types, and imported functions. */
  vocabulary?: CodeVocabulary;
  /** Analyst or agent comments by line index (in the full output), shown at the end of the line. */
  comments?: Map<number, string>;
  /** The name to show for a function name as printed, when it has another. */
  display?: (token: string) => string | undefined;
  /** File data an address names: links the data labels and big hex literals to it. */
  data?: { is: (address: number) => boolean; go: (address: number) => void };
  /** Show a referenced string in place of its data label (IDA / Binary Ninja style). */
  inlineStrings?: boolean;
  /** The string stored at a virtual address, if any. */
  strAt?: (address: number) => string | undefined;
  text: string;
  /** Index of the first displayed line within the decompiler's full output. */
  lineOffset?: number;
  /** Indexes (in the full output) of highlighted lines. */
  active?: Set<number>;
  onLine?: (index: number) => void;
  /** Maps an identifier or hex literal to a function entry, if it is one. */
  resolve?: (token: string) => number | undefined;
  onGoto?: (address: number) => void;
  /** Called with the content of a clicked string, and its address when the text names one. */
  onString?: (content: string, address?: number) => void;
}) {
  const lines = text.split("\n");
  // The arrow keys move the selected line while the code itself has focus; Tab still reaches its links.
  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (!onLine || e.target !== e.currentTarget || (e.key !== "ArrowDown" && e.key !== "ArrowUp")) return;
    e.preventDefault();
    const now = active?.size ? Math.min(...active) : null, last = lineOffset + lines.length - 1;
    const next = now === null ? lineOffset : Math.min(last, Math.max(lineOffset, now + (e.key === "ArrowDown" ? 1 : -1)));
    onLine(next);
    e.currentTarget.querySelector(`[data-ln="${next}"]`)?.scrollIntoView({ block: "nearest" });
  };
  return (
    <div className="code" tabIndex={onLine ? 0 : undefined} aria-label="Decompiled code" onKeyDown={onKey}>
      {lines.map((line, i) => {
        const index = i + lineOffset;
        return (
          <div key={i} data-ln={index} className={"ln" + (active?.has(index) ? " hl" : "")} onClick={() => onLine?.(index)}>
            {highlightLine(line, resolve, onGoto, onString, strAt, inlineStrings, data, display, vocabulary)}
            {comments?.get(index) && <span className="tk-c ucm" title={comments.get(index)}>  // {comments.get(index)}</span>}
          </div>
        );
      })}
    </div>
  );
}

function highlightLine(
  text: string,
  resolve?: (token: string) => number | undefined,
  onGoto?: (address: number) => void,
  onString?: (content: string, address?: number) => void,
  strAt?: (address: number) => string | undefined,
  inlineStrings = true,
  data?: { is: (address: number) => boolean; go: (address: number) => void },
  display?: (token: string) => string | undefined,
  vocabulary?: CodeVocabulary,
) {
  const out: React.ReactNode[] = [];
  let last = 0, k = 0;
  for (const m of text.matchAll(TOKEN)) {
    const i = m.index!;
    if (i > last) out.push(<Fragment key={k++}>{tokenized(text.slice(last, i))}</Fragment>);
    let cls = CLASSES[m.findIndex((g, n) => n > 0 && g !== undefined)];
    // A function named without a call (a pointer to it is taken) is still a function.
    let named = false;
    if (m[11]) {
      if (resolve?.(m[0]) !== undefined || vocabulary?.isFunction(m[0])) { cls = "tk-f"; named = true; }
      else if (vocabulary?.vars.has(m[0])) { cls = "tk-v"; named = true; }
      else if (vocabulary?.types.has(m[0])) cls = "tk-t";
      else {
        out.push(<Fragment key={k++}>{tokenized(m[0])}</Fragment>);
        last = i + m[0].length;
        continue;
      }
    }
    if (m[2] && onString) {
      out.push(<a key={k++} className="xref tk-s" href="#str" title="Show in the Listing"
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); onString(unescapeLiteral(m[0])); }}>{m[0]}</a>);
      last = i + m[0].length;
      continue;
    }
    // A data label or hex literal that points at a known string: link it and show the string.
    if ((m[3] || m[7]) && onString && strAt) {
      const hit = m[3] ? (m[3].startsWith("0x") ? parseInt(m[3], 16) : undefined) : parseInt(m[0].slice(m[0].lastIndexOf("_") + 1), 16);
      const str = hit === undefined || Number.isNaN(hit) ? undefined : strAt(hit);
      if (str !== undefined) {
        const shown = JSON.stringify(str.length > 60 ? str.slice(0, 60) + "…" : str);
        const where = m[0] + " · 0x" + hit!.toString(16);
        out.push(inlineStrings
          ? <a key={k++} className="xref tk-s" href="#str" title={where}
              onClick={(e) => { e.preventDefault(); e.stopPropagation(); onString(str, hit); }}>{shown}</a>
          : <Fragment key={k++}>
              <a className={"xref " + cls} href="#str" title={"String at 0x" + hit!.toString(16)}
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); onString(str, hit); }}>{m[0]}</a>
              <span className="tk-s str-hint">{" "}{shown}</span>
            </Fragment>);
        last = i + m[0].length;
        continue;
      }
    }
    const target = onGoto && (m[3] || m[8] || (m[11] && cls === "tk-f")) ? resolve?.(m[0]) : undefined;
    if (target === undefined && data && (m[7] || (m[3] && m[3].startsWith("0x") && m[3].length >= 7))) {
      const v = m[3] ? parseInt(m[3], 16) : parseInt(m[0].slice(m[0].lastIndexOf("_") + 1), 16);
      if (!Number.isNaN(v) && data.is(v)) {
        out.push(<a key={k++} className={"xref " + cls} data-tok={"n" + v} data-id={m[0]} href={"#" + v.toString(16)} title={"Show 0x" + v.toString(16) + " in the Listing"}
          onClick={(e) => { e.preventDefault(); e.stopPropagation(); data.go(v); }}>{m[0]}</a>);
        last = i + m[0].length;
        continue;
      }
    }
    const shown = ((m[8] || m[6] || named) && display?.(m[0])) || m[0];
    const id = m[6] || m[7] || m[8] || named ? m[0] : undefined;
    const tok = m[1] || m[2] || m[9] ? undefined : tokKey(shown);
    out.push(target !== undefined
      ? <a key={k++} className={"xref " + cls} data-tok={tok} data-id={id} data-fn={target} href={"#" + target.toString(16)}
          onClick={(e) => { e.preventDefault(); e.stopPropagation(); onGoto!(target); }}>{shown}</a>
      : <span key={k++} className={cls} data-tok={tok} data-id={id} title={shown !== m[0] ? m[0] : undefined}>{shown}</span>);
    last = i + m[0].length;
  }
  out.push(<Fragment key={k++}>{tokenized(text.slice(last))}</Fragment>);
  return out.length === 1 && text === "" ? "\u200b" : out;
}
