export interface FileHandleOrigin {
  column: number;
  line: number;
  api: string;
  path?: string;
}

const LEXEME = /L?"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|[A-Za-z_]\w*|&&|[^\s]/g;
const COMMENTS_OR_LITERALS = /\/\*[\s\S]*?\*\/|\/\/[^\n]*|L?"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g;
const API = /^(?:(?:kernel32|kernelbase)_)?(CreateFile[AW]|ReadFile)$/;
const CONTROL = /^(?:if|else|for|while|do|switch|case|default|goto|break|continue|return|[{}:;])$/;
const IDENTIFIER = /^[A-Za-z_]\w*$/;

/** Trace direct assignments and reads within a straight-line region of the printed C. */
export function fileHandleOrigins(text: string, isImport: (name: string) => boolean) {
  const hints = new Map<number, FileHandleOrigin>();
  if (!text.includes("ReadFile") || !/CreateFile[AW]/.test(text)) return hints;

  // Keep columns and line numbers intact for the highlighter. Quoted text stays a single token.
  const rows = text.replace(COMMENTS_OR_LITERALS, (part) => part.startsWith("/") ? part.replace(/[^\n]/g, " ") : part)
    .split("\n").map((line) => [...line.matchAll(LEXEME)]);
  const locals = new Set<string>(), escaped = new Set<string>();
  let afterAddress = false;
  for (const row of rows) {
    for (const [token] of row) {
      if (afterAddress && IDENTIFIER.test(token)) escaped.add(token);
      if (token !== "(") afterAddress = token === "&";
    }
  }

  const origins = new Map<string, Omit<FileHandleOrigin, "column">>();
  let boundary = false, depth = 0, blocks = 0;
  for (const [line, row] of rows.entries()) {
    if (!row.length) continue;
    const tokens = row.map(([token]) => token);
    const last = tokens.at(-1);
    const starts = boundary && depth === 0 && blocks === 1;
    for (const token of tokens) {
      if (token === "(" || token === "[") depth++;
      if (token === ")" || token === "]") depth--;
      if (token === "{") blocks++;
      if (token === "}") blocks--;
    }
    boundary = depth === 0 && (last === ";" || last === "{" || last === "}");
    if (!starts || depth !== 0 || last !== ";" || tokens.slice(0, -1).some((t) => CONTROL.test(t))) {
      origins.clear();
      continue;
    }

    if (tokens.length === 3 && tokens[0] === "HANDLE" && IDENTIFIER.test(tokens[1])) locals.add(tokens[1]);
    const callAt = tokens[1] === "=" ? 2 : 0;
    const name = tokens[callAt];
    const api = API.exec(name)?.[1];
    const argAt = callAt + 2;
    const arg = tokens[argAt];
    const direct = api && isImport(name) && tokens[callAt + 1] === "(" &&
      endsWithCall(tokens, callAt + 1);
    const handle = direct && api === "ReadFile" && tokens[argAt + 1] === "," && IDENTIFIER.test(arg) &&
      tokens.indexOf(arg) === argAt && tokens.lastIndexOf(arg) === argAt ? arg : undefined;
    const origin = handle ? origins.get(handle) : undefined;
    if (origin) hints.set(line, { ...origin, column: row[argAt].index! });

    // A mention outside the known read may write, close, or pass the handle elsewhere.
    for (const token of tokens) if (token !== handle) origins.delete(token);
    if (direct && api !== "ReadFile" && callAt === 2 && locals.has(tokens[0]) && !escaped.has(tokens[0])) {
      origins.set(tokens[0], { line, api, path: tokens[argAt + 1] === "," && /^L?"/.test(arg) ? arg : undefined });
    }
  }
  return hints;
}

function endsWithCall(tokens: string[], open: number): boolean {
  let depth = 0;
  for (let i = open; i < tokens.length; i++) {
    if (tokens[i] === "(") depth++;
    if (tokens[i] === ")" && --depth === 0) return i === tokens.length - 2;
  }
  return false;
}
