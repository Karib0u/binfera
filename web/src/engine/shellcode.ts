export type ShellcodeEncoding = "binary" | "hex text" | "escaped hex";

/** Decode only complete byte literals. Source text is never evaluated or partially extracted. */
export function decodeShellcodeInput(input: ArrayBuffer): { bytes: ArrayBuffer; encoding: ShellcodeEncoding } {
  const binary = { bytes: input, encoding: "binary" as const };
  const view = new Uint8Array(input);
  if (!view.length || view.length > 1048576 || view.some(b => b > 126 || (b < 32 && b !== 9 && b !== 10 && b !== 13))) return binary;
  let text = new TextDecoder().decode(view).trim();
  // Common C/Python assignments are wrappers around the literal, not instructions to run.
  text = text.replace(/^(?:(?:unsigned\s+)?char\s+|u?int8_t\s+)?[A-Za-z_]\w*(?:\s*\[\s*\d*\s*\])?\s*=\s*/, "").replace(/;\s*$/, "").trim();
  const escaped = /^(?:\\x[0-9a-f]{2}\s*)+$/i.test(text)
    || /^(?:b?(?:"(?:\\x[0-9a-f]{2})+"|'(?:\\x[0-9a-f]{2})+')\s*)+$/i.test(text);
  if (escaped) return {
    bytes: Uint8Array.from([...text.matchAll(/\\x([0-9a-f]{2})/gi)], m => parseInt(m[1], 16)).buffer,
    encoding: "escaped hex",
  };
  if ((text.startsWith("[") && text.endsWith("]")) || (text.startsWith("{") && text.endsWith("}"))) text = text.slice(1, -1).trim();
  if (/^(?:[0-9a-f]{2})+$/i.test(text)) return {
    bytes: Uint8Array.from(text.match(/../g)!, b => parseInt(b, 16)).buffer, encoding: "hex text",
  };
  if (/,\s*,/.test(text)) return binary;
  const tokens = text.replace(/,\s*$/, "").split(/[\s,]+/);
  if (tokens.length && tokens.every(t => /^(?:0x)?[0-9a-f]{2}$/i.test(t))) return {
    bytes: Uint8Array.from(tokens, t => parseInt(t.replace(/^0x/i, ""), 16)).buffer, encoding: "hex text",
  };
  return binary;
}

export function shellcodePayload(input: ArrayBuffer, offset = 0) {
  const decoded = decodeShellcodeInput(input);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= decoded.bytes.byteLength) {
    throw new Error("Start offset must be within the decoded input bytes.");
  }
  return { ...decoded, inputSize: decoded.bytes.byteLength, bytes: offset ? decoded.bytes.slice(offset) : decoded.bytes };
}
