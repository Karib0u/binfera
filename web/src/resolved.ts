import type { ImportEntry } from "./engine/image";

/**
 * The globals the decompiler found loaded with `GetProcAddress` and a literal name, shaped like
 * import slots so the assembly, the graph and the Listing treat them as imports. They have no
 * library: the program resolved them itself.
 */
export function resolvedSlots(resolved: ReadonlyMap<number, string> | undefined): ImportEntry[] {
  return [...(resolved ?? [])].map(([va, name]) => ({ dll: "", name, va }));
}

/** Where an operand's tooltip says an import slot comes from. */
export const slotSource = (slot: { dll: string }) => slot.dll || "resolved at run time";
