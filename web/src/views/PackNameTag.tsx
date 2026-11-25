import { useNotes } from "../names";

/**
 * Marks a function label that comes from a BXFAM003 pack's Trusted symbols rather than the file,
 * a signature or the analyst. Renders nothing when another name wins.
 */
export function PackNameTag({ at, name }: { at: number; name?: string | null }) {
  const trusted = useNotes().trustedLabel(at, name);
  if (!trusted) return null;
  return (
    <span className="exp-tag pack-tag" title={trusted.detail}>
      {trusted.source ? `Trusted · ${trusted.source}` : "Trusted"}
    </span>
  );
}
