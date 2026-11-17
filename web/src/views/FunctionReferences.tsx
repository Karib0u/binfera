import { useState } from "react";

/** Keep each row compact until the user asks to see all of its references. */
export function FunctionReferences({ addresses, limit, label, onSelect }: {
  addresses: number[]; limit: number; label: (address: number) => string; onSelect: (address: number) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const remaining = addresses.length - limit;
  const refButton = (address: number) => (
    <button type="button" key={address} onClick={(event) => {
      event.stopPropagation();
      onSelect(address);
    }}>{label(address)}</button>
  );

  return (
    <>
      {addresses.slice(0, limit).map(refButton)}
      {remaining > 0 && (
        <button type="button" aria-expanded={expanded}
          aria-label={expanded ? undefined : `+${remaining} more function references`}
          onClick={(event) => { event.stopPropagation(); setExpanded(!expanded); }}>
          {expanded ? "Show less" : `+${remaining} more`}
        </button>
      )}
      {expanded && addresses.slice(limit).map(refButton)}
    </>
  );
}
