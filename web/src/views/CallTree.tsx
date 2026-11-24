import { useState } from "react";

const hex = (n: number) => "0x" + n.toString(16);
/** Past this many rows a level asks before showing the rest. */
const PAGE = 40;

export type TreeDirection = "callers" | "callees";

interface TreeProps {
  dir: TreeDirection;
  /** The next functions in the chosen direction. */
  edges: (ad: number) => number[] | undefined;
  /** Imported APIs a function calls: leaves of a callee tree. */
  apis?: (ad: number) => string[] | undefined; onApi?: (name: string) => void;
  label: (ad: number) => string; caps: (ad: number) => string[];
  onOpen: (ad: number) => void;
}

/**
 * The call graph as a list: one function's callers or callees, each expandable into its own, as deep as wanted.
 * On a phone this replaces a pannable graph: rows read at full size and every one is a thumb-sized target.
 */
export function CallTree({ root, ...props }: TreeProps & { root: number }) {
  const fns = props.edges(root) ?? [], apis = props.apis?.(root) ?? [];
  if (!fns.length && !apis.length) return <p className="ct-empty">{props.dir === "callers" ? "Nothing in this file calls this function." : "This function makes no calls."}</p>;
  return <ul className="ct" role="tree" aria-label={props.dir === "callers" ? "Callers" : "Calls"}><Level fns={fns} names={apis} path={[root]} {...props} /></ul>;
}

function Level({ fns, names, path, ...props }: TreeProps & { fns: number[]; names: string[]; path: number[] }) {
  const [limit, setLimit] = useState(PAGE);
  const depth = { "--depth": path.length - 1 } as React.CSSProperties;
  const rows = [...fns.map((ad) => ({ ad })), ...names.map((name) => ({ name }))];
  return (
    <>
      {rows.slice(0, limit).map((r) => "ad" in r
        ? <Row key={r.ad} ad={r.ad} path={path} {...props} />
        : (
          <li key={"api:" + r.name} role="treeitem" style={depth}>
            <div className="ct-row api">
              <span className="ct-tog leaf" aria-hidden />
              <button className="ct-fn api" onClick={() => props.onApi?.(r.name)} aria-label={r.name + ", imported API"}><code>{r.name}</code><small>API</small></button>
            </div>
          </li>
        ))}
      {rows.length > limit && <li className="ct-more" style={depth}><button onClick={() => setLimit(limit + PAGE * 4)}>Show {rows.length - limit} more</button></li>}
    </>
  );
}

function Row({ ad, path, ...props }: TreeProps & { ad: number; path: number[] }) {
  const { edges, apis, label, caps, onOpen } = props;
  const [open, setOpen] = useState(false);
  const loop = path.includes(ad);
  const fns = loop ? [] : edges(ad) ?? [], names = loop ? [] : apis?.(ad) ?? [];
  const n = fns.length + names.length;
  const c = caps(ad);
  return (
    <li role="treeitem" aria-expanded={n ? open : undefined} style={{ "--depth": path.length - 1 } as React.CSSProperties}>
      <div className="ct-row">
        {n > 0
          ? <button className={"ct-tog" + (open ? " open" : "")} aria-label={(open ? "Collapse " : "Expand ") + label(ad)} onClick={() => setOpen(!open)}>
              <svg viewBox="0 0 24 24" aria-hidden><path d="M9 6l6 6-6 6" /></svg>
            </button>
          : <span className="ct-tog leaf" aria-hidden />}
        <button className="ct-fn" onClick={() => onOpen(ad)}>
          <code>{label(ad)}</code>
          <small>{loop ? "recursive call" : [
            n ? `${n} ${props.dir === "callers" ? (n === 1 ? "caller" : "callers") : (n === 1 ? "call" : "calls")}` : "",
            c.length ? c.slice(0, 2).join(" · ") + (c.length > 2 ? ` · +${c.length - 2}` : "") : hex(ad),
          ].filter(Boolean).join(" · ")}</small>
        </button>
        {c.length > 0 && <span className="pill" title={c.join("\n")}>{c.length}</span>}
      </div>
      {open && n > 0 && <ul role="group"><Level fns={fns} names={names} path={[...path, ad]} {...props} /></ul>}
    </li>
  );
}
