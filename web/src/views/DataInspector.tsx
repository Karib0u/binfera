import { inspect } from "../engine/inspect";

/** What the bytes under the cursor mean, in both byte orders. */
export function DataInspector({ bytes, off }: { bytes: Uint8Array; off: number }) {
  const rows = inspect(bytes, off);
  return (
    <div className="inspector" role="region" aria-label="Data inspector">
      <table>
        <thead><tr><th>At offset {"0x" + off.toString(16)}</th><th>Little-endian</th><th>Big-endian</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label}>
              <th scope="row">{r.label}</th>
              {r.single ? <td colSpan={2}><code>{r.le}</code></td> : <><td><code>{r.le ?? "–"}</code></td><td><code>{r.be ?? "–"}</code></td></>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
