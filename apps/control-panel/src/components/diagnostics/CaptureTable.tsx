import type { CaptureDiagnostics, DiagnosticsReport } from "../../types";
import { formatNumber } from "../../lib/format";
import { SortTh, useSort } from "./sortable";

/** One capture-counter row: its accessor on CaptureDiagnostics, a human label,
 *  and whether a non-zero value is a *failure* signal (highlighted orange). */
interface CaptureRow {
  key: keyof CaptureDiagnostics;
  label: string;
  failure: boolean;
}

const CAPTURE_ROWS: CaptureRow[] = [
  { key: "observed", label: "Events observed", failure: false },
  { key: "suppressed", label: "Suppressed (remote routing)", failure: false },
  { key: "allowedLocal", label: "Allowed locally (fail-open)", failure: false },
  { key: "pointerObservations", label: "Pointer observations", failure: false },
  { key: "pointerTransitions", label: "Pointer handoff transitions", failure: false },
  { key: "cursorHides", label: "Cursor hides", failure: false },
  { key: "cursorShows", label: "Cursor shows", failure: false },
  { key: "cursorWarps", label: "Cursor warps", failure: false },
  { key: "lockContention", label: "Lock contention", failure: true },
  { key: "callbackPanics", label: "Callback panics", failure: true },
  { key: "pointerObservationFailures", label: "Pointer observation failures", failure: true },
];

type CaptureSortKey = "counter" | "local" | "peer";

/** The sortable native input-capture counters table. Extracted from
 *  DiagnosticsDashboard.tsx verbatim — no behavior changes. */
export function CaptureTable({
  label,
  local,
  peer,
}: {
  label: string;
  local: DiagnosticsReport | null;
  peer: DiagnosticsReport | null;
}) {
  const localCap = local?.capture ?? null;
  const peerCap = peer?.capture ?? null;
  const seen = localCap ?? peerCap;
  const { key: sortKey, dir, toggle } = useSort<CaptureSortKey>("counter", "asc");

  const valueFor = (row: CaptureRow, host: "local" | "peer"): number => {
    const cap = host === "local" ? localCap : peerCap;
    return cap ? cap[row.key] : -1;
  };

  // Stable sort: a copy of CAPTURE_ROWS ordered by the active column. Numeric
  // columns compare the raw counter (missing -> -1 so absent values sink in
  // descending order); the Counter column is alphabetical by label.
  const sortedRows = [...CAPTURE_ROWS].sort((a, b) => {
    let cmp: number;
    if (sortKey === "counter") {
      cmp = a.label.localeCompare(b.label);
    } else {
      cmp = valueFor(a, sortKey) - valueFor(b, sortKey);
    }
    return dir === "asc" ? cmp : -cmp;
  });

  return (
    <div className="dash-table-wrap">
      <div className="dash-table-title">
        <span>{label}</span>
        <em>SORTABLE · AGGREGATE COUNTERS</em>
      </div>
      <table className="dash-table">
        <thead>
          <tr>
            <SortTh text="Counter" active={sortKey === "counter"} dir={dir} onClick={() => toggle("counter")} />
            <SortTh text="This computer" active={sortKey === "local"} dir={dir} onClick={() => toggle("local")} />
            <SortTh text="Paired computer" active={sortKey === "peer"} dir={dir} onClick={() => toggle("peer")} />
          </tr>
        </thead>
        <tbody>
          {sortedRows.map((row) => {
            const lv = localCap ? localCap[row.key] : null;
            const pv = peerCap ? peerCap[row.key] : null;
            return (
              <tr key={row.key}>
                <td className="label">{row.label}</td>
                <td className={row.failure && lv && lv > 0 ? "neg" : ""}>{lv != null ? formatNumber(lv) : "—"}</td>
                <td className={row.failure && pv && pv > 0 ? "neg" : ""}>{pv != null ? formatNumber(pv) : "—"}</td>
              </tr>
            );
          })}
          {!seen && (
            <tr>
              <td className="label">Waiting for capture supervisor…</td>
              <td>—</td>
              <td>—</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
