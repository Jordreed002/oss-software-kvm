import type { DiagnosticsReport } from "../../types";
import { formatNumber, formatRate } from "../../lib/format";
import { NetRate } from "./model";
import { SortTh, useSort } from "./sortable";

/** The sortable "Network activity" comparison table. Each row carries its raw
 *  numeric value alongside the formatted display string so the column headers
 *  can sort by magnitude. Units differ across rows (B/s, ms, count), so a
 *  magnitude sort ranks within whatever column is active — the units stay
 *  visible in the cells. Extracted from DiagnosticsDashboard.tsx verbatim. */
export function NetworkTable({
  label,
  local,
  peer,
  localRate,
  peerRate,
}: {
  label: string;
  local: DiagnosticsReport | null;
  peer: DiagnosticsReport | null;
  localRate: NetRate | null;
  peerRate: NetRate | null;
}) {
  const localNet = local?.network ?? null;
  const peerNet = peer?.network ?? null;
  type NetSortKey = "metric" | "local" | "peer";
  const rows: Array<{ metric: string; local: string; localSub?: string; peer: string; peerSub?: string; localValue: number | null; peerValue: number | null }> = [
    {
      metric: "Outbound throughput",
      local: localRate ? formatRate(localRate.outBps) : "—",
      localSub: localNet ? `${formatNumber(localNet.outboundFrames)} frames` : undefined,
      peer: peerRate ? formatRate(peerRate.outBps) : "—",
      peerSub: peerNet ? `${formatNumber(peerNet.outboundFrames)} frames` : undefined,
      localValue: localRate?.outBps ?? null,
      peerValue: peerRate?.outBps ?? null,
    },
    {
      metric: "Inbound throughput",
      local: localRate ? formatRate(localRate.inBps) : "—",
      localSub: localNet ? `${formatNumber(localNet.inboundFrames)} frames` : undefined,
      peer: peerRate ? formatRate(peerRate.inBps) : "—",
      peerSub: peerNet ? `${formatNumber(peerNet.inboundFrames)} frames` : undefined,
      localValue: localRate?.inBps ?? null,
      peerValue: peerRate?.inBps ?? null,
    },
    {
      metric: "Last RTT",
      local: localNet?.lastRttMs != null ? `${localNet.lastRttMs} ms` : "—",
      peer: peerNet?.lastRttMs != null ? `${peerNet.lastRttMs} ms` : "—",
      localValue: localNet?.lastRttMs ?? null,
      peerValue: peerNet?.lastRttMs ?? null,
    },
    {
      metric: "Coalesced pointer moves",
      local: localNet ? formatNumber(localNet.coalescedMoves) : "—",
      peer: peerNet ? formatNumber(peerNet.coalescedMoves) : "—",
      localValue: localNet?.coalescedMoves ?? null,
      peerValue: peerNet?.coalescedMoves ?? null,
    },
  ];
  const { key: sortKey, dir, toggle } = useSort<NetSortKey>("metric", "asc");
  const sortedRows = [...rows].sort((a, b) => {
    let cmp: number;
    if (sortKey === "metric") {
      cmp = a.metric.localeCompare(b.metric);
    } else {
      const av = (sortKey === "local" ? a.localValue : a.peerValue) ?? -1;
      const bv = (sortKey === "local" ? b.localValue : b.peerValue) ?? -1;
      cmp = av - bv;
    }
    return dir === "asc" ? cmp : -cmp;
  });

  return (
    <div className="dash-table-wrap">
      <div className="dash-table-title">
        <span>{label}</span>
        <em>SORTABLE · CUMULATIVE</em>
      </div>
      <table className="dash-table">
        <thead>
          <tr>
            <SortTh text="Metric" active={sortKey === "metric"} dir={dir} onClick={() => toggle("metric")} />
            <SortTh text="This computer" active={sortKey === "local"} dir={dir} onClick={() => toggle("local")} />
            <SortTh text="Paired computer" active={sortKey === "peer"} dir={dir} onClick={() => toggle("peer")} />
          </tr>
        </thead>
        <tbody>
          {sortedRows.map((row) => (
            <tr key={row.metric}>
              <td className="label">{row.metric}</td>
              <td>
                {row.local}
                {row.localSub && <div className="sub">{row.localSub}</div>}
              </td>
              <td>
                {row.peer}
                {row.peerSub && <div className="sub">{row.peerSub}</div>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
