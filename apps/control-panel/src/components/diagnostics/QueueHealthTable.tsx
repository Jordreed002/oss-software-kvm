import type { DiagnosticsReport } from "../../types";
import { formatNumber } from "../../lib/format";
import { LANES, laneValue } from "./model";

/** Per-traffic-lane drop/rejection counts for both hosts. Extracted from
 *  DiagnosticsDashboard.tsx verbatim — no behavior changes. */
export function QueueHealthTable(
  { label, local, peer }: { label: string; local: DiagnosticsReport | null; peer: DiagnosticsReport | null },
) {
  const localNet = local?.network ?? null;
  const peerNet = peer?.network ?? null;

  return (
    <div className="dash-table-wrap">
      <div className="dash-table-title">
        <span>{label}</span>
        <em>DROPS · CHANNEL REJECTIONS</em>
      </div>
      <table className="dash-table">
        <thead>
          <tr>
            <th scope="col">Lane</th>
            <th scope="col">Drops · local</th>
            <th scope="col">Rejects · local</th>
            <th scope="col">Drops · peer</th>
            <th scope="col">Rejects · peer</th>
          </tr>
        </thead>
        <tbody>
          {LANES.map((lane) => {
            const ld = localNet ? laneValue(localNet.dropped, lane) : null;
            const lr = localNet ? laneValue(localNet.channelRejections, lane) : null;
            const pd = peerNet ? laneValue(peerNet.dropped, lane) : null;
            const pr = peerNet ? laneValue(peerNet.channelRejections, lane) : null;
            return (
              <tr key={lane}>
                <td className="label">
                  <span className="dash-lane-badge">{lane}</span>
                </td>
                <td className={ld && ld > 0 ? "neg" : ""}>{ld != null ? formatNumber(ld) : "—"}</td>
                <td className={lr && lr > 0 ? "neg" : ""}>{lr != null ? formatNumber(lr) : "—"}</td>
                <td className={pd && pd > 0 ? "neg" : ""}>{pd != null ? formatNumber(pd) : "—"}</td>
                <td className={pr && pr > 0 ? "neg" : ""}>{pr != null ? formatNumber(pr) : "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
