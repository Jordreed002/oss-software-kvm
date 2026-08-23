import { Laptop, Monitor } from "lucide-react";
import { Sparkline } from "../../DashChart";
import { formatBytes, formatNumber, formatRate, formatUptime } from "../../lib/format";
import type { DiagnosticsReport, Platform } from "../../types";
import { LOCAL_COLOR, PEER_COLOR, NetRate, totalDrops } from "./model";

/** One host's summary card: identity, live/offline status, headline stats, and
 *  the compact meta grid (host id, drops sparkline, pointer fast path).
 *  Extracted from DiagnosticsDashboard.tsx verbatim — no behavior changes. */
export function HostCard({
  kind,
  name,
  platform,
  report,
  rate,
  hasPeer,
  dropSeries,
}: {
  kind: "local" | "peer";
  name: string;
  platform: Platform;
  report: DiagnosticsReport | null;
  rate: NetRate | null;
  hasPeer: boolean;
  dropSeries: number[];
}) {
  const online = !!report;
  const net = report?.network ?? null;
  const missing = kind === "peer" && !hasPeer;

  return (
    <article className={`dash-host ${kind} ${online ? "" : "offline"}`}>
      <div className="dash-host-head">
        <span className="dash-host-icon">{platform === "macos" ? <Laptop size={20} /> : <Monitor size={20} />}</span>
        <div>
          <small>{kind === "local" ? "THIS COMPUTER" : "PAIRED COMPUTER"}</small>
          <strong>{name}</strong>
        </div>
        <span className={`dash-status ${online ? "" : "offline"}`}>
          {missing ? "NO PEER" : online ? (net ? "LIVE" : "IDLE") : "OFFLINE"}
        </span>
      </div>

      <div className="dash-stat-grid">
        <Stat label="Uptime" value={report ? formatUptime(report.uptimeMs) : "—"} />
        <Stat
          label="Last RTT"
          value={net?.lastRttMs != null ? `${net.lastRttMs} ms` : "—"}
          accent={net?.lastRttMs != null && net.lastRttMs > 30 ? "neg" : undefined}
        />
        <Stat
          label="Outbound"
          value={rate ? formatRate(rate.outBps) : "—"}
          sub={net ? formatBytes(net.outboundBytes) : undefined}
        />
        <Stat
          label="Inbound"
          value={rate ? formatRate(rate.inBps) : "—"}
          sub={net ? formatBytes(net.inboundBytes) : undefined}
        />
      </div>

      <div className="dash-host-meta">
        <span>
          <small>HOST ID</small>
          <code>{report ? report.hostId.slice(0, 8) : "—"}</code>
        </span>
        <span>
          <small>DROPS</small>
          <code className={net && totalDrops(net.dropped) > 0 ? "neg" : ""}>
            {net ? formatNumber(totalDrops(net.dropped)) : "—"}
          </code>
          {dropSeries.length > 0 && (
            <Sparkline values={dropSeries} color={kind === "local" ? LOCAL_COLOR : PEER_COLOR} />
          )}
        </span>
        <span>
          <small>COALESCED MOVES</small>
          <code>{net ? formatNumber(net.coalescedMoves) : "—"}</code>
        </span>
        <span>
          <small>POINTER FAST PATH</small>
          <code className={net && !net.pointerDatagramActive ? "neg" : ""}>
            {net ? (net.pointerDatagramActive ? "UDP ACTIVE" : "TCP FALLBACK") : "—"}
          </code>
          {net && <small>{formatNumber(net.pointerDatagramsOutbound)} TX · {formatNumber(net.pointerDatagramsInbound)} RX</small>}
          {net && <small>{formatNumber(net.pointerDatagramGaps)} gaps · {(net.pointerDatagramJitterUs / 1000).toFixed(1)} ms jitter · {formatNumber(net.pointerDatagramMaxSilenceMs)} ms max silence</small>}
          {net && <small>jitter p50 {(net.pointerJitterP50Us / 1000).toFixed(1)} · p95 {(net.pointerJitterP95Us / 1000).toFixed(1)} · p99 {(net.pointerJitterP99Us / 1000).toFixed(1)} ms</small>}
          {net && <small>{formatNumber(net.reliableDatagramsOutbound)} / {formatNumber(net.reliableDatagramsInbound)} reliable · {formatNumber(net.reliableDatagramRetransmits)} retries</small>}
        </span>
      </div>
    </article>
  );
}

function Stat({ label, value, sub, accent }: { label: string; value: string; sub?: string; accent?: "neg" }) {
  return (
    <div className="dash-stat">
      <span>{label}</span>
      <strong className={accent ?? ""}>{value}</strong>
      {sub && <em>{sub}</em>}
    </div>
  );
}
