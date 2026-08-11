import { useCallback, useEffect, useRef, useState } from "react";
import { Activity, Download, Laptop, Monitor, Pause, Play, RefreshCw } from "lucide-react";
import { api } from "./bridge";
import { type ChartSeries, TimeSeriesChart, useHistory } from "./DashChart";
import type { CaptureDiagnostics, DiagnosticsReport, DropCounters, NetworkDiagnostics, Platform, SetupSnapshot } from "./types";

const POLL_INTERVAL_MS = 1500;
const HISTORY_MAX_SAMPLES = 60;
const CHART_WINDOW_MS = 90_000;
const LANES = ["input", "control", "background"] as const;
type Lane = (typeof LANES)[number];

/** Mint = this computer, signal = paired computer, matching the console palette. */
const LOCAL_COLOR = "#a9e5c8";
const PEER_COLOR = "#ff6b35";

/** Derived per-second rates between two consecutive telemetry snapshots. */
interface NetRate {
  outBps: number;
  inBps: number;
  outFps: number;
  inFps: number;
}

interface SampleHost {
  rttMs: number | null;
  outBps: number | null;
  inBps: number | null;
}

interface DashSample {
  t: number;
  local: SampleHost | null;
  peer: SampleHost | null;
}

function hostIp(address: string | undefined): string {
  if (!address) return "";
  if (address.startsWith("[")) return address.slice(1, address.indexOf("]"));
  return address.slice(0, address.lastIndexOf(":"));
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function formatRate(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

function formatNumber(value: number): string {
  return value.toLocaleString();
}

function formatUptime(ms: number): string {
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function deriveRate(prev: NetworkDiagnostics | null, curr: NetworkDiagnostics | null, dtMs: number): NetRate | null {
  if (!prev || !curr || dtMs <= 0) return null;
  const dt = dtMs / 1000;
  return {
    outBps: Math.max(0, (curr.outboundBytes - prev.outboundBytes) / dt),
    inBps: Math.max(0, (curr.inboundBytes - prev.inboundBytes) / dt),
    outFps: Math.max(0, (curr.outboundFrames - prev.outboundFrames) / dt),
    inFps: Math.max(0, (curr.inboundFrames - prev.inboundFrames) / dt),
  };
}

function laneValue(counters: DropCounters, lane: Lane): number {
  return counters[lane];
}

function totalDrops(counters: DropCounters): number {
  return counters.input + counters.control + counters.background;
}

export function DiagnosticsDashboard({ snapshot }: { snapshot: SetupSnapshot }) {
  const localIp = hostIp(snapshot.local?.address);
  const peerIp = hostIp(snapshot.peer?.address);

  const [localReport, setLocalReport] = useState<DiagnosticsReport | null>(null);
  const [peerReport, setPeerReport] = useState<DiagnosticsReport | null>(null);
  const [localRate, setLocalRate] = useState<NetRate | null>(null);
  const [peerRate, setPeerRate] = useState<NetRate | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [paused, setPaused] = useState(false);
  const [history, appendSample] = useHistory<DashSample>(HISTORY_MAX_SAMPLES);

  const prevRef = useRef<{ at: number; local: NetworkDiagnostics | null; peer: NetworkDiagnostics | null } | null>(null);

  // Extracted so the "Refresh now" control can pull a single snapshot even while
  // the periodic poll is paused. Wrapped in an in-flight guard so a slow host
  // cannot stack overlapping polls and race the rate derivation.
  const inFlightRef = useRef(false);
  const poll = useCallback(async () => {
    if (!localIp || inFlightRef.current) return;
    inFlightRef.current = true;
    try {
      const [local, peer] = await Promise.all([
        api.fetchDiagnostics(localIp),
        peerIp ? api.fetchDiagnostics(peerIp) : Promise.resolve<DiagnosticsReport | null>(null),
      ]);

      const now = Date.now();
      const prev = prevRef.current;
      const localDerived = deriveRate(prev?.local ?? null, local?.network ?? null, prev ? now - prev.at : 0);
      const peerDerived = deriveRate(prev?.peer ?? null, peer?.network ?? null, prev ? now - prev.at : 0);
      setLocalRate(localDerived);
      setPeerRate(peerDerived);
      prevRef.current = { at: now, local: local?.network ?? null, peer: peer?.network ?? null };

      appendSample({
        t: now,
        local: local ? { rttMs: local.network?.lastRttMs ?? null, outBps: localDerived?.outBps ?? null, inBps: localDerived?.inBps ?? null } : null,
        peer: peer ? { rttMs: peer.network?.lastRttMs ?? null, outBps: peerDerived?.outBps ?? null, inBps: peerDerived?.inBps ?? null } : null,
      });

      setLocalReport(local);
      setPeerReport(peer);
      setUpdatedAt(now);
    } finally {
      inFlightRef.current = false;
    }
  }, [localIp, peerIp, appendSample]);

  useEffect(() => {
    if (!localIp || paused) return;
    void poll();
    const timer = window.setInterval(() => void poll(), POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [localIp, paused, poll]);

  // Serializes the current pair of reports to a JSON download. The diagnostics
  // channel already carries only aggregate counters, so the export holds no
  // payloads, credentials, or peer addresses.
  const exportSnapshot = useCallback(() => {
    const payload = {
      exportedAtUnixMs: Date.now(),
      schemaVersion: localReport?.schemaVersion ?? peerReport?.schemaVersion ?? 1,
      local: localReport,
      peer: peerReport,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `skvm-diagnostics-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }, [localReport, peerReport]);

  const localName = snapshot.local?.displayName ?? "This computer";
  const peerName = snapshot.peer?.displayName ?? "Paired computer";
  const peerPlatform: Platform = snapshot.peer?.platform ?? (snapshot.platform === "macos" ? "windows" : "macos");

  const rttSeries: ChartSeries[] = [
    { id: "rtt-local", label: localName, color: LOCAL_COLOR, points: history.map((sample) => ({ t: sample.t, y: sample.local?.rttMs ?? null })) },
    { id: "rtt-peer", label: peerName, color: PEER_COLOR, points: history.map((sample) => ({ t: sample.t, y: sample.peer?.rttMs ?? null })) },
  ];
  const outboundSeries: ChartSeries[] = [
    { id: "out-local", label: localName, color: LOCAL_COLOR, points: history.map((sample) => ({ t: sample.t, y: sample.local?.outBps ?? null })) },
    { id: "out-peer", label: peerName, color: PEER_COLOR, points: history.map((sample) => ({ t: sample.t, y: sample.peer?.outBps ?? null })) },
  ];
  const inboundSeries: ChartSeries[] = [
    { id: "in-local", label: localName, color: LOCAL_COLOR, points: history.map((sample) => ({ t: sample.t, y: sample.local?.inBps ?? null })) },
    { id: "in-peer", label: peerName, color: PEER_COLOR, points: history.map((sample) => ({ t: sample.t, y: sample.peer?.inBps ?? null })) },
  ];

  return (
    <section className="dashboard enter" aria-label="Live diagnostics dashboard">
      <header className="dashboard-head">
        <div>
          <div className="eyebrow">DIAGNOSTICS · SEPARATE CHANNEL · 24801</div>
          <h2>Live session monitor</h2>
          <p>
            Aggregate counters and redacted distributions pulled over a dedicated read-only connection — distinct from the
            active KVM switch on 24800. No input payloads, credentials, or peer addresses leave either host.
          </p>
        </div>
        <div className="dashboard-controls">
          <button
            type="button"
            className="dash-btn"
            onClick={() => void poll()}
            disabled={!localIp}
            title="Poll both hosts once now"
          >
            <RefreshCw size={13} /> Refresh
          </button>
          <button
            type="button"
            className={`dash-btn${paused ? " active" : ""}`}
            onClick={() => setPaused((wasPaused) => !wasPaused)}
            aria-pressed={paused}
            title={paused ? "Resume periodic polling" : "Pause periodic polling"}
          >
            {paused ? (<><Play size={13} /> Resume</>) : (<><Pause size={13} /> Pause</>)}
          </button>
          <button
            type="button"
            className="dash-btn"
            onClick={exportSnapshot}
            disabled={!localReport && !peerReport}
            title="Download the current diagnostics pair as JSON"
          >
            <Download size={13} /> Export
          </button>
          <div className={`dashboard-pulse${paused ? " paused" : ""}`} aria-live="polite">
            <i />
            {paused ? "Paused" : updatedAt ? `Updated ${new Date(updatedAt).toLocaleTimeString()}` : "Connecting…"}
          </div>
        </div>
      </header>

      <div className="dash-host-grid">
        <HostCard
          kind="local"
          name={localName}
          platform={snapshot.platform}
          report={localReport}
          rate={localRate}
          hasPeer={!!snapshot.peer}
        />
        <HostCard
          kind="peer"
          name={peerName}
          platform={peerPlatform}
          report={peerReport}
          rate={peerRate}
          hasPeer={!!snapshot.peer}
        />
      </div>

      <div className="dash-charts-grid">
        <div className="dash-chart-wide">
          <TimeSeriesChart
            title="Round-trip latency"
            windowMs={CHART_WINDOW_MS}
            series={rttSeries}
            yFormat={(value) => `${Math.round(value)} ms`}
          />
        </div>
        <TimeSeriesChart
          title="Outbound throughput"
          windowMs={CHART_WINDOW_MS}
          series={outboundSeries}
          yFormat={(value) => formatBytes(value)}
        />
        <TimeSeriesChart
          title="Inbound throughput"
          windowMs={CHART_WINDOW_MS}
          series={inboundSeries}
          yFormat={(value) => formatBytes(value)}
        />
      </div>

      <NetworkTable label="Network activity" local={localReport} peer={peerReport} localRate={localRate} peerRate={peerRate} />

      <QueueHealthTable label="Queue health · per traffic lane" local={localReport} peer={peerReport} />

      <CaptureTable label="Native input capture · aggregate counters" local={localReport} peer={peerReport} />

      <div className="dash-foot">
        <span>
          <Activity size={12} /> {paused ? "Polling paused" : `Polling every ${(POLL_INTERVAL_MS / 1000).toFixed(1)}s`} · read-only · schema v
          {localReport?.schemaVersion ?? peerReport?.schemaVersion ?? 1}
        </span>
        <span>Pause freezes the live view · Export saves the current pair as JSON · failure counters highlight orange.</span>
      </div>
    </section>
  );
}

function HostCard({
  kind,
  name,
  platform,
  report,
  rate,
  hasPeer,
}: {
  kind: "local" | "peer";
  name: string;
  platform: Platform;
  report: DiagnosticsReport | null;
  rate: NetRate | null;
  hasPeer: boolean;
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
        </span>
        <span>
          <small>COALESCED MOVES</small>
          <code>{net ? formatNumber(net.coalescedMoves) : "—"}</code>
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

function NetworkTable({
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
  const rows: Array<{ metric: string; local: string; localSub?: string; peer: string; peerSub?: string }> = [
    {
      metric: "Outbound throughput",
      local: localRate ? formatRate(localRate.outBps) : localNet ? "—" : "—",
      localSub: localNet ? `${formatNumber(localNet.outboundFrames)} frames` : undefined,
      peer: peerRate ? formatRate(peerRate.outBps) : "—",
      peerSub: peerNet ? `${formatNumber(peerNet.outboundFrames)} frames` : undefined,
    },
    {
      metric: "Inbound throughput",
      local: localRate ? formatRate(localRate.inBps) : "—",
      localSub: localNet ? `${formatNumber(localNet.inboundFrames)} frames` : undefined,
      peer: peerRate ? formatRate(peerRate.inBps) : "—",
      peerSub: peerNet ? `${formatNumber(peerNet.inboundFrames)} frames` : undefined,
    },
    {
      metric: "Last RTT",
      local: localNet?.lastRttMs != null ? `${localNet.lastRttMs} ms` : "—",
      peer: peerNet?.lastRttMs != null ? `${peerNet.lastRttMs} ms` : "—",
    },
    {
      metric: "Coalesced pointer moves",
      local: localNet ? formatNumber(localNet.coalescedMoves) : "—",
      peer: peerNet ? formatNumber(peerNet.coalescedMoves) : "—",
    },
  ];

  return (
    <div className="dash-table-wrap">
      <div className="dash-table-title">
        <span>{label}</span>
        <em>CUMULATIVE · LIVE</em>
      </div>
      <table className="dash-table">
        <thead>
          <tr>
            <th scope="col">Metric</th>
            <th scope="col">This computer</th>
            <th scope="col">Paired computer</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
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

function QueueHealthTable({
  label,
  local,
  peer,
}: {
  label: string;
  local: DiagnosticsReport | null;
  peer: DiagnosticsReport | null;
}) {
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

function CaptureTable({
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

  return (
    <div className="dash-table-wrap">
      <div className="dash-table-title">
        <span>{label}</span>
        <em>AGGREGATE COUNTERS · NO PAYLOADS</em>
      </div>
      <table className="dash-table">
        <thead>
          <tr>
            <th scope="col">Counter</th>
            <th scope="col">This computer</th>
            <th scope="col">Paired computer</th>
          </tr>
        </thead>
        <tbody>
          {CAPTURE_ROWS.map((row) => {
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
