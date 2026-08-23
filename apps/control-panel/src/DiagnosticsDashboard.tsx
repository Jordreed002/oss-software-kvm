import { useCallback, useEffect, useRef, useState } from "react";
import { Activity } from "lucide-react";
import { api } from "./bridge";
import { type ChartSeries, CompositionBar, type CompositionSegment, HealthMeter, TimeSeriesChart, useHistory } from "./DashChart";
import { CaptureTable } from "./components/diagnostics/CaptureTable";
import { DashboardToolbar } from "./components/diagnostics/DashboardToolbar";
import { HostCard } from "./components/diagnostics/HostCard";
import { NetworkTable } from "./components/diagnostics/NetworkTable";
import { QueueHealthTable } from "./components/diagnostics/QueueHealthTable";
import {
  CHART_WINDOW_MS, DashSample, HISTORY_MAX_SAMPLES, deriveRate, hostIp, LOCAL_COLOR, PEER_COLOR, NetRate, POLL_INTERVAL_MS, totalDrops,
} from "./components/diagnostics/model";
import { formatBytes, formatNumber } from "./lib/format";
import type { CaptureDiagnostics, DiagnosticsReport, NetworkDiagnostics, Platform, SetupSnapshot } from "./types";

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
        local: local ? { rttMs: local.network?.lastRttMs ?? null, outBps: localDerived?.outBps ?? null, inBps: localDerived?.inBps ?? null, drops: local.network ? totalDrops(local.network.dropped) : null } : null,
        peer: peer ? { rttMs: peer.network?.lastRttMs ?? null, outBps: peerDerived?.outBps ?? null, inBps: peerDerived?.inBps ?? null, drops: peer.network ? totalDrops(peer.network.dropped) : null } : null,
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

  // Point-in-time input-routing split: every observed event is either forwarded
  // to the peer (suppressed locally) or allowed to reach the local OS. A residual
  // "other" slice covers any observed events not accounted for by those two. The
  // ratio — not obvious from the raw capture table — is what this bar shows.
  const routingSegments = (cap: CaptureDiagnostics | null): CompositionSegment[] => {
    if (!cap) return [];
    const other = Math.max(0, cap.observed - cap.suppressed - cap.allowedLocal);
    const segments: CompositionSegment[] = [
      { label: "Remote-routed", value: cap.suppressed, color: PEER_COLOR },
      { label: "Allowed locally", value: cap.allowedLocal, color: LOCAL_COLOR },
    ];
    if (other > 0) segments.push({ label: "Other", value: other, color: "#5d6863" });
    return segments;
  };
  const compositionHosts = [
    ...(localReport?.capture ? [{ name: localName, segments: routingSegments(localReport.capture) }] : []),
    ...(peerReport?.capture ? [{ name: peerName, segments: routingSegments(peerReport.capture) }] : []),
  ];

  // Frame drop rate per host: of all frames the host tried to push through its
  // outbound queue, the fraction rejected by backpressure. A headline health
  // signal that the gauge surfaces at a glance.
  const dropFraction = (net: NetworkDiagnostics | null): number => {
    if (!net) return 0;
    const drops = totalDrops(net.dropped);
    const denom = drops + net.outboundFrames;
    return denom > 0 ? drops / denom : 0;
  };
  const healthHosts = [
    ...(localReport?.network ? [{ name: localName, fraction: dropFraction(localReport.network), detail: `${formatNumber(totalDrops(localReport.network.dropped))} drops · ${formatNumber(localReport.network.outboundFrames)} frames` }] : []),
    ...(peerReport?.network ? [{ name: peerName, fraction: dropFraction(peerReport.network), detail: `${formatNumber(totalDrops(peerReport.network.dropped))} drops · ${formatNumber(peerReport.network.outboundFrames)} frames` }] : []),
  ];

  // Difference the cumulative counter and normalize by elapsed wall time so
  // delayed or manual polls do not distort the per-second drop-rate trend.
  const dropRateSeries = (host: "local" | "peer"): number[] => {
    const out: number[] = [];
    let prev: { at: number; drops: number } | null = null;
    for (const sample of history) {
      const cumulative = (host === "local" ? sample.local?.drops : sample.peer?.drops) ?? null;
      if (cumulative != null) {
        const elapsedSeconds = prev ? (sample.t - prev.at) / 1000 : 0;
        out.push(prev && elapsedSeconds > 0 ? Math.max(0, cumulative - prev.drops) / elapsedSeconds : 0);
        prev = { at: sample.t, drops: cumulative };
      }
    }
    return out;
  };
  const localDropSeries = dropRateSeries("local");
  const peerDropSeries = dropRateSeries("peer");

  return (
    <section className="dashboard enter" aria-label="Live diagnostics dashboard">
      <DashboardToolbar
        paused={paused}
        updatedAt={updatedAt}
        canRefresh={!!localIp}
        canExport={!!localReport || !!peerReport}
        onRefresh={() => void poll()}
        onTogglePause={() => setPaused((wasPaused) => !wasPaused)}
        onExport={exportSnapshot}
      />

      <div className="dash-host-grid">
        <HostCard
          kind="local"
          name={localName}
          platform={snapshot.platform}
          report={localReport}
          rate={localRate}
          hasPeer={!!snapshot.peer}
          dropSeries={localDropSeries}
        />
        <HostCard
          kind="peer"
          name={peerName}
          platform={peerPlatform}
          report={peerReport}
          rate={peerRate}
          hasPeer={!!snapshot.peer}
          dropSeries={peerDropSeries}
        />
      </div>

      <HealthMeter title="Outbound drop health" badge="QUEUE" hosts={healthHosts} />

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

      <CompositionBar
        title="Input routing split"
        badge="CAPTURE"
        hosts={compositionHosts}
        valueFormat={formatNumber}
      />

      <NetworkTable label="Network activity" local={localReport} peer={peerReport} localRate={localRate} peerRate={peerRate} />

      <QueueHealthTable label="Queue health · per traffic lane" local={localReport} peer={peerReport} />

      <CaptureTable label="Native input capture · aggregate counters" local={localReport} peer={peerReport} />

      <div className="dash-foot">
        <span>
          <Activity size={12} /> {paused ? "Polling paused" : `Polling every ${(POLL_INTERVAL_MS / 1000).toFixed(1)}s`} · read-only · schema v
          {localReport?.schemaVersion ?? peerReport?.schemaVersion ?? 1}
        </span>
        <span>Pause freezes the live view · Export saves the current pair as JSON · click table columns to sort.</span>
      </div>
    </section>
  );
}
