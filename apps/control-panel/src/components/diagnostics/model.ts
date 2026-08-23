import type { DropCounters, NetworkDiagnostics } from "../../types";

/** Constants, shared types, and pure derivation helpers for the diagnostics
 *  dashboard. Extracted from DiagnosticsDashboard.tsx verbatim — no behavior
 *  changes. */

export const POLL_INTERVAL_MS = 1500;
export const HISTORY_MAX_SAMPLES = 60;
export const CHART_WINDOW_MS = 90_000;

export const LANES = ["input", "control", "background"] as const;
export type Lane = (typeof LANES)[number];

/** Mint = this computer, signal = paired computer, matching the console palette. */
export const LOCAL_COLOR = "#a9e5c8";
export const PEER_COLOR = "#ff6b35";

/** Derived per-second rates between two consecutive telemetry snapshots. */
export interface NetRate {
  outBps: number;
  inBps: number;
  outFps: number;
  inFps: number;
}

export interface SampleHost {
  rttMs: number | null;
  outBps: number | null;
  inBps: number | null;
  /** Cumulative total drops at sample time — differenced into a rate trend. */
  drops: number | null;
}

export interface DashSample {
  t: number;
  local: SampleHost | null;
  peer: SampleHost | null;
}

export function hostIp(address: string | undefined): string {
  if (!address) return "";
  if (address.startsWith("[")) return address.slice(1, address.indexOf("]"));
  return address.slice(0, address.lastIndexOf(":"));
}

export function deriveRate(prev: NetworkDiagnostics | null, curr: NetworkDiagnostics | null, dtMs: number): NetRate | null {
  if (!prev || !curr || dtMs <= 0) return null;
  const dt = dtMs / 1000;
  return {
    outBps: Math.max(0, (curr.outboundBytes - prev.outboundBytes) / dt),
    inBps: Math.max(0, (curr.inboundBytes - prev.inboundBytes) / dt),
    outFps: Math.max(0, (curr.outboundFrames - prev.outboundFrames) / dt),
    inFps: Math.max(0, (curr.inboundFrames - prev.inboundFrames) / dt),
  };
}

export function laneValue(counters: DropCounters, lane: Lane): number {
  return counters[lane];
}

export function totalDrops(counters: DropCounters): number {
  return counters.input + counters.control + counters.background;
}
