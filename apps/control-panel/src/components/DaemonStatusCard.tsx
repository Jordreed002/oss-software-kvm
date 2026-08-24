import { useEffect, useState } from "react";
import { api, uuidToBytes } from "../bridge";
import { CheckRow } from "./shared";
import type { ControlPeerState, DaemonStatusReply, SetupSnapshot } from "../types";

/** Live §31 daemon status card (spec 31 control link), shown while the runtime
 *  is running. Polls the daemon's local control endpoint every 2 seconds and
 *  stops cleanly on unmount. Extracted from App.tsx. */
export function DaemonStatusCard({ snapshot }: { snapshot: SetupSnapshot }) {
  const [status, setStatus] = useState<DaemonStatusReply | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const pull = () => {
      api.controlStatus().then((reply) => {
        if (alive) { setStatus(reply); setPollError(null); }
      }).catch((error: unknown) => {
        // Keep the failure visible instead of stalling on "Contacting…" forever.
        if (alive) setPollError(error instanceof Error ? error.message : "the status request failed");
      });
    };
    pull();
    const timer = window.setInterval(pull, 2000);
    return () => { alive = false; window.clearInterval(timer); };
  }, []);

  const live = status?.state === "responded" ? status.status : null;
  // A malformed (or missing) local host id cannot be compared against the
  // daemon's active-host bytes; report that separately instead of silently
  // treating the peer as the active host.
  const localHostBytes = snapshot.local ? uuidToBytes(snapshot.local.hostId) : null;
  const identityKnown = !!snapshot.local && !!localHostBytes;
  const activeHostLocal = !!live && !!localHostBytes && bytesEqual(live.activeHost, localHostBytes);
  const peerName = snapshot.peer?.displayName ?? "Paired computer";
  const linkDetail: [string, boolean] =
    pollError !== null
      ? [`Daemon status poll failed (${pollError})`, false]
      : status === null
        ? ["Contacting the daemon's local control endpoint…", false]
        : status.state === "unreachable"
          ? ["Daemon not running at the local control endpoint", false]
          : status.state === "refused"
            ? [`Daemon refused the status request (${status.error ?? "error"})`, false]
            : ["Daemon is answering the local control endpoint", true];
  const peerDetail: [string, boolean] = live
    ? [peerConnectionDetail(live.peerState, live.roundTripTimeMs), live.peerState === "connected"]
    : ["Peer link unknown until the daemon responds", false];
  const routingDetail: [string, boolean] = live
    ? live.kvmEnabled
      ? ["Input routing is armed between both computers", true]
      : ["Input stays local (routing gated or failsafe released)", false]
    : ["Waiting for the daemon's routing state…", false];

  return <section className="checklist" aria-label="Live daemon status (spec 31 control link)">
    <CheckRow label="Daemon control link" detail={linkDetail[0]} good={linkDetail[1]} />
    <CheckRow label="Peer connection" detail={peerDetail[0]} good={peerDetail[1]} />
    <CheckRow label="KVM routing" detail={routingDetail[0]} good={routingDetail[1]} />
    {live && (
      <CheckRow
        label="Input destination"
        detail={identityKnown
          ? activeHostLocal
            ? `Active host is this computer (protocol v${live.protocolVersion})`
            : `Active host is ${peerName} (protocol v${live.protocolVersion})`
          : "Unknown local identity — the active host cannot be compared"}
        good={identityKnown && live.peerState === "connected"}
      />
    )}
  </section>;
}

function peerConnectionDetail(state: ControlPeerState, roundTripTimeMs: number | null): string {
  const stateText = state.replaceAll("_", " ");
  return roundTripTimeMs === null
    ? `Peer link: ${stateText}`
    : `Peer link: ${stateText} · round trip ${roundTripTimeMs} ms`;
}

function bytesEqual(left: number[], right: number[]): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
