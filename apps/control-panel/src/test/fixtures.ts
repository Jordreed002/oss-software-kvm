import type {
  CaptureDiagnostics,
  DaemonStatus,
  DaemonStatusReply,
  DiagnosticsReport,
  DisplayInfo,
  NetworkDiagnostics,
  SetupSnapshot,
} from "../types";

/** Deterministic builders for the serializable snapshot/report shapes. Tests
 *  override only the fields they care about; everything else gets a
 *  representative "healthy running session" default. */

export function makeNetwork(overrides: Partial<NetworkDiagnostics> = {}): NetworkDiagnostics {
  return {
    outboundBytes: 1_200_000,
    outboundFrames: 8_400,
    inboundBytes: 980_000,
    inboundFrames: 7_600,
    lastRttMs: 4,
    dropped: { input: 0, control: 0, background: 0 },
    channelRejections: { input: 0, control: 0, background: 0 },
    coalescedMoves: 400,
    pointerDatagramActive: true,
    pointerDatagramsOutbound: 2_000,
    pointerDatagramsInbound: 1_800,
    pointerDatagramGaps: 12,
    pointerDatagramJitterUs: 900,
    pointerJitterP50Us: 1_000,
    pointerJitterP95Us: 5_000,
    pointerJitterP99Us: 10_000,
    pointerDatagramMaxSilenceMs: 18,
    pointerRecoveryMilliunits: 2_000,
    reliableDatagramsOutbound: 40,
    reliableDatagramsInbound: 38,
    reliableDatagramRetransmits: 1,
    ...overrides,
  };
}

export function makeCapture(overrides: Partial<CaptureDiagnostics> = {}): CaptureDiagnostics {
  return {
    observed: 12_000,
    suppressed: 8_000,
    allowedLocal: 4_000,
    lockContention: 0,
    callbackPanics: 0,
    pointerObservations: 6_200,
    pointerTransitions: 4,
    pointerObservationFailures: 0,
    cursorHides: 4,
    cursorShows: 4,
    cursorWarps: 8,
    ...overrides,
  };
}

export function makeReport(overrides: Partial<DiagnosticsReport> = {}): DiagnosticsReport {
  return {
    schemaVersion: 1,
    hostId: "00000001-0000-4000-8000-000000000001",
    peerId: "00000002-0000-4000-8000-000000000002",
    platform: "macos",
    hostName: "Local host",
    capturedAtUnixMs: 1_700_000_000_000,
    uptimeMs: 3_723_000,
    network: makeNetwork(),
    capture: makeCapture(),
    ...overrides,
  };
}

/** Canonical local-identity UUID used by the §31 daemon status fixtures. Its
 *  byte form matches LOCAL_HOST_BYTES below. */
export const LOCAL_HOST_UUID = "11111111-2222-4333-8444-555555555555";

/** 16 bytes of LOCAL_HOST_UUID — the shape the backend really serializes for
 *  the §31 `activeHost` field (a plain number array, camelCase keys). */
export const LOCAL_HOST_BYTES = [
  0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33,
  0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
];

export function makeDaemonStatus(overrides: Partial<DaemonStatus> = {}): DaemonStatus {
  return {
    kvmEnabled: true,
    clipboardEnabled: false,
    peerState: "connected",
    roundTripTimeMs: 4,
    activeHost: [...LOCAL_HOST_BYTES],
    protocolVersion: 3,
    ...overrides,
  };
}

export function makeDaemonStatusReply(overrides: Partial<DaemonStatusReply> = {}): DaemonStatusReply {
  return {
    state: "responded",
    status: makeDaemonStatus(),
    error: null,
    ...overrides,
  };
}

export function makeDisplay(id: string, overrides: Partial<DisplayInfo> = {}): DisplayInfo {
  return {
    id,
    name: `Display ${id}`,
    width: 1_000,
    height: 800,
    scaleFactor: 2,
    primary: true,
    nativeBounds: { x: 0, y: 0, width: 2_000, height: 1_600 },
    ...overrides,
  };
}

export function makeSnapshot(overrides: Partial<SetupSnapshot> = {}): SetupSnapshot {
  return {
    platform: "macos",
    suggestedName: "Jordan’s Mac",
    addressOptions: ["192.168.1.24", "10.0.0.8"],
    local: {
      hostId: "local-host",
      peerId: "local-peer",
      displayName: "Jordan’s Mac",
      serverName: "jordans-mac.kvm.test",
      certificateFingerprint: "9f".repeat(32),
      address: "192.168.1.24:24800",
      publicBundle: "eyJzb2Z0d2FyZV9rdm0iOiAxfQ==",
    },
    peer: {
      hostId: "peer-host",
      peerId: "peer-peer",
      displayName: "Office Windows",
      platform: "windows",
      serverName: "office-windows.kvm.test",
      certificateFingerprint: "3a".repeat(32),
      address: "192.168.1.31:24800",
      displays: [makeDisplay("peer-1", { name: "Studio monitor", primary: true, nativeBounds: { x: 1000, y: 0, width: 2000, height: 1600 } })],
    },
    displays: [makeDisplay("local-1", { name: "Built-in display" })],
    placement: "local_left",
    displayLayout: [],
    workspaceRole: "unassigned",
    workspaceRevision: 0,
    workspaceSync: "not_configured",
    configured: false,
    validated: false,
    runtime: "running",
    runtimeFault: null,
    inputAuthority: { owner: "local", linkReady: true, sessionActive: true },
    runtimeLogPath: null,
    discoveryAvailable: true,
    nearbyMachines: [],
    nearbyPairing: null,
    developerDiagnostics: null,
    setupDirectory: null,
    profilePath: null,
    ...overrides,
  };
}
