export type Platform = "macos" | "windows";
export type RuntimeState = "stopped" | "starting" | "running" | "stopping" | "faulted";
export type RuntimeFault = "native_capture" | "authenticated_transport" | "runtime_task" | "unknown";
export type NearbyPresence = "setting_up" | "runtime_active";
export type NearbyPairingStatus = "incoming_request" | "waiting_for_acceptance" | "verify_code" | "waiting_for_confirmation";
export type Placement = "local_left" | "local_right";
export type WorkspaceRole = "unassigned" | "leader" | "follower";
export type WorkspaceSyncState = "not_configured" | "manual" | "waiting" | "confirmed";
export type LanBindingState = "healthy" | "mismatch" | "waiting_for_peer" | "not_configured";
export type InputOwnerState = "local" | "peer" | "transitioning" | "unavailable";

export interface InputAuthority {
  owner: InputOwnerState;
  linkReady: boolean;
  sessionActive: boolean;
}

export interface DisplayInfo {
  id: string;
  name: string;
  width: number;
  height: number;
  scaleFactor: number;
  primary: boolean;
  nativeBounds?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
}

export interface DisplayPlacement {
  displayId: string;
  x: number;
  y: number;
}

export interface LocalIdentity {
  hostId: string;
  peerId: string;
  displayName: string;
  serverName: string;
  certificateFingerprint: string;
  address: string;
  publicBundle: string;
}

export interface PeerIdentity {
  hostId: string;
  peerId: string;
  displayName: string;
  platform: Platform;
  serverName: string;
  certificateFingerprint: string;
  address: string;
  displays: DisplayInfo[];
}

export interface SetupSnapshot {
  platform: Platform;
  suggestedName: string;
  addressOptions: string[];
  local: LocalIdentity | null;
  peer: PeerIdentity | null;
  displays: DisplayInfo[];
  placement: Placement;
  displayLayout: DisplayPlacement[];
  workspaceRole: WorkspaceRole;
  workspaceRevision: number;
  workspaceSync: WorkspaceSyncState;
  configured: boolean;
  validated: boolean;
  runtime: RuntimeState;
  runtimeFault: RuntimeFault | null;
  inputAuthority: InputAuthority;
  runtimeLogPath: string | null;
  discoveryAvailable: boolean;
  nearbyMachines: NearbyMachine[];
  nearbyPairing: NearbyPairing | null;
  developerDiagnostics: DeveloperDiagnostics | null;
  setupDirectory: string | null;
  profilePath: string | null;
}

export interface NearbyMachine {
  peerId: string;
  name: string;
  platform: Platform;
  presence: NearbyPresence;
  address: string;
  paired: boolean;
}

export interface NearbyPairing {
  requestId: string;
  peerId: string;
  name: string;
  platform: Platform;
  address: string;
  status: NearbyPairingStatus;
  verificationCode: string | null;
}

export interface DeveloperDiagnostics {
  lanBinding: LanBindingState;
  configuredListener: string | null;
  routedListener: string | null;
  configuredPeer: string | null;
  observedPeer: string | null;
  recentEvents: string[];
  peerRecentEvents: string[];
}

/** Per-traffic-lane counters. Single-word lanes serialize identically in any
 *  case style. Mirrors `kvm_network::DropCounters`. */
export interface DropCounters {
  input: number;
  control: number;
  background: number;
}

/** Serializable view of the live session network telemetry. Mirrors
 *  `kvm_network::NetworkDiagnostics` (served over the separate §31 channel). */
export interface NetworkDiagnostics {
  outboundBytes: number;
  outboundFrames: number;
  inboundBytes: number;
  inboundFrames: number;
  /** Last ping/pong RTT in ms, or null before the first pong. */
  lastRttMs: number | null;
  dropped: DropCounters;
  channelRejections: DropCounters;
  coalescedMoves: number;
}

/** Aggregate native input-capture counters (spec §35 surface). Every field is
 *  a coarse counter — never an input payload, key value, coordinate, or peer
 *  address. Mirrors `kvm_network::CaptureDiagnostics`. */
export interface CaptureDiagnostics {
  observed: number;
  suppressed: number;
  allowedLocal: number;
  lockContention: number;
  callbackPanics: number;
  pointerObservations: number;
  pointerTransitions: number;
  pointerObservationFailures: number;
  cursorHides: number;
  cursorShows: number;
  cursorWarps: number;
}

/** One redacted, versioned read of a host's diagnostics state. Mirrors
 *  `kvm_network::DiagnosticsReport`, pulled over the separate diagnostics
 *  connection (port 24801), distinct from the active KVM switch (24800). */
export interface DiagnosticsReport {
  schemaVersion: number;
  hostId: string;
  peerId: string | null;
  platform: Platform;
  hostName: string | null;
  capturedAtUnixMs: number | null;
  uptimeMs: number;
  /** Live session telemetry, or null when no session is active. */
  network: NetworkDiagnostics | null;
  /** Aggregate capture counters, or null before the capture supervisor reports. */
  capture: CaptureDiagnostics | null;
}
