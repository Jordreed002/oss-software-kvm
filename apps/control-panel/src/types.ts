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
