export type Platform = "macos" | "windows";
export type RuntimeState = "stopped" | "starting" | "running" | "stopping" | "faulted";
export type RuntimeFault = "native_capture" | "authenticated_transport" | "runtime_task" | "unknown";
export type Placement = "local_left" | "local_right";

export interface DisplayInfo {
  id: string;
  name: string;
  width: number;
  height: number;
  scaleFactor: number;
  primary: boolean;
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
  configured: boolean;
  validated: boolean;
  runtime: RuntimeState;
  runtimeFault: RuntimeFault | null;
  runtimeLogPath: string | null;
  setupDirectory: string | null;
  profilePath: string | null;
}
