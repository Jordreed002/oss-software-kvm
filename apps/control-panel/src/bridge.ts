import { invoke } from "@tauri-apps/api/core";
import type { DiagnosticsReport, DisplayPlacement, Placement, SetupSnapshot } from "./types";

const inTauri = () => "__TAURI_INTERNALS__" in window;

const mock: SetupSnapshot = {
  platform: navigator.platform.toLowerCase().includes("mac") ? "macos" : "windows",
  suggestedName: navigator.platform.toLowerCase().includes("mac") ? "Jordan’s Mac" : "Studio PC",
  addressOptions: ["192.168.1.24", "10.0.0.8"],
  local: null,
  peer: null,
  displays: [
    { id: "preview-local-display", name: "Built-in display", width: 1512, height: 982, scaleFactor: 2, primary: true, nativeBounds: { x: 0, y: 0, width: 3024, height: 1964 } },
  ],
  placement: "local_left",
  displayLayout: [],
  workspaceRole: "unassigned",
  workspaceRevision: 0,
  workspaceSync: "not_configured",
  configured: false,
  validated: false,
  runtime: "stopped",
  runtimeFault: null,
  inputAuthority: { owner: "unavailable", linkReady: false, sessionActive: false },
  runtimeLogPath: null,
  discoveryAvailable: true,
  nearbyMachines: [],
  nearbyPairing: null,
  developerDiagnostics: import.meta.env.DEV ? {
    lanBinding: "healthy", configuredListener: "192.168.1.24:24800",
    routedListener: "192.168.1.24:24800", configuredPeer: "192.168.1.31:24800",
    observedPeer: "192.168.1.31:24800", recentEvents: ["[dev] listener=ready", "[dev] capture=armed"],
    peerRecentEvents: ["[dev] listener=ready", "[dev] manager=state sessions:1 routing:enabled"],
  } : null,
  setupDirectory: null,
  profilePath: null,
};

let previewState = structuredClone(mock);

const invokeOrPreview = async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
  if (inTauri()) return invoke<T>(command, args);
  await new Promise((resolve) => window.setTimeout(resolve, 320));
  if (command === "setup_status") return structuredClone(previewState) as T;
  if (command === "create_local_identity") {
    const displayName = String(args?.displayName ?? "This computer");
    const address = String(args?.address ?? "192.168.1.24");
    previewState.local = {
      hostId: crypto.randomUUID(), peerId: crypto.randomUUID(), displayName,
      serverName: `${displayName.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.kvm.test`,
      certificateFingerprint: "9f".repeat(32), address: `${address}:24800`,
      publicBundle: btoa(JSON.stringify({ software_kvm_pairing: 1, display_name: displayName, address })),
    };
    return structuredClone(previewState) as T;
  }
  if (command === "import_peer_bundle") {
    previewState.peer = {
      hostId: crypto.randomUUID(), peerId: crypto.randomUUID(), displayName: "Office Windows",
      platform: previewState.platform === "macos" ? "windows" : "macos",
      serverName: "office-windows.kvm.test", certificateFingerprint: "3a".repeat(32),
      address: "192.168.1.31:24800",
      displays: [
        { id: "preview-peer-display", name: "Studio monitor", width: 2560, height: 1440, scaleFactor: 1, primary: true, nativeBounds: { x: 0, y: 0, width: 2560, height: 1440 } },
        { id: "preview-peer-display-2", name: "Second monitor", width: 1920, height: 1080, scaleFactor: 1, primary: false, nativeBounds: { x: 2560, y: 0, width: 1920, height: 1080 } },
      ],
    };
    previewState.workspaceRole = "unassigned";
    previewState.workspaceSync = "not_configured";
    return structuredClone(previewState) as T;
  }
  if (command === "request_nearby_pairing") {
    const machine = previewState.nearbyMachines.find((item) => item.peerId === args?.peerId);
    if (machine) {
      previewState.nearbyPairing = {
        requestId: crypto.randomUUID(), peerId: machine.peerId, name: machine.name,
        platform: machine.platform, address: machine.address,
        status: "waiting_for_acceptance", verificationCode: null,
      };
    }
    return structuredClone(previewState) as T;
  }
  if (command === "accept_nearby_pairing" && previewState.nearbyPairing) {
    previewState.nearbyPairing.status = "waiting_for_confirmation";
    previewState.nearbyPairing.verificationCode = "418 205";
    return structuredClone(previewState) as T;
  }
  if (command === "confirm_nearby_pairing" && previewState.nearbyPairing) {
    previewState.peer = {
      hostId: crypto.randomUUID(), peerId: previewState.nearbyPairing.peerId,
      displayName: previewState.nearbyPairing.name, platform: previewState.nearbyPairing.platform,
      serverName: "nearby-peer.kvm.test", certificateFingerprint: "3a".repeat(32),
      address: previewState.nearbyPairing.address,
      displays: [
        { id: "preview-peer-display", name: "Studio monitor", width: 2560, height: 1440, scaleFactor: 1, primary: true, nativeBounds: { x: 0, y: 0, width: 2560, height: 1440 } },
        { id: "preview-peer-display-2", name: "Second monitor", width: 1920, height: 1080, scaleFactor: 1, primary: false, nativeBounds: { x: 2560, y: 0, width: 1920, height: 1080 } },
      ],
    };
    previewState.workspaceRole = "leader";
    previewState.workspaceSync = "not_configured";
    previewState.nearbyPairing = null;
    return structuredClone(previewState) as T;
  }
  if (command === "decline_nearby_pairing") {
    previewState.nearbyPairing = null;
    return structuredClone(previewState) as T;
  }
  if (command === "forget_paired_computer") {
    previewState.peer = null;
    previewState.configured = false;
    previewState.validated = false;
    previewState.runtime = "stopped";
    previewState.inputAuthority = { owner: "unavailable", linkReady: false, sessionActive: false };
    previewState.nearbyPairing = null;
    previewState.workspaceRole = "unassigned";
    previewState.workspaceRevision = 0;
    previewState.workspaceSync = "not_configured";
    previewState.displayLayout = [];
    return structuredClone(previewState) as T;
  }
  if (command === "repair_lan_binding" && previewState.developerDiagnostics) {
    previewState.developerDiagnostics.lanBinding = "healthy";
    previewState.developerDiagnostics.configuredListener = previewState.developerDiagnostics.routedListener;
    previewState.developerDiagnostics.configuredPeer = previewState.developerDiagnostics.observedPeer;
    previewState.validated = true;
    return structuredClone(previewState) as T;
  }
  if (command === "finalize_setup") {
    previewState.configured = true;
    previewState.placement = args?.placement as Placement;
    previewState.displayLayout = args?.layout as DisplayPlacement[];
    previewState.workspaceRevision += 1;
    previewState.workspaceSync = previewState.workspaceRole === "unassigned" ? "manual" : "confirmed";
    previewState.setupDirectory = "/Users/demo/Library/Application Support/software-kvm";
    previewState.profilePath = `${previewState.setupDirectory}/runtime.toml`;
    return structuredClone(previewState) as T;
  }
  if (command === "validate_setup") {
    previewState.validated = true;
    return structuredClone(previewState) as T;
  }
  if (command === "start_runtime") {
    previewState.runtime = "running";
    previewState.runtimeFault = null;
    previewState.inputAuthority = { owner: "local", linkReady: true, sessionActive: true };
  }
  if (command === "stop_runtime") {
    previewState.runtime = "stopped";
    previewState.runtimeFault = null;
    previewState.inputAuthority = { owner: "unavailable", linkReady: false, sessionActive: false };
  }
  if (command === "fetch_diagnostics") {
    // Preview: synthesize a live-looking report so the dashboard can be built
    // in the web preview without a real runtime. Returns null when the runtime
    // is not running, matching the Tauri command's unreachable -> null contract.
    if (previewState.runtime !== "running") return null as T;
    const host = String(args?.host ?? "local");
    const isLocal = host === "local";
    const peerPlatform = previewState.platform === "macos" ? "windows" : "macos";
    const seed = isLocal ? 1 : 2;
    const t = Date.now() / 1000;
    return {
      schemaVersion: 1,
      hostId: `0000000${seed}-0000-4000-8000-00000000000${seed}`,
      peerId: `0000000${seed}-0000-4000-8000-00000000000${seed}`,
      platform: isLocal ? previewState.platform : peerPlatform,
      hostName: isLocal ? (previewState.local?.displayName ?? "This computer") : (previewState.peer?.displayName ?? "Peer"),
      capturedAtUnixMs: Date.now(),
      uptimeMs: Math.floor(60_000 + (Math.sin(t / 3) + 1) * 30_000),
      network: {
        outboundBytes: Math.floor(1_200_000 + (Math.sin(t) + 1) * 240_000),
        outboundFrames: Math.floor(8_400 + (Math.sin(t / 1.3) + 1) * 2_000),
        inboundBytes: Math.floor(980_000 + (Math.cos(t) + 1) * 180_000),
        inboundFrames: Math.floor(7_600 + (Math.cos(t / 1.1) + 1) * 1_800),
        lastRttMs: Math.floor(2 + (Math.sin(t / 2) + 1) * 3),
        dropped: { input: Math.floor((Math.sin(t / 7) + 1) * 3), control: 0, background: 0 },
        channelRejections: { input: 0, control: 0, background: 0 },
        coalescedMoves: Math.floor(400 + (Math.cos(t / 4) + 1) * 250),
      },
    } as DiagnosticsReport as T;
  }
  return structuredClone(previewState) as T;
};

export const api = {
  status: () => invokeOrPreview<SetupSnapshot>("setup_status"),
  createIdentity: (displayName: string, address: string) =>
    invokeOrPreview<SetupSnapshot>("create_local_identity", { displayName, address }),
  importPeer: (bundle: string) => invokeOrPreview<SetupSnapshot>("import_peer_bundle", { bundle }),
  requestNearbyPairing: (peerId: string) => invokeOrPreview<SetupSnapshot>("request_nearby_pairing", { peerId }),
  acceptNearbyPairing: (requestId: string) => invokeOrPreview<SetupSnapshot>("accept_nearby_pairing", { requestId }),
  confirmNearbyPairing: (requestId: string) => invokeOrPreview<SetupSnapshot>("confirm_nearby_pairing", { requestId }),
  declineNearbyPairing: (requestId: string) => invokeOrPreview<SetupSnapshot>("decline_nearby_pairing", { requestId }),
  forgetPairedComputer: () => invokeOrPreview<SetupSnapshot>("forget_paired_computer"),
  repairLanBinding: () => invokeOrPreview<SetupSnapshot>("repair_lan_binding"),
  finalize: (placement: Placement, layout: DisplayPlacement[]) =>
    invokeOrPreview<SetupSnapshot>("finalize_setup", { placement, layout }),
  validate: () => invokeOrPreview<SetupSnapshot>("validate_setup"),
  start: () => invokeOrPreview<SetupSnapshot>("start_runtime"),
  stop: () => invokeOrPreview<SetupSnapshot>("stop_runtime"),
  /** Pulls one diagnostics report over the separate §31 channel (port 24801).
   *  Pass "local" for this host, or a peer LAN IP. Returns null when offline. */
  fetchDiagnostics: (host: string, port?: number) =>
    invokeOrPreview<DiagnosticsReport | null>("fetch_diagnostics", { host, port }),
};
