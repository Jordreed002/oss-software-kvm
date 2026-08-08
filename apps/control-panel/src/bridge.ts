import { invoke } from "@tauri-apps/api/core";
import type { Placement, SetupSnapshot } from "./types";

const inTauri = () => "__TAURI_INTERNALS__" in window;

const mock: SetupSnapshot = {
  platform: navigator.platform.toLowerCase().includes("mac") ? "macos" : "windows",
  suggestedName: navigator.platform.toLowerCase().includes("mac") ? "Jordan’s Mac" : "Studio PC",
  addressOptions: ["192.168.1.24", "10.0.0.8"],
  local: null,
  peer: null,
  displays: [
    { id: "preview-local-display", name: "Built-in display", width: 1512, height: 982, scaleFactor: 2, primary: true },
  ],
  placement: "local_left",
  configured: false,
  validated: false,
  runtime: "stopped",
  runtimeFault: null,
  runtimeLogPath: null,
  discoveryAvailable: true,
  nearbyMachines: [],
  nearbyPairing: null,
  developerDiagnostics: import.meta.env.DEV ? {
    lanBinding: "healthy", configuredListener: "192.168.1.24:24800",
    routedListener: "192.168.1.24:24800", configuredPeer: "192.168.1.31:24800",
    observedPeer: "192.168.1.31:24800", recentEvents: ["[dev] listener=ready", "[dev] capture=armed"],
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
      displays: [{ id: "preview-peer-display", name: "Studio monitor", width: 2560, height: 1440, scaleFactor: 1, primary: true }],
    };
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
      displays: [{ id: "preview-peer-display", name: "Studio monitor", width: 2560, height: 1440, scaleFactor: 1, primary: true }],
    };
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
    previewState.nearbyPairing = null;
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
  }
  if (command === "stop_runtime") {
    previewState.runtime = "stopped";
    previewState.runtimeFault = null;
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
  finalize: (placement: Placement) => invokeOrPreview<SetupSnapshot>("finalize_setup", { placement }),
  validate: () => invokeOrPreview<SetupSnapshot>("validate_setup"),
  start: () => invokeOrPreview<SetupSnapshot>("start_runtime"),
  stop: () => invokeOrPreview<SetupSnapshot>("stop_runtime"),
};
