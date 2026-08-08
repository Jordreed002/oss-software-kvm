//! Safety-critical daemon coordination for Software KVM.
//!
//! Native capture and injection APIs are deliberately kept behind traits. The
//! daemon core is deterministic and synchronous so a platform callback can
//! decide whether to suppress an event without waiting for UI or disk I/O.

mod core;
mod device_inventory;
mod display_inventory;
mod peer_manager;
mod platform;
mod pointer_handoff;
mod session;
mod session_endpoint;
mod supervisor;
mod wire;
mod workspace_control;

pub use core::{
    CaptureOutcome, CaptureRouteState, CoreAction, CoreCaptureError, DaemonCore, DaemonError,
    PeerState, ProcessResult, RemoteRelease, RoutingSnapshot, RoutingSnapshotHandle,
};
pub use device_inventory::{
    DeviceInventory, DeviceInventoryConfig, DeviceInventoryError, DeviceInventorySnapshot,
    HostDeviceInventorySnapshot, MAX_DEVICE_INVENTORY_PER_HOST, MAX_DEVICE_INVENTORY_REMOTE_HOSTS,
    MAX_DEVICE_INVENTORY_TOTAL,
};
pub use display_inventory::{
    DisplayInventory, DisplayInventoryConfig, DisplayInventoryError, DisplayInventorySnapshot,
    HostDisplayInventorySnapshot, MAX_INVENTORY_DISPLAYS_PER_HOST, MAX_INVENTORY_REMOTE_HOSTS,
    MAX_INVENTORY_TOTAL_DISPLAYS,
};
pub use peer_manager::{
    DeviceInventoryUpdateOutcome, DeviceInventoryUpdateState, DeviceRouteUpdateOutcome,
    DeviceRouteUpdateState, InstalledPeerSessionParts, ManagedPairedPeer, ManagedSessionBuildError,
    ManagedSessionEnd, ManagedSessionError, OutboundDialTask, PeerManager, PeerManagerConfig,
    PeerManagerError, PeerManagerSnapshot, PreparedPeerSession, PreparedPeerSessionParts,
    SealedPeerSessionStart, SelectedCaptureOutcome, SelectedCaptureState, MAX_CANDIDATES_PER_PEER,
    MAX_MANAGED_PEERS,
};
pub use platform::{
    CaptureCallback, CaptureDisposition, CaptureLifecycleState, CapturedInput, DisplayBackend,
    EventClassification, EventClassifier, InputCaptureBackend, OutputInjectionBackend,
    PlatformError,
};
pub use pointer_handoff::{
    PointerAckOutcome, PointerEffectCompletion, PointerHandoffConfig, PointerHandoffCoordinator,
    PointerHandoffEffect, PointerHandoffError, PointerHandoffErrorKind, PointerHandoffStatus,
    PointerHandoffTimeouts, MAX_POINTER_HANDOFF_TIMEOUT,
};
pub use session::{
    CoordinatorError, ManagedSessionOutbound, OutboundPeer, OutboundPeerError, PeerEventOutcome,
    PeerSessionCoordinator, MAX_INBOUND_HELD_PER_DEVICE, MAX_INBOUND_HELD_TOTAL,
    MAX_INBOUND_PRESSED_DEVICES,
};
pub use supervisor::{PeerSessionSupervisor, PeerSessionSupervisorError, SupervisorEventOutcome};
pub use wire::{input_from_wire, input_to_wire, release_to_wire, WireConversionError};
pub use workspace_control::{WorkspaceControlError, WorkspaceControlPlane};
