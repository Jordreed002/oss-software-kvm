//! Safety-critical daemon coordination for Software KVM.
//!
//! Native capture and injection APIs are deliberately kept behind traits. The
//! daemon core is deterministic and synchronous so a platform callback can
//! decide whether to suppress an event without waiting for UI or disk I/O.

mod core;
mod platform;

pub use core::{
    CoreAction, DaemonCore, DaemonError, PeerState, ProcessResult, RemoteRelease, RoutingSnapshot,
    RoutingSnapshotHandle,
};
pub use platform::{
    CaptureCallback, CaptureDisposition, CapturedInput, DisplayBackend, EventClassification,
    EventClassifier, InputCaptureBackend, OutputInjectionBackend, PlatformError,
};
