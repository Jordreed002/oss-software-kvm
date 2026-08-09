//! Platform-neutral domain types shared by the Software KVM crates.
//!
//! This crate deliberately contains no platform APIs and keeps UUIDs behind
//! strongly typed identifiers so IDs from different domains cannot be mixed.

mod device;
mod display;
mod geometry;
mod host;
mod id;
mod keyboard;
mod workspace;

pub use device::{DeviceCapabilities, DeviceKind, DeviceRoute, InputDevice};
pub use display::Display;
pub use geometry::{Edge, Point, Rect, Size};
pub use host::{Host, Platform};
pub use id::{DeviceId, DisplayId, HostId, ParseIdError, PeerId};
pub use keyboard::KeyboardMode;
pub use workspace::{LogicalPointer, WorkspaceState};
