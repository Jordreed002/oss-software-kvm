use core::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_HOST_NAME_BYTES: usize = 255;
pub const MAX_DEVICE_NAME_BYTES: usize = 255;
pub const MAX_DISPLAY_NAME_BYTES: usize = 255;
pub const MAX_DISPLAY_LOGICAL_DIMENSION: f64 = 65_536.0;
pub const MAX_DISPLAY_PHYSICAL_DIMENSION: f64 = 262_144.0;
pub const MAX_DISPLAY_NATIVE_COORDINATE_ABS: f64 = 1_000_000.0;
pub const MAX_DISPLAY_SCALE_FACTOR: f64 = 16.0;
pub const MAX_DISPLAY_REFRESH_RATE_HZ: f64 = 1_000.0;
pub const MAX_SNAPSHOT_ITEMS: usize = 256;
pub const MAX_AUTH_BYTES: usize = 4096;
pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_RELEASE_KEYS: usize = 256;
pub const MAX_RELEASE_BUTTONS: usize = 32;
pub const MAX_RELEASE_CONTROLS: usize = 256;

macro_rules! wire_id {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            Deserialize,
            Eq,
            Hash,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
        )]
        pub struct $name(pub [u8; 16]);
    };
}

wire_id!(WireHostId);
wire_id!(WirePeerId);
wire_id!(WireDeviceId);
wire_id!(WireDisplayId);
wire_id!(WireClipboardId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WirePlatform {
    Windows,
    MacOs,
    Linux,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HelloV1 {
    pub host_id: WireHostId,
    pub peer_id: WirePeerId,
    pub host_name: String,
    pub platform: WirePlatform,
    pub minimum_protocol_version: u16,
    pub maximum_protocol_version: u16,
    pub daemon_version: String,
    pub nonce: [u8; 32],
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticateV1 {
    pub peer_id: WirePeerId,
    /// Authentication scheme identifier, such as `tls-exporter-v1`.
    pub scheme: String,
    /// Scheme-specific challenge response. Long-term private credentials are
    /// never included in protocol values.
    pub proof: Vec<u8>,
}

impl fmt::Debug for AuthenticateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticateV1")
            .field("peer_id", &self.peer_id)
            .field("scheme", &self.scheme)
            .field("proof", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireDeviceKind {
    Keyboard,
    Mouse,
    Trackpad,
    Other,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct WireDeviceCapabilities {
    pub pointer: bool,
    pub keyboard: bool,
    pub vertical_scroll: bool,
    pub horizontal_scroll: bool,
    pub extra_buttons: bool,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct WireInputDeviceV1 {
    pub id: WireDeviceId,
    pub host_id: WireHostId,
    pub name: String,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub kind: WireDeviceKind,
    pub capabilities: WireDeviceCapabilities,
}

impl fmt::Debug for WireInputDeviceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireInputDeviceV1([REDACTED])")
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceSnapshotV1 {
    pub revision: u64,
    pub host_id: WireHostId,
    pub devices: Vec<WireInputDeviceV1>,
}

impl fmt::Debug for DeviceSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceSnapshotV1")
            .field("device_count", &self.devices.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceAddedV1 {
    pub revision: u64,
    pub device: WireInputDeviceV1,
}

impl fmt::Debug for DeviceAddedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceAddedV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRemovedV1 {
    pub revision: u64,
    pub host_id: WireHostId,
    pub device_id: WireDeviceId,
}

impl fmt::Debug for DeviceRemovedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceRemovedV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct WireSize {
    pub width: f64,
    pub height: f64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct WireRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct WireDisplayV1 {
    pub id: WireDisplayId,
    pub host_id: WireHostId,
    pub name: String,
    pub logical_size: WireSize,
    pub physical_size: Option<WireSize>,
    pub scale_factor: f64,
    pub refresh_rate: Option<f64>,
    pub native_bounds: WireRect,
    pub primary: bool,
}

impl fmt::Debug for WireDisplayV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireDisplayV1([REDACTED])")
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct DisplaySnapshotV1 {
    pub revision: u64,
    pub host_id: WireHostId,
    pub displays: Vec<WireDisplayV1>,
}

impl fmt::Debug for DisplaySnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisplaySnapshotV1")
            .field("display_count", &self.displays.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct DisplayUpdatedV1 {
    pub revision: u64,
    pub display: WireDisplayV1,
}

impl fmt::Debug for DisplayUpdatedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisplayUpdatedV1([REDACTED])")
    }
}

/// USB HID usage page and usage, independent of either platform's native key
/// codes.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct WireKeyCode {
    pub usage_page: u16,
    pub usage: u16,
}

impl fmt::Debug for WireKeyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireKeyCode([REDACTED])")
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireKeyState {
    Down,
    Up,
    Repeat,
}

impl fmt::Debug for WireKeyState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireKeyState([REDACTED])")
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WirePointerButton {
    Primary,
    Secondary,
    Middle,
    Back,
    Forward,
    Other(u16),
}

impl fmt::Debug for WirePointerButton {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WirePointerButton([REDACTED])")
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireButtonState {
    Down,
    Up,
}

impl fmt::Debug for WireButtonState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireButtonState([REDACTED])")
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireInputPayloadV1 {
    Key {
        code: WireKeyCode,
        state: WireKeyState,
    },
    PointerMove {
        dx: f64,
        dy: f64,
    },
    PointerButton {
        button: WirePointerButton,
        state: WireButtonState,
    },
    Scroll {
        horizontal: f64,
        vertical: f64,
    },
}

impl fmt::Debug for WireInputPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Key { .. } => "Key",
            Self::PointerMove { .. } => "PointerMove",
            Self::PointerButton { .. } => "PointerButton",
            Self::Scroll { .. } => "Scroll",
        };
        formatter
            .debug_struct("WireInputPayloadV1")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct InputEventV1 {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub source_host: WireHostId,
    pub source_device: WireDeviceId,
    pub payload: WireInputPayloadV1,
}

impl fmt::Debug for InputEventV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InputEventV1")
            .field("payload", &self.payload)
            .field("source", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireEdge {
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
pub struct PointerEnterV1 {
    pub transition_id: u64,
    /// Deterministic identity of the source's compiled workspace.
    pub workspace_epoch: u64,
    pub sequence: u64,
    pub source_host: WireHostId,
    pub destination_host: WireHostId,
    pub source_display: WireDisplayId,
    pub destination_display: WireDisplayId,
    pub destination_edge: WireEdge,
    /// Position along the destination edge in the inclusive range 0.0..=1.0.
    pub normalized_position: f64,
}

impl fmt::Debug for PointerEnterV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerEnterV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
pub struct PointerLeaveV1 {
    pub transition_id: u64,
    /// Deterministic identity of the source's compiled workspace.
    pub workspace_epoch: u64,
    pub sequence: u64,
    pub source_host: WireHostId,
    pub source_display: WireDisplayId,
    pub edge: WireEdge,
    /// Position along the source edge in the inclusive range 0.0..=1.0.
    pub normalized_position: f64,
}

impl fmt::Debug for PointerLeaveV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerLeaveV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerTransitionOutcomeV1 {
    Accepted,
    StaleWorkspaceEpoch,
    UnknownDisplay,
    NotAuthoritative,
    Rejected,
}

/// Explicit response to `PointerEnterV1`. The sender must not commit remote
/// routing until it receives an accepted acknowledgement for the exact
/// transition and workspace epoch it proposed.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct PointerTransitionAckV1 {
    pub transition_id: u64,
    pub workspace_epoch: u64,
    pub receiver_host: WireHostId,
    pub active_display: WireDisplayId,
    pub outcome: PointerTransitionOutcomeV1,
}

impl fmt::Debug for PointerTransitionAckV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PointerTransitionAckV1")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

/// Final ordered handoff commit sent only after the source receives an exact
/// accepted acknowledgement. This shares the input FIFO lane so later input
/// cannot overtake authority transfer.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct PointerTransitionCommitV1 {
    pub transition_id: u64,
    pub workspace_epoch: u64,
    pub sequence: u64,
    pub source_host: WireHostId,
    pub destination_host: WireHostId,
    pub source_display: WireDisplayId,
    pub destination_display: WireDisplayId,
}

impl fmt::Debug for PointerTransitionCommitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerTransitionCommitV1([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClipboardV1 {
    pub update_id: WireClipboardId,
    pub origin_host: WireHostId,
    pub sequence: u64,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PingV1 {
    pub nonce: u64,
    pub sent_at_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PongV1 {
    pub nonce: u64,
    pub ping_sent_at_ns: u64,
    pub received_at_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReasonV1 {
    RouteChanged,
    PeerDisconnecting,
    Failsafe,
    Shutdown,
    StateResynchronization,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseInputV1 {
    pub sequence: u64,
    pub source_host: WireHostId,
    pub source_device: Option<WireDeviceId>,
    pub reason: ReleaseReasonV1,
    /// Empty means release every input held for the selected source.
    pub keys: Vec<WireKeyCode>,
    pub buttons: Vec<WirePointerButton>,
}

impl fmt::Debug for ReleaseInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleaseInputV1")
            .field("reason", &self.reason)
            .field("key_count", &self.keys.len())
            .field("button_count", &self.buttons.len())
            .field("source", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Reason for a protocol-v2 release which requires application confirmation.
///
/// This remains a distinct wire enum so future v2 evolution cannot silently
/// alter the serialized representation of [`ReleaseReasonV1`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReasonV2 {
    RouteChanged,
    PeerDisconnecting,
    Failsafe,
    Shutdown,
    StateResynchronization,
}

/// Protocol-v2 release request whose application is confirmed explicitly.
///
/// `transaction_id` identifies the retained cleanup transaction,
/// `release_token` prevents blind replay, and `old_session_id` is an opaque
/// digest derived from the admitted session whose input is being cleared.
/// An empty control list retains the v1 meaning: release every control held
/// for the selected source.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseInputV2 {
    pub transaction_id: u64,
    pub release_token: [u8; 32],
    pub old_session_id: [u8; 32],
    pub sequence: u64,
    pub covered_input_sequence: u64,
    pub source_host: WireHostId,
    pub applying_host: WireHostId,
    pub source_device: Option<WireDeviceId>,
    pub reason: ReleaseReasonV2,
    pub keys: Vec<WireKeyCode>,
    pub buttons: Vec<WirePointerButton>,
}

impl fmt::Debug for ReleaseInputV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleaseInputV2")
            .field("reason", &self.reason)
            .field("key_count", &self.keys.len())
            .field("button_count", &self.buttons.len())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Application-level confirmation for one exact protocol-v2 release.
///
/// The current delivery generation is deliberately not serialized: the
/// transport binds this value to the exact admitted generation which carried
/// it. `old_session_id` separately echoes the opaque prior-session digest so
/// a replacement-generation resynchronization cannot be confused with its
/// own current authority.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseAppliedAckV2 {
    pub transaction_id: u64,
    pub release_token: [u8; 32],
    pub old_session_id: [u8; 32],
    pub sequence: u64,
    pub release_sequence: u64,
    pub covered_input_sequence: u64,
    pub source_host: WireHostId,
    pub applying_host: WireHostId,
}

impl fmt::Debug for ReleaseAppliedAckV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReleaseAppliedAckV2([REDACTED])")
    }
}
