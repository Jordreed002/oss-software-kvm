use serde::{Deserialize, Serialize};

pub const MAX_HOST_NAME_BYTES: usize = 255;
pub const MAX_DEVICE_NAME_BYTES: usize = 255;
pub const MAX_DISPLAY_NAME_BYTES: usize = 255;
pub const MAX_SNAPSHOT_ITEMS: usize = 256;
pub const MAX_AUTH_BYTES: usize = 4096;
pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_RELEASE_KEYS: usize = 256;

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticateV1 {
    pub peer_id: WirePeerId,
    /// Authentication scheme identifier, such as `tls-exporter-v1`.
    pub scheme: String,
    /// Scheme-specific challenge response. Long-term private credentials are
    /// never included in protocol values.
    pub proof: Vec<u8>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WireInputDeviceV1 {
    pub id: WireDeviceId,
    pub host_id: WireHostId,
    pub name: String,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub kind: WireDeviceKind,
    pub capabilities: WireDeviceCapabilities,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceSnapshotV1 {
    pub revision: u64,
    pub host_id: WireHostId,
    pub devices: Vec<WireInputDeviceV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceAddedV1 {
    pub revision: u64,
    pub device: WireInputDeviceV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRemovedV1 {
    pub revision: u64,
    pub host_id: WireHostId,
    pub device_id: WireDeviceId,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DisplaySnapshotV1 {
    pub revision: u64,
    pub host_id: WireHostId,
    pub displays: Vec<WireDisplayV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DisplayUpdatedV1 {
    pub revision: u64,
    pub display: WireDisplayV1,
}

/// USB HID usage page and usage, independent of either platform's native key
/// codes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct WireKeyCode {
    pub usage_page: u16,
    pub usage: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireKeyState {
    Down,
    Up,
    Repeat,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WirePointerButton {
    Primary,
    Secondary,
    Middle,
    Back,
    Forward,
    Other(u16),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireButtonState {
    Down,
    Up,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct InputEventV1 {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub source_host: WireHostId,
    pub source_device: WireDeviceId,
    pub payload: WireInputPayloadV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireEdge {
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct PointerEnterV1 {
    pub transition_id: u64,
    /// Monotonic workspace revision used to reject stale handoffs.
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

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct PointerLeaveV1 {
    pub transition_id: u64,
    /// Monotonic workspace revision used to reject stale handoffs.
    pub workspace_epoch: u64,
    pub sequence: u64,
    pub source_host: WireHostId,
    pub source_display: WireDisplayId,
    pub edge: WireEdge,
    /// Position along the source edge in the inclusive range 0.0..=1.0.
    pub normalized_position: f64,
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PointerTransitionAckV1 {
    pub transition_id: u64,
    pub workspace_epoch: u64,
    pub receiver_host: WireHostId,
    pub active_display: WireDisplayId,
    pub outcome: PointerTransitionOutcomeV1,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseInputV1 {
    pub sequence: u64,
    pub source_host: WireHostId,
    pub source_device: Option<WireDeviceId>,
    pub reason: ReleaseReasonV1,
    /// Empty means release every input held for the selected source.
    pub keys: Vec<WireKeyCode>,
    pub buttons: Vec<WirePointerButton>,
}
