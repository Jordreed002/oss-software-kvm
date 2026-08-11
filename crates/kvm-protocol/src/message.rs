use crate::{
    AuthenticateV1, ClipboardV1, DeviceAddedV1, DeviceRemovedV1, DeviceSnapshotV1,
    DisplaySnapshotV1, DisplayUpdatedV1, HelloV1, InputEventV1, PingV1, PointerEnterV1,
    PointerLeaveV1, PointerTransitionAckV1, PointerTransitionCommitV1, PongV1, ProtocolError,
    ReleaseAppliedAckV2, ReleaseInputV1, ReleaseInputV2, ValidationError, WireDisplayV1,
    WireInputDeviceV1, WireInputPayloadV1, CURRENT_PROTOCOL_VERSION, MAX_AUTH_BYTES,
    MAX_CLIPBOARD_TEXT_BYTES, MAX_DEVICE_NAME_BYTES, MAX_DISPLAY_LOGICAL_DIMENSION,
    MAX_DISPLAY_NAME_BYTES, MAX_DISPLAY_NATIVE_COORDINATE_ABS, MAX_DISPLAY_PHYSICAL_DIMENSION,
    MAX_DISPLAY_REFRESH_RATE_HZ, MAX_DISPLAY_SCALE_FACTOR, MAX_HOST_NAME_BYTES,
    MAX_RELEASE_BUTTONS, MAX_RELEASE_CONTROLS, MAX_RELEASE_KEYS, MAX_SNAPSHOT_ITEMS,
    MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION_V2,
};
use serde::de::DeserializeOwned;
use std::collections::{BTreeSet, HashSet};

/// Zero-cost adapter that lets `postcard::to_extend` append into a borrowed
/// `Vec<u8>` instead of consuming an owned one.
///
/// postcard's `to_extend` takes its writer by value (`W: Extend<u8>`) and
/// returns it wrapped in `Result`; on a serialize error the writer is dropped.
/// Passing an owned `Vec` therefore loses the allocation on error. This wrapper
/// borrows the caller's buffer mutably and implements `Extend<u8>` by
/// delegating to `Vec::extend` (which specializes for contiguous slices), so it
/// is allocation-free and is the only value consumed on the error path — the
/// caller's buffer survives with its prior content intact. Used by
/// [`WireMessage::encode_payload_into`].
struct BufExt<'a>(&'a mut Vec<u8>);

impl Extend<u8> for BufExt<'_> {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.0.extend(iter);
    }
}

/// Appends the postcard serialization of one variant's inner payload into `buf`
/// through the borrowing [`BufExt`] adapter, returning `Ok(())` so each match
/// arm in [`WireMessage::encode_payload_into`] stays short and uniform (the
/// concrete payload type differs per variant, so the dispatching match cannot
/// be collapsed). Monomorphized and inlined per payload type — zero overhead
/// versus inlining the call.
fn append_payload<T: serde::Serialize>(
    value: &T,
    buf: &mut Vec<u8>,
) -> Result<(), postcard::Error> {
    postcard::to_extend(value, BufExt(buf)).map(drop)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum MessageType {
    Hello = 1,
    Authenticate = 2,
    DeviceSnapshot = 10,
    DeviceAdded = 11,
    DeviceRemoved = 12,
    DisplaySnapshot = 20,
    DisplayUpdated = 21,
    Input = 30,
    PointerEnter = 31,
    PointerLeave = 32,
    PointerTransitionAck = 33,
    PointerTransitionCommit = 34,
    Clipboard = 40,
    Ping = 50,
    Pong = 51,
    ReleaseInput = 60,
    ReleaseInputV2 = 61,
    ReleaseAppliedAckV2 = 62,
}

impl TryFrom<u16> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Authenticate),
            10 => Ok(Self::DeviceSnapshot),
            11 => Ok(Self::DeviceAdded),
            12 => Ok(Self::DeviceRemoved),
            20 => Ok(Self::DisplaySnapshot),
            21 => Ok(Self::DisplayUpdated),
            30 => Ok(Self::Input),
            31 => Ok(Self::PointerEnter),
            32 => Ok(Self::PointerLeave),
            33 => Ok(Self::PointerTransitionAck),
            34 => Ok(Self::PointerTransitionCommit),
            40 => Ok(Self::Clipboard),
            50 => Ok(Self::Ping),
            51 => Ok(Self::Pong),
            60 => Ok(Self::ReleaseInput),
            61 => Ok(Self::ReleaseInputV2),
            62 => Ok(Self::ReleaseAppliedAckV2),
            other => Err(ProtocolError::UnknownMessageType(other)),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum WireMessage {
    Hello(HelloV1),
    Authenticate(AuthenticateV1),
    DeviceSnapshot(DeviceSnapshotV1),
    DeviceAdded(DeviceAddedV1),
    DeviceRemoved(DeviceRemovedV1),
    DisplaySnapshot(DisplaySnapshotV1),
    DisplayUpdated(DisplayUpdatedV1),
    Input(InputEventV1),
    PointerEnter(PointerEnterV1),
    PointerLeave(PointerLeaveV1),
    PointerTransitionAck(PointerTransitionAckV1),
    PointerTransitionCommit(PointerTransitionCommitV1),
    Clipboard(ClipboardV1),
    Ping(PingV1),
    Pong(PongV1),
    ReleaseInput(ReleaseInputV1),
    ReleaseInputV2(ReleaseInputV2),
    ReleaseAppliedAckV2(ReleaseAppliedAckV2),
}

impl std::fmt::Debug for WireMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("WireMessage")
            .field(&self.message_type())
            .field(&"[REDACTED]")
            .finish()
    }
}

impl WireMessage {
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Hello(_) => MessageType::Hello,
            Self::Authenticate(_) => MessageType::Authenticate,
            Self::DeviceSnapshot(_) => MessageType::DeviceSnapshot,
            Self::DeviceAdded(_) => MessageType::DeviceAdded,
            Self::DeviceRemoved(_) => MessageType::DeviceRemoved,
            Self::DisplaySnapshot(_) => MessageType::DisplaySnapshot,
            Self::DisplayUpdated(_) => MessageType::DisplayUpdated,
            Self::Input(_) => MessageType::Input,
            Self::PointerEnter(_) => MessageType::PointerEnter,
            Self::PointerLeave(_) => MessageType::PointerLeave,
            Self::PointerTransitionAck(_) => MessageType::PointerTransitionAck,
            Self::PointerTransitionCommit(_) => MessageType::PointerTransitionCommit,
            Self::Clipboard(_) => MessageType::Clipboard,
            Self::Ping(_) => MessageType::Ping,
            Self::Pong(_) => MessageType::Pong,
            Self::ReleaseInput(_) => MessageType::ReleaseInput,
            Self::ReleaseInputV2(_) => MessageType::ReleaseInputV2,
            Self::ReleaseAppliedAckV2(_) => MessageType::ReleaseAppliedAckV2,
        }
    }

    /// Earliest framing version which may carry this message type.
    #[must_use]
    pub const fn minimum_protocol_version(&self) -> u16 {
        self.message_type().minimum_protocol_version()
    }

    /// Validates message-specific size, ownership, and numeric invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when any value is unsafe or invalid for its
    /// v1 message type.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let message_type = self.message_type();
        let invalid = |detail| ValidationError::new(message_type, detail);
        match self {
            Self::Hello(value) => {
                string_len("host_name", &value.host_name, MAX_HOST_NAME_BYTES, &invalid)?;
                string_len("daemon_version", &value.daemon_version, 128, &invalid)?;
                if value.minimum_protocol_version == 0 {
                    return Err(invalid(
                        "minimum protocol version must be positive".to_owned(),
                    ));
                }
                if value.minimum_protocol_version > value.maximum_protocol_version {
                    return Err(invalid(
                        "minimum protocol version exceeds maximum".to_owned(),
                    ));
                }
                if value.maximum_protocol_version < MIN_SUPPORTED_PROTOCOL_VERSION
                    || value.minimum_protocol_version > CURRENT_PROTOCOL_VERSION
                {
                    return Err(invalid(
                        "peer does not advertise a supported protocol version".to_owned(),
                    ));
                }
            }
            Self::Authenticate(value) => {
                string_len("scheme", &value.scheme, 64, &invalid)?;
                if value.scheme.is_empty() {
                    return Err(invalid("authentication scheme cannot be empty".to_owned()));
                }
                if value.proof.is_empty() || value.proof.len() > MAX_AUTH_BYTES {
                    return Err(invalid(format!(
                        "proof length must be in 1..={MAX_AUTH_BYTES} bytes"
                    )));
                }
            }
            Self::DeviceSnapshot(value) => {
                value.validate()?;
            }
            Self::DeviceAdded(value) => value.validate()?,
            Self::DeviceRemoved(value) => value.validate()?,
            Self::DisplaySnapshot(value) => {
                value.validate()?;
            }
            Self::DisplayUpdated(value) => {
                value.validate()?;
            }
            Self::Input(value) => validate_input(value, &invalid)?,
            Self::PointerEnter(value) => {
                normalized(value.normalized_position, &invalid)?;
                if value.source_host == value.destination_host {
                    return Err(invalid(
                        "pointer-enter destination must be a different host".to_owned(),
                    ));
                }
            }
            Self::PointerLeave(value) => normalized(value.normalized_position, &invalid)?,
            Self::PointerTransitionCommit(value) => {
                if value.source_host == value.destination_host {
                    return Err(invalid(
                        "pointer-transition commit destination must be a different host".to_owned(),
                    ));
                }
            }
            Self::Clipboard(value) => {
                string_len("text", &value.text, MAX_CLIPBOARD_TEXT_BYTES, &invalid)?;
            }
            Self::ReleaseInput(value) => {
                list_len("keys", value.keys.len(), MAX_RELEASE_KEYS, &invalid)?;
                list_len(
                    "buttons",
                    value.buttons.len(),
                    MAX_RELEASE_BUTTONS,
                    &invalid,
                )?;
            }
            Self::ReleaseInputV2(value) => value.validate()?,
            Self::ReleaseAppliedAckV2(value) => value.validate()?,
            Self::PointerTransitionAck(_) | Self::Ping(_) | Self::Pong(_) => {}
        }
        Ok(())
    }

    /// Serializes the message payload by appending it onto `buf`, reusing the
    /// buffer's existing allocation instead of allocating a fresh `Vec`.
    ///
    /// This is the allocation-free hot path used by batch framing: under a
    /// high-rate input burst many frames are encoded into one reused buffer
    /// without a per-frame allocation.
    ///
    /// On error the buffer is rewound to its entry length — no partially
    /// appended bytes and no lost allocation — so the caller can rely on the
    /// buffer being unchanged across a failed encode.
    pub(crate) fn encode_payload_into(&self, buf: &mut Vec<u8>) -> Result<(), postcard::Error> {
        // `postcard::to_extend` takes its writer by value and returns
        // `Result<W>`: on a serialize error the writer is dropped. Passing the
        // caller's owned `Vec` directly (the prior `mem::take` form) therefore
        // destroyed the buffer — and its retained capacity — on the error path,
        // because `to_extend` consumed the moved-out allocation and never gave
        // it back. `BufExt` instead borrows `buf` mutably and implements
        // `Extend<u8>` by delegating to `Vec::extend`, so it is the only value
        // consumed on error; `buf` keeps its allocation and prior content. Each
        // arm maps the returned `Result<BufExt>` to `Result<()>` inline so the
        // borrow ends before the truncate below mutates `buf` again.
        let entry_len = buf.len();
        let result = match self {
            Self::Hello(value) => append_payload(value, buf),
            Self::Authenticate(value) => append_payload(value, buf),
            Self::DeviceSnapshot(value) => append_payload(value, buf),
            Self::DeviceAdded(value) => append_payload(value, buf),
            Self::DeviceRemoved(value) => append_payload(value, buf),
            Self::DisplaySnapshot(value) => append_payload(value, buf),
            Self::DisplayUpdated(value) => append_payload(value, buf),
            Self::Input(value) => append_payload(value, buf),
            Self::PointerEnter(value) => append_payload(value, buf),
            Self::PointerLeave(value) => append_payload(value, buf),
            Self::PointerTransitionAck(value) => append_payload(value, buf),
            Self::PointerTransitionCommit(value) => append_payload(value, buf),
            Self::Clipboard(value) => append_payload(value, buf),
            Self::Ping(value) => append_payload(value, buf),
            Self::Pong(value) => append_payload(value, buf),
            Self::ReleaseInput(value) => append_payload(value, buf),
            Self::ReleaseInputV2(value) => append_payload(value, buf),
            Self::ReleaseAppliedAckV2(value) => append_payload(value, buf),
        };
        if result.is_err() {
            // Drop any bytes the failing serialize appended before bailing.
            buf.truncate(entry_len);
        }
        result
    }

    pub(crate) fn decode_payload(
        message_type: MessageType,
        bytes: &[u8],
    ) -> Result<Self, ProtocolError> {
        fn decode<T: DeserializeOwned>(
            message_type: MessageType,
            bytes: &[u8],
        ) -> Result<T, ProtocolError> {
            let (decoded, remaining) =
                postcard::take_from_bytes(bytes).map_err(|error| ProtocolError::Decode {
                    message_type,
                    detail: error.to_string(),
                })?;
            if !remaining.is_empty() {
                return Err(ProtocolError::Decode {
                    message_type,
                    detail: format!("payload contains {} trailing bytes", remaining.len()),
                });
            }
            Ok(decoded)
        }

        Ok(match message_type {
            MessageType::Hello => Self::Hello(decode(message_type, bytes)?),
            MessageType::Authenticate => Self::Authenticate(decode(message_type, bytes)?),
            MessageType::DeviceSnapshot => Self::DeviceSnapshot(decode(message_type, bytes)?),
            MessageType::DeviceAdded => Self::DeviceAdded(decode(message_type, bytes)?),
            MessageType::DeviceRemoved => Self::DeviceRemoved(decode(message_type, bytes)?),
            MessageType::DisplaySnapshot => Self::DisplaySnapshot(decode(message_type, bytes)?),
            MessageType::DisplayUpdated => Self::DisplayUpdated(decode(message_type, bytes)?),
            MessageType::Input => Self::Input(decode(message_type, bytes)?),
            MessageType::PointerEnter => Self::PointerEnter(decode(message_type, bytes)?),
            MessageType::PointerLeave => Self::PointerLeave(decode(message_type, bytes)?),
            MessageType::PointerTransitionAck => {
                Self::PointerTransitionAck(decode(message_type, bytes)?)
            }
            MessageType::PointerTransitionCommit => {
                Self::PointerTransitionCommit(decode(message_type, bytes)?)
            }
            MessageType::Clipboard => Self::Clipboard(decode(message_type, bytes)?),
            MessageType::Ping => Self::Ping(decode(message_type, bytes)?),
            MessageType::Pong => Self::Pong(decode(message_type, bytes)?),
            MessageType::ReleaseInput => Self::ReleaseInput(decode(message_type, bytes)?),
            MessageType::ReleaseInputV2 => Self::ReleaseInputV2(decode(message_type, bytes)?),
            MessageType::ReleaseAppliedAckV2 => {
                Self::ReleaseAppliedAckV2(decode(message_type, bytes)?)
            }
        })
    }
}

impl MessageType {
    /// Earliest framing version in which this discriminant is valid.
    #[must_use]
    pub const fn minimum_protocol_version(self) -> u16 {
        match self {
            Self::ReleaseInputV2 | Self::ReleaseAppliedAckV2 => PROTOCOL_VERSION_V2,
            Self::Hello
            | Self::Authenticate
            | Self::DeviceSnapshot
            | Self::DeviceAdded
            | Self::DeviceRemoved
            | Self::DisplaySnapshot
            | Self::DisplayUpdated
            | Self::Input
            | Self::PointerEnter
            | Self::PointerLeave
            | Self::PointerTransitionAck
            | Self::PointerTransitionCommit
            | Self::Clipboard
            | Self::Ping
            | Self::Pong
            | Self::ReleaseInput => MIN_SUPPORTED_PROTOCOL_VERSION,
        }
    }
}

impl ReleaseInputV2 {
    /// Revalidates the complete v2 release request without encoding it.
    ///
    /// # Errors
    ///
    /// Rejects zero correlation/session values, invalid ownership, unsafe
    /// sequence coverage, duplicate controls, or any count above its bound.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let invalid = |detail| ValidationError::new(MessageType::ReleaseInputV2, detail);
        validate_release_v2(self, &invalid)
    }
}

impl ReleaseAppliedAckV2 {
    /// Revalidates the complete v2 applied-release acknowledgment.
    ///
    /// Exact equality with a retained request is intentionally a daemon state
    /// machine check; this method validates only self-contained wire bounds.
    ///
    /// # Errors
    ///
    /// Rejects zero correlation/session values, invalid ownership, or unsafe
    /// sequence coverage.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let invalid = |detail| ValidationError::new(MessageType::ReleaseAppliedAckV2, detail);
        validate_release_ack_v2(self, &invalid)
    }
}

impl DeviceSnapshotV1 {
    /// Revalidates every device-wire invariant without encoding or copying
    /// peer-controlled values.
    ///
    /// # Errors
    ///
    /// Rejects nil or inconsistent ownership, zero revision, excessive count,
    /// duplicate device IDs, or invalid device metadata.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let invalid = |detail| ValidationError::new(MessageType::DeviceSnapshot, detail);
        positive_revision("device", self.revision, &invalid)?;
        non_nil_id("snapshot host", self.host_id.0, &invalid)?;
        list_len("devices", self.devices.len(), MAX_SNAPSHOT_ITEMS, &invalid)?;
        let mut device_ids = BTreeSet::new();
        for device in &self.devices {
            validate_device(device, &invalid)?;
            if device.host_id != self.host_id {
                return Err(invalid(
                    "snapshot contains a device owned by another host".to_owned(),
                ));
            }
            if !device_ids.insert(device.id) {
                return Err(invalid(
                    "snapshot contains duplicate device identifiers".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl DeviceAddedV1 {
    /// Revalidates a device-add delta without encoding or copying it.
    ///
    /// # Errors
    ///
    /// Rejects a zero revision or invalid device identifier, owner, or name.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let invalid = |detail| ValidationError::new(MessageType::DeviceAdded, detail);
        positive_revision("device", self.revision, &invalid)?;
        validate_device(&self.device, &invalid)
    }
}

impl DeviceRemovedV1 {
    /// Revalidates a device-remove delta without encoding or copying it.
    ///
    /// # Errors
    ///
    /// Rejects a zero revision or nil host/device identifier.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let invalid = |detail| ValidationError::new(MessageType::DeviceRemoved, detail);
        positive_revision("device", self.revision, &invalid)?;
        non_nil_id("device owner", self.host_id.0, &invalid)?;
        non_nil_id("device", self.device_id.0, &invalid)
    }
}

impl DisplaySnapshotV1 {
    /// Revalidates every display-wire invariant without encoding or copying
    /// peer-controlled values.
    ///
    /// # Errors
    ///
    /// Rejects nil or inconsistent ownership, zero revision, excessive count,
    /// duplicate display IDs, invalid display metadata, or a primary-count
    /// other than exactly one.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let invalid = |detail| ValidationError::new(MessageType::DisplaySnapshot, detail);
        positive_revision("display", self.revision, &invalid)?;
        non_nil_id("snapshot host", self.host_id.0, &invalid)?;
        list_len(
            "displays",
            self.displays.len(),
            MAX_SNAPSHOT_ITEMS,
            &invalid,
        )?;
        let mut display_ids = BTreeSet::new();
        let mut primary_count = 0_usize;
        for display in &self.displays {
            validate_display(display, &invalid)?;
            if display.host_id != self.host_id {
                return Err(invalid(
                    "snapshot contains a display owned by another host".to_owned(),
                ));
            }
            if !display_ids.insert(display.id) {
                return Err(invalid(
                    "snapshot contains duplicate display identifiers".to_owned(),
                ));
            }
            primary_count += usize::from(display.primary);
        }
        if primary_count != 1 {
            return Err(invalid(
                "snapshot must contain exactly one primary display".to_owned(),
            ));
        }
        Ok(())
    }
}

impl DisplayUpdatedV1 {
    /// Revalidates one display update without encoding or copying it.
    ///
    /// # Errors
    ///
    /// Rejects a zero revision or invalid display identifier, owner, name, or
    /// geometry.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let invalid = |detail| ValidationError::new(MessageType::DisplayUpdated, detail);
        positive_revision("display", self.revision, &invalid)?;
        validate_display(&self.display, &invalid)
    }
}

fn string_len(
    name: &str,
    value: &str,
    maximum: usize,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if value.len() > maximum {
        return Err(invalid(format!(
            "{name} is {} bytes; maximum is {maximum}",
            value.len()
        )));
    }
    Ok(())
}

fn list_len(
    name: &str,
    length: usize,
    maximum: usize,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if length > maximum {
        return Err(invalid(format!(
            "{name} contains {length} items; maximum is {maximum}"
        )));
    }
    Ok(())
}

fn validate_device(
    device: &WireInputDeviceV1,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    string_len("device name", &device.name, MAX_DEVICE_NAME_BYTES, invalid)?;
    if device.name.trim().is_empty() || device.name.chars().any(char::is_control) {
        return Err(invalid(
            "device name must be nonempty and contain no control characters".to_owned(),
        ));
    }
    non_nil_id("device", device.id.0, invalid)?;
    non_nil_id("device owner", device.host_id.0, invalid)
}

fn validate_display(
    display: &WireDisplayV1,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    string_len(
        "display name",
        &display.name,
        MAX_DISPLAY_NAME_BYTES,
        invalid,
    )?;
    if display.name.trim().is_empty() || display.name.chars().any(char::is_control) {
        return Err(invalid(
            "display name must be nonempty and contain no control characters".to_owned(),
        ));
    }
    non_nil_id("display", display.id.0, invalid)?;
    non_nil_id("display owner", display.host_id.0, invalid)?;
    positive_bounded(
        "logical width",
        display.logical_size.width,
        MAX_DISPLAY_LOGICAL_DIMENSION,
        invalid,
    )?;
    positive_bounded(
        "logical height",
        display.logical_size.height,
        MAX_DISPLAY_LOGICAL_DIMENSION,
        invalid,
    )?;
    if let Some(size) = display.physical_size {
        positive_bounded(
            "physical width",
            size.width,
            MAX_DISPLAY_PHYSICAL_DIMENSION,
            invalid,
        )?;
        positive_bounded(
            "physical height",
            size.height,
            MAX_DISPLAY_PHYSICAL_DIMENSION,
            invalid,
        )?;
    }
    positive_bounded(
        "scale factor",
        display.scale_factor,
        MAX_DISPLAY_SCALE_FACTOR,
        invalid,
    )?;
    if let Some(refresh_rate) = display.refresh_rate {
        positive_bounded(
            "refresh rate",
            refresh_rate,
            MAX_DISPLAY_REFRESH_RATE_HZ,
            invalid,
        )?;
    }
    bounded_coordinate("native x", display.native_bounds.x, invalid)?;
    bounded_coordinate("native y", display.native_bounds.y, invalid)?;
    positive_bounded(
        "native width",
        display.native_bounds.width,
        MAX_DISPLAY_PHYSICAL_DIMENSION,
        invalid,
    )?;
    positive_bounded(
        "native height",
        display.native_bounds.height,
        MAX_DISPLAY_PHYSICAL_DIMENSION,
        invalid,
    )?;
    bounded_coordinate(
        "native maximum x",
        display.native_bounds.x + display.native_bounds.width,
        invalid,
    )?;
    bounded_coordinate(
        "native maximum y",
        display.native_bounds.y + display.native_bounds.height,
        invalid,
    )
}

fn validate_input(
    input: &InputEventV1,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    match input.payload {
        WireInputPayloadV1::PointerMove { dx, dy } => {
            finite("pointer dx", dx, invalid)?;
            finite("pointer dy", dy, invalid)
        }
        WireInputPayloadV1::Scroll {
            horizontal,
            vertical,
        } => {
            finite("horizontal scroll", horizontal, invalid)?;
            finite("vertical scroll", vertical, invalid)
        }
        WireInputPayloadV1::Key { .. } | WireInputPayloadV1::PointerButton { .. } => Ok(()),
    }
}

fn validate_release_v2(
    release: &ReleaseInputV2,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    positive_counter("release transaction", release.transaction_id, invalid)?;
    nonzero_secret("release token", &release.release_token, invalid)?;
    nonzero_secret("old session", &release.old_session_id, invalid)?;
    if release.release_token == release.old_session_id {
        return Err(invalid(
            "release token and old session identifier must differ".to_owned(),
        ));
    }
    positive_counter("release sequence", release.sequence, invalid)?;
    positive_counter(
        "covered input sequence",
        release.covered_input_sequence,
        invalid,
    )?;
    if release.covered_input_sequence >= release.sequence {
        return Err(invalid(
            "covered input sequence must precede the release sequence".to_owned(),
        ));
    }
    non_nil_id("release source host", release.source_host.0, invalid)?;
    non_nil_id("release applying host", release.applying_host.0, invalid)?;
    if release.source_host == release.applying_host {
        return Err(invalid(
            "release source and applying hosts must differ".to_owned(),
        ));
    }
    if let Some(device) = release.source_device {
        non_nil_id("release source device", device.0, invalid)?;
    }
    list_len("keys", release.keys.len(), MAX_RELEASE_KEYS, invalid)?;
    list_len(
        "buttons",
        release.buttons.len(),
        MAX_RELEASE_BUTTONS,
        invalid,
    )?;
    let control_count = release
        .keys
        .len()
        .checked_add(release.buttons.len())
        .ok_or_else(|| invalid("release control count exceeds maximum".to_owned()))?;
    list_len("controls", control_count, MAX_RELEASE_CONTROLS, invalid)?;
    if !all_unique(&release.keys) || !all_unique(&release.buttons) {
        return Err(invalid(
            "release controls must not contain duplicates".to_owned(),
        ));
    }
    Ok(())
}

fn validate_release_ack_v2(
    acknowledgement: &ReleaseAppliedAckV2,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    positive_counter(
        "release transaction",
        acknowledgement.transaction_id,
        invalid,
    )?;
    nonzero_secret("release token", &acknowledgement.release_token, invalid)?;
    nonzero_secret("old session", &acknowledgement.old_session_id, invalid)?;
    if acknowledgement.release_token == acknowledgement.old_session_id {
        return Err(invalid(
            "release token and old session identifier must differ".to_owned(),
        ));
    }
    positive_counter(
        "acknowledgement sequence",
        acknowledgement.sequence,
        invalid,
    )?;
    positive_counter(
        "acknowledged release sequence",
        acknowledgement.release_sequence,
        invalid,
    )?;
    positive_counter(
        "covered input sequence",
        acknowledgement.covered_input_sequence,
        invalid,
    )?;
    if acknowledgement.covered_input_sequence >= acknowledgement.release_sequence {
        return Err(invalid(
            "covered input sequence must precede the acknowledged release sequence".to_owned(),
        ));
    }
    non_nil_id(
        "acknowledgement source host",
        acknowledgement.source_host.0,
        invalid,
    )?;
    non_nil_id(
        "acknowledgement applying host",
        acknowledgement.applying_host.0,
        invalid,
    )?;
    if acknowledgement.source_host == acknowledgement.applying_host {
        return Err(invalid(
            "acknowledgement source and applying hosts must differ".to_owned(),
        ));
    }
    Ok(())
}

fn positive_counter(
    name: &str,
    value: u64,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if value == 0 {
        return Err(invalid(format!("{name} must be positive")));
    }
    Ok(())
}

fn nonzero_secret(
    name: &str,
    value: &[u8; 32],
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if value == &[0; 32] {
        return Err(invalid(format!("{name} must be nonzero")));
    }
    Ok(())
}

fn all_unique<T: Copy + Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut unique = HashSet::with_capacity(values.len());
    values.iter().copied().all(|value| unique.insert(value))
}

fn normalized(
    value: f64,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(invalid(
            "normalized position must be finite and in 0.0..=1.0".to_owned(),
        ));
    }
    Ok(())
}

fn finite(
    name: &str,
    value: f64,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if !value.is_finite() {
        return Err(invalid(format!("{name} must be finite")));
    }
    Ok(())
}

fn positive_bounded(
    name: &str,
    value: f64,
    maximum: f64,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if !value.is_finite() || value <= 0.0 || value > maximum {
        return Err(invalid(format!(
            "{name} must be finite, positive, and within its permitted bound"
        )));
    }
    Ok(())
}

fn bounded_coordinate(
    name: &str,
    value: f64,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if !value.is_finite() || value.abs() > MAX_DISPLAY_NATIVE_COORDINATE_ABS {
        return Err(invalid(format!(
            "{name} must be finite and within its permitted bound"
        )));
    }
    Ok(())
}

fn positive_revision(
    subject: &str,
    revision: u64,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if revision == 0 {
        return Err(invalid(format!("{subject} revision must be positive")));
    }
    Ok(())
}

fn non_nil_id(
    name: &str,
    value: [u8; 16],
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if value == [0; 16] {
        return Err(invalid(format!("{name} identifier must be non-nil")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    const HOST_A: WireHostId = WireHostId([1; 16]);
    const HOST_B: WireHostId = WireHostId([2; 16]);
    const PEER: WirePeerId = WirePeerId([3; 16]);
    const DEVICE: WireDeviceId = WireDeviceId([4; 16]);
    const DISPLAY_A: WireDisplayId = WireDisplayId([5; 16]);
    const DISPLAY_B: WireDisplayId = WireDisplayId([6; 16]);

    fn device() -> WireInputDeviceV1 {
        WireInputDeviceV1 {
            id: DEVICE,
            host_id: HOST_A,
            name: "MX Master".into(),
            vendor_id: Some(0x046d),
            product_id: Some(0xb034),
            kind: WireDeviceKind::Mouse,
            capabilities: WireDeviceCapabilities {
                pointer: true,
                vertical_scroll: true,
                horizontal_scroll: true,
                extra_buttons: true,
                ..WireDeviceCapabilities::default()
            },
        }
    }

    fn indexed_device(index: usize) -> WireInputDeviceV1 {
        let mut value = device();
        let mut id = [0_u8; 16];
        id[..8].copy_from_slice(
            &u64::try_from(index + 1)
                .expect("bounded test index fits in u64")
                .to_be_bytes(),
        );
        value.id = WireDeviceId(id);
        value
    }

    fn display(id: WireDisplayId, host_id: WireHostId) -> WireDisplayV1 {
        WireDisplayV1 {
            id,
            host_id,
            name: "Retina".into(),
            logical_size: WireSize {
                width: 1728.0,
                height: 1117.0,
            },
            physical_size: Some(WireSize {
                width: 3456.0,
                height: 2234.0,
            }),
            scale_factor: 2.0,
            refresh_rate: Some(120.0),
            native_bounds: WireRect {
                x: 0.0,
                y: 0.0,
                width: 3456.0,
                height: 2234.0,
            },
            primary: true,
        }
    }

    fn display_snapshot(displays: Vec<WireDisplayV1>) -> WireMessage {
        WireMessage::DisplaySnapshot(DisplaySnapshotV1 {
            revision: 1,
            host_id: HOST_A,
            displays,
        })
    }

    fn release_v2() -> ReleaseInputV2 {
        ReleaseInputV2 {
            transaction_id: 17,
            release_token: [19; 32],
            old_session_id: [21; 32],
            sequence: 23,
            covered_input_sequence: 22,
            source_host: HOST_A,
            applying_host: HOST_B,
            source_device: Some(DEVICE),
            reason: ReleaseReasonV2::RouteChanged,
            keys: vec![WireKeyCode {
                usage_page: 0x07,
                usage: 0xe0,
            }],
            buttons: vec![WirePointerButton::Primary],
        }
    }

    fn release_ack_v2() -> ReleaseAppliedAckV2 {
        ReleaseAppliedAckV2 {
            transaction_id: 17,
            release_token: [19; 32],
            old_session_id: [21; 32],
            sequence: 29,
            release_sequence: 23,
            covered_input_sequence: 22,
            source_host: HOST_A,
            applying_host: HOST_B,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn messages() -> Vec<WireMessage> {
        let input = InputEventV1 {
            sequence: 42,
            timestamp_ns: 7_000,
            source_host: HOST_A,
            source_device: DEVICE,
            payload: WireInputPayloadV1::PointerMove { dx: 1.5, dy: -2.0 },
        };
        vec![
            WireMessage::Hello(HelloV1 {
                host_id: HOST_A,
                peer_id: PEER,
                host_name: "desk-pc".into(),
                platform: WirePlatform::Windows,
                minimum_protocol_version: 1,
                maximum_protocol_version: 1,
                daemon_version: "0.1.0".into(),
                nonce: [9; 32],
            }),
            WireMessage::Authenticate(AuthenticateV1 {
                peer_id: PEER,
                scheme: "tls-exporter-v1".into(),
                proof: vec![8; 32],
            }),
            WireMessage::DeviceSnapshot(DeviceSnapshotV1 {
                revision: 1,
                host_id: HOST_A,
                devices: vec![device()],
            }),
            WireMessage::DeviceAdded(DeviceAddedV1 {
                revision: 2,
                device: device(),
            }),
            WireMessage::DeviceRemoved(DeviceRemovedV1 {
                revision: 3,
                host_id: HOST_A,
                device_id: DEVICE,
            }),
            WireMessage::DisplaySnapshot(DisplaySnapshotV1 {
                revision: 1,
                host_id: HOST_A,
                displays: vec![display(DISPLAY_A, HOST_A)],
            }),
            WireMessage::DisplayUpdated(DisplayUpdatedV1 {
                revision: 2,
                display: display(DISPLAY_A, HOST_A),
            }),
            WireMessage::Input(input),
            WireMessage::PointerEnter(PointerEnterV1 {
                transition_id: 5,
                workspace_epoch: 9,
                sequence: 43,
                source_host: HOST_A,
                destination_host: HOST_B,
                source_display: DISPLAY_A,
                destination_display: DISPLAY_B,
                destination_edge: WireEdge::Top,
                normalized_position: 0.25,
            }),
            WireMessage::PointerLeave(PointerLeaveV1 {
                transition_id: 5,
                workspace_epoch: 9,
                sequence: 43,
                source_host: HOST_A,
                source_display: DISPLAY_A,
                edge: WireEdge::Bottom,
                normalized_position: 0.25,
            }),
            WireMessage::PointerTransitionAck(PointerTransitionAckV1 {
                transition_id: 5,
                workspace_epoch: 9,
                receiver_host: HOST_B,
                active_display: DISPLAY_B,
                outcome: PointerTransitionOutcomeV1::Accepted,
            }),
            WireMessage::PointerTransitionCommit(PointerTransitionCommitV1 {
                transition_id: 5,
                workspace_epoch: 9,
                sequence: 5,
                source_host: HOST_A,
                destination_host: HOST_B,
                source_display: DISPLAY_A,
                destination_display: DISPLAY_B,
            }),
            WireMessage::Clipboard(ClipboardV1 {
                update_id: WireClipboardId([7; 16]),
                origin_host: HOST_A,
                sequence: 10,
                text: "hello".into(),
            }),
            WireMessage::Ping(PingV1 {
                nonce: 77,
                sent_at_ns: 100,
            }),
            WireMessage::Pong(PongV1 {
                nonce: 77,
                ping_sent_at_ns: 100,
                received_at_ns: 105,
            }),
            WireMessage::ReleaseInput(ReleaseInputV1 {
                sequence: 44,
                source_host: HOST_A,
                source_device: Some(DEVICE),
                reason: ReleaseReasonV1::RouteChanged,
                keys: vec![WireKeyCode {
                    usage_page: 0x07,
                    usage: 0xe0,
                }],
                buttons: vec![WirePointerButton::Primary],
            }),
        ]
    }

    #[test]
    fn every_v1_message_round_trips_through_a_frame() {
        for message in messages() {
            let encoded = encode_frame(&message).expect("valid message must encode");
            assert_eq!(decode_frame(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn v2_release_and_ack_require_and_round_trip_in_v2_framing() {
        for message in [
            WireMessage::ReleaseInputV2(release_v2()),
            WireMessage::ReleaseAppliedAckV2(release_ack_v2()),
        ] {
            assert_eq!(message.minimum_protocol_version(), PROTOCOL_VERSION_V2);
            assert!(matches!(
                encode_frame(&message),
                Err(ProtocolError::MessageVersionMismatch {
                    version: PROTOCOL_VERSION_V1,
                    ..
                })
            ));

            let encoded = encode_frame_for_version(&message, PROTOCOL_VERSION_V2).unwrap();
            assert_eq!(
                FrameHeader::decode_supported(&encoded)
                    .unwrap()
                    .protocol_version,
                PROTOCOL_VERSION_V2
            );
            assert_eq!(
                decode_frame_for_version(&encoded, PROTOCOL_VERSION_V2).unwrap(),
                message
            );
            assert!(matches!(
                decode_frame_for_version(&encoded, PROTOCOL_VERSION_V1),
                Err(ProtocolError::UnsupportedVersion {
                    received: PROTOCOL_VERSION_V2,
                    supported: PROTOCOL_VERSION_V1,
                })
            ));
        }
    }

    #[test]
    fn common_messages_support_exact_v1_and_v2_framing() {
        let message = WireMessage::Ping(PingV1 {
            nonce: 7,
            sent_at_ns: 11,
        });
        let legacy = encode_frame(&message).unwrap();
        assert_eq!(FrameHeader::decode(&legacy).unwrap().protocol_version, 1);
        assert_eq!(decode_frame(&legacy).unwrap(), message);

        let v2 = encode_frame_for_version(&message, PROTOCOL_VERSION_V2).unwrap();
        assert_eq!(
            FrameHeader::decode_supported(&v2).unwrap().protocol_version,
            2
        );
        assert_eq!(
            decode_frame_for_version(&v2, PROTOCOL_VERSION_V2).unwrap(),
            message
        );
    }

    #[test]
    fn encode_frame_for_version_into_appends_in_place_and_matches_standalone_encode() {
        // Reuse one buffer across several frames: each append must extend it
        // exactly as a standalone encode would, proving the batch framing path
        // appends serialized bytes in place rather than allocating per frame.
        let first = WireMessage::Ping(PingV1 {
            nonce: 1,
            sent_at_ns: 2,
        });
        let second = WireMessage::Pong(PongV1 {
            nonce: 1,
            ping_sent_at_ns: 2,
            received_at_ns: 9,
        });

        let mut batch = vec![0xAB, 0xCD];
        let prefix_len = batch.len();
        encode_frame_for_version_into(&first, PROTOCOL_VERSION_V1, &mut batch).unwrap();
        encode_frame_for_version_into(&second, PROTOCOL_VERSION_V1, &mut batch).unwrap();

        // The pre-existing bytes are untouched.
        assert_eq!(&batch[..prefix_len], &[0xAB, 0xCD]);

        let encoded_first = encode_frame_for_version(&first, PROTOCOL_VERSION_V1).unwrap();
        let encoded_second = encode_frame_for_version(&second, PROTOCOL_VERSION_V1).unwrap();
        let first_region = prefix_len..prefix_len + encoded_first.len();
        let second_region = prefix_len + encoded_first.len()..;

        assert_eq!(&batch[first_region.clone()], encoded_first.as_slice());
        assert_eq!(&batch[second_region.clone()], encoded_second.as_slice());

        // Each appended frame still round-trips independently.
        assert_eq!(decode_frame(&batch[first_region]).unwrap(), first);
        assert_eq!(decode_frame(&batch[second_region]).unwrap(), second);
    }

    #[test]
    fn encode_frame_for_version_into_leaves_the_buffer_untouched_on_error() {
        let invalid = WireMessage::PointerLeave(PointerLeaveV1 {
            transition_id: 1,
            workspace_epoch: 1,
            sequence: 1,
            source_host: HOST_A,
            source_display: DISPLAY_A,
            edge: WireEdge::Bottom,
            normalized_position: f64::NAN,
        });
        let mut batch = vec![0x11, 0x22, 0x33];
        let len_before = batch.len();
        assert!(encode_frame_for_version_into(&invalid, PROTOCOL_VERSION_V1, &mut batch).is_err());
        assert_eq!(batch.len(), len_before);
        assert_eq!(batch, vec![0x11_u8, 0x22, 0x33]);
    }

    #[test]
    fn release_proof_capability_applies_to_v2_and_later() {
        assert_eq!(RELEASE_PROOF_PROTOCOL_VERSION, PROTOCOL_VERSION_V2);
        assert!(!supports_release_proof(0));
        assert!(!supports_release_proof(PROTOCOL_VERSION_V1));
        assert!(supports_release_proof(PROTOCOL_VERSION_V2));
        assert!(supports_release_proof(PROTOCOL_VERSION_V3));
        assert!(!supports_release_proof(CURRENT_PROTOCOL_VERSION + 1));
    }

    #[test]
    fn initial_hello_remains_v1_compatible_while_advertising_v2() {
        let hello = WireMessage::Hello(HelloV1 {
            host_id: HOST_A,
            peer_id: PEER,
            host_name: "negotiating-host".to_owned(),
            platform: WirePlatform::Linux,
            minimum_protocol_version: PROTOCOL_VERSION_V1,
            maximum_protocol_version: PROTOCOL_VERSION_V2,
            daemon_version: "0.2.0".to_owned(),
            nonce: [13; 32],
        });
        let encoded = encode_frame(&hello).unwrap();
        assert_eq!(FrameHeader::decode(&encoded).unwrap().protocol_version, 1);
        assert_eq!(decode_frame(&encoded).unwrap(), hello);
    }

    #[test]
    fn v2_release_validation_is_bounded_identity_exact_and_duplicate_free() {
        let assert_invalid = |release: ReleaseInputV2| {
            assert!(WireMessage::ReleaseInputV2(release).validate().is_err());
        };

        let mut invalid = release_v2();
        invalid.transaction_id = 0;
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.release_token = [0; 32];
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.old_session_id = [0; 32];
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.old_session_id = invalid.release_token;
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.sequence = 0;
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.covered_input_sequence = 0;
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.covered_input_sequence = invalid.sequence;
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.source_host = WireHostId([0; 16]);
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.applying_host = WireHostId([0; 16]);
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.applying_host = invalid.source_host;
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.source_device = Some(WireDeviceId([0; 16]));
        assert_invalid(invalid);

        let mut invalid = release_v2();
        invalid.keys.push(invalid.keys[0]);
        assert_invalid(invalid);
        let mut invalid = release_v2();
        invalid.buttons.push(invalid.buttons[0]);
        assert_invalid(invalid);

        let mut maximum = release_v2();
        maximum.keys = (0..MAX_RELEASE_KEYS)
            .map(|usage| WireKeyCode {
                usage_page: 0x07,
                usage: u16::try_from(usage).unwrap(),
            })
            .collect();
        maximum.buttons.clear();
        WireMessage::ReleaseInputV2(maximum.clone())
            .validate()
            .unwrap();
        maximum.keys.push(WireKeyCode {
            usage_page: 0x0c,
            usage: 1,
        });
        assert_invalid(maximum);

        let mut oversized_buttons = release_v2();
        oversized_buttons.keys.clear();
        oversized_buttons.buttons = (0..MAX_RELEASE_BUTTONS)
            .map(|button| WirePointerButton::Other(u16::try_from(button).unwrap()))
            .collect();
        WireMessage::ReleaseInputV2(oversized_buttons.clone())
            .validate()
            .unwrap();
        oversized_buttons.buttons = (0..=MAX_RELEASE_BUTTONS)
            .map(|button| WirePointerButton::Other(u16::try_from(button).unwrap()))
            .collect();
        assert_invalid(oversized_buttons);

        let mut oversized_combined = release_v2();
        oversized_combined.keys = (0..(MAX_RELEASE_CONTROLS - 1))
            .map(|usage| WireKeyCode {
                usage_page: 0x07,
                usage: u16::try_from(usage).unwrap(),
            })
            .collect();
        oversized_combined.buttons = vec![WirePointerButton::Primary, WirePointerButton::Secondary];
        assert_invalid(oversized_combined);

        let mut release_all = release_v2();
        release_all.keys.clear();
        release_all.buttons.clear();
        WireMessage::ReleaseInputV2(release_all).validate().unwrap();
    }

    #[test]
    fn v2_ack_validation_requires_positive_exact_distinct_authority() {
        let assert_invalid = |acknowledgement: ReleaseAppliedAckV2| {
            assert!(WireMessage::ReleaseAppliedAckV2(acknowledgement)
                .validate()
                .is_err());
        };

        let mut invalid = release_ack_v2();
        invalid.transaction_id = 0;
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.release_token = [0; 32];
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.old_session_id = [0; 32];
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.old_session_id = invalid.release_token;
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.sequence = 0;
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.release_sequence = 0;
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.covered_input_sequence = 0;
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.covered_input_sequence = invalid.release_sequence;
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.source_host = WireHostId([0; 16]);
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.applying_host = WireHostId([0; 16]);
        assert_invalid(invalid);
        let mut invalid = release_ack_v2();
        invalid.applying_host = invalid.source_host;
        assert_invalid(invalid);
    }

    #[test]
    fn v2_release_diagnostics_redact_authority_controls_and_correlation() {
        let release = ReleaseInputV2 {
            transaction_id: 8_675_309,
            release_token: [181; 32],
            old_session_id: [191; 32],
            sequence: 8_675_310,
            covered_input_sequence: 8_675_308,
            source_host: WireHostId([211; 16]),
            applying_host: WireHostId([223; 16]),
            source_device: Some(WireDeviceId([199; 16])),
            reason: ReleaseReasonV2::StateResynchronization,
            keys: vec![WireKeyCode {
                usage_page: 53_191,
                usage: 54_321,
            }],
            buttons: vec![WirePointerButton::Other(43_219)],
        };
        let acknowledgement = ReleaseAppliedAckV2 {
            transaction_id: release.transaction_id,
            release_token: release.release_token,
            old_session_id: release.old_session_id,
            sequence: 8_675_311,
            release_sequence: release.sequence,
            covered_input_sequence: release.covered_input_sequence,
            source_host: release.source_host,
            applying_host: release.applying_host,
        };
        for debug in [
            format!("{release:?}"),
            format!("{acknowledgement:?}"),
            format!("{:?}", WireMessage::ReleaseInputV2(release)),
            format!("{:?}", WireMessage::ReleaseAppliedAckV2(acknowledgement)),
        ] {
            assert!(!debug.contains("8675309"));
            assert!(!debug.contains("8675308"));
            assert!(!debug.contains("8675310"));
            assert!(!debug.contains("8675311"));
            assert!(!debug.contains("211, 211"));
            assert!(!debug.contains("223, 223"));
            assert!(!debug.contains("199, 199"));
            assert!(!debug.contains("181, 181"));
            assert!(!debug.contains("191, 191"));
            assert!(!debug.contains("53191"));
            assert!(!debug.contains("54321"));
            assert!(!debug.contains("43219"));
        }
    }

    #[test]
    fn authentication_proof_is_redacted_from_debug_output() {
        let message = WireMessage::Authenticate(AuthenticateV1 {
            peer_id: PEER,
            scheme: "tls-exporter-v1".to_owned(),
            proof: b"distinct-exporter-proof-marker".to_vec(),
        });

        let debug = format!("{message:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("distinct-exporter-proof-marker"));
        assert!(!debug.contains("100, 105, 115, 116, 105, 110, 99, 116"));
    }

    #[test]
    fn device_inventory_diagnostics_are_payload_free() {
        let marked = WireInputDeviceV1 {
            id: WireDeviceId([211; 16]),
            host_id: WireHostId([223; 16]),
            name: "peer-controlled-device-name-marker".to_owned(),
            vendor_id: Some(45_321),
            product_id: Some(54_321),
            kind: WireDeviceKind::Keyboard,
            capabilities: WireDeviceCapabilities {
                keyboard: true,
                ..WireDeviceCapabilities::default()
            },
        };
        let snapshot = DeviceSnapshotV1 {
            revision: 8_675_309,
            host_id: marked.host_id,
            devices: vec![marked.clone()],
        };
        let added = DeviceAddedV1 {
            revision: 8_675_310,
            device: marked.clone(),
        };
        let removed = DeviceRemovedV1 {
            revision: 8_675_311,
            host_id: marked.host_id,
            device_id: marked.id,
        };

        assert_eq!(format!("{marked:?}"), "WireInputDeviceV1([REDACTED])");
        assert_eq!(
            format!("{snapshot:?}"),
            "DeviceSnapshotV1 { device_count: 1, .. }"
        );
        assert_eq!(format!("{added:?}"), "DeviceAddedV1([REDACTED])");
        assert_eq!(format!("{removed:?}"), "DeviceRemovedV1([REDACTED])");

        for debug in [
            format!("{snapshot:?}"),
            format!("{added:?}"),
            format!("{removed:?}"),
            format!("{:?}", WireMessage::DeviceSnapshot(snapshot)),
        ] {
            assert!(!debug.contains("peer-controlled-device-name-marker"));
            assert!(!debug.contains("8675309"));
            assert!(!debug.contains("211, 211"));
            assert!(!debug.contains("223, 223"));
            assert!(!debug.contains("45321"));
            assert!(!debug.contains("54321"));
        }
    }

    #[test]
    fn input_and_release_diagnostics_are_payload_free() {
        let key = WireKeyCode {
            usage_page: 53_191,
            usage: 54_321,
        };
        let button = WirePointerButton::Other(43_219);
        assert_eq!(format!("{key:?}"), "WireKeyCode([REDACTED])");
        assert_eq!(
            format!("{:?}", WireKeyState::Repeat),
            "WireKeyState([REDACTED])"
        );
        assert_eq!(format!("{button:?}"), "WirePointerButton([REDACTED])");
        assert_eq!(
            format!("{:?}", WireButtonState::Down),
            "WireButtonState([REDACTED])"
        );

        let payloads = [
            WireInputPayloadV1::Key {
                code: key,
                state: WireKeyState::Repeat,
            },
            WireInputPayloadV1::PointerMove {
                dx: 12_345.678_9,
                dy: -98_765.432_1,
            },
            WireInputPayloadV1::PointerButton {
                button,
                state: WireButtonState::Down,
            },
            WireInputPayloadV1::Scroll {
                horizontal: 23_456.789_1,
                vertical: -87_654.321_9,
            },
        ];
        for payload in &payloads {
            let debug = format!("{payload:?}");
            assert!(debug.contains("WireInputPayloadV1"));
            assert!(!debug.contains("53191"));
            assert!(!debug.contains("54321"));
            assert!(!debug.contains("43219"));
            assert!(!debug.contains("12345.6789"));
            assert!(!debug.contains("98765.4321"));
            assert!(!debug.contains("23456.7891"));
            assert!(!debug.contains("87654.3219"));
            assert!(!debug.contains("Repeat"));
            assert!(!debug.contains("Down"));
        }

        let event = InputEventV1 {
            sequence: 8_675_309,
            timestamp_ns: 9_753_124_680,
            source_host: WireHostId([211; 16]),
            source_device: WireDeviceId([223; 16]),
            payload: payloads[1].clone(),
        };
        let release = ReleaseInputV1 {
            sequence: 8_675_310,
            source_host: WireHostId([211; 16]),
            source_device: Some(WireDeviceId([223; 16])),
            reason: ReleaseReasonV1::StateResynchronization,
            keys: vec![key],
            buttons: vec![button],
        };

        let event_debug = format!("{event:?}");
        assert!(event_debug.contains("PointerMove"));
        assert!(event_debug.contains("[REDACTED]"));
        let release_debug = format!("{release:?}");
        assert!(release_debug.contains("StateResynchronization"));
        assert!(release_debug.contains("key_count: 1"));
        assert!(release_debug.contains("button_count: 1"));
        assert!(release_debug.contains("[REDACTED]"));

        for debug in [
            event_debug,
            release_debug,
            format!("{:?}", WireMessage::Input(event)),
            format!("{:?}", WireMessage::ReleaseInput(release)),
        ] {
            assert!(!debug.contains("8675309"));
            assert!(!debug.contains("8675310"));
            assert!(!debug.contains("9753124680"));
            assert!(!debug.contains("211, 211"));
            assert!(!debug.contains("223, 223"));
            assert!(!debug.contains("53191"));
            assert!(!debug.contains("54321"));
            assert!(!debug.contains("43219"));
            assert!(!debug.contains("12345.6789"));
            assert!(!debug.contains("98765.4321"));
        }
    }

    #[test]
    fn device_snapshots_reject_revision_identity_owner_name_and_duplicates() {
        let assert_invalid = |snapshot: DeviceSnapshotV1| {
            assert!(matches!(
                snapshot.validate(),
                Err(ValidationError {
                    message_type: MessageType::DeviceSnapshot,
                    ..
                })
            ));
        };

        let mut snapshot = DeviceSnapshotV1 {
            revision: 1,
            host_id: HOST_A,
            devices: vec![device()],
        };
        snapshot.revision = 0;
        assert_invalid(snapshot.clone());
        snapshot.revision = 1;
        snapshot.host_id = WireHostId([0; 16]);
        snapshot.devices[0].host_id = snapshot.host_id;
        assert_invalid(snapshot.clone());
        snapshot.host_id = HOST_A;
        snapshot.devices[0].host_id = HOST_A;
        snapshot.devices[0].id = WireDeviceId([0; 16]);
        assert_invalid(snapshot.clone());
        snapshot.devices[0].id = DEVICE;
        snapshot.devices[0].host_id = WireHostId([0; 16]);
        assert_invalid(snapshot.clone());
        snapshot.devices[0].host_id = HOST_B;
        assert_invalid(snapshot.clone());

        snapshot.devices[0].host_id = HOST_A;
        snapshot.devices[0].name.clear();
        assert_invalid(snapshot.clone());
        snapshot.devices[0].name = "   ".to_owned();
        assert_invalid(snapshot.clone());
        snapshot.devices[0].name = "control\nname".to_owned();
        assert_invalid(snapshot.clone());
        snapshot.devices[0].name = "x".repeat(MAX_DEVICE_NAME_BYTES + 1);
        assert_invalid(snapshot);

        let duplicate = device();
        assert_invalid(DeviceSnapshotV1 {
            revision: 1,
            host_id: HOST_A,
            devices: vec![duplicate.clone(), duplicate],
        });
    }

    #[test]
    fn device_snapshots_enforce_count_and_utf8_byte_bounds() {
        let maximum = DeviceSnapshotV1 {
            revision: 1,
            host_id: HOST_A,
            devices: (0..MAX_SNAPSHOT_ITEMS).map(indexed_device).collect(),
        };
        maximum.validate().unwrap();

        let oversized = DeviceSnapshotV1 {
            revision: 1,
            host_id: HOST_A,
            devices: (0..=MAX_SNAPSHOT_ITEMS).map(indexed_device).collect(),
        };
        assert!(oversized.validate().is_err());

        let mut boundary = device();
        boundary.name = format!("{}a", "é".repeat(127));
        assert_eq!(boundary.name.len(), MAX_DEVICE_NAME_BYTES);
        DeviceAddedV1 {
            revision: 1,
            device: boundary.clone(),
        }
        .validate()
        .unwrap();
        boundary.name.push('é');
        assert!(DeviceAddedV1 {
            revision: 1,
            device: boundary,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn device_deltas_reject_zero_revision_nil_ids_and_invalid_names() {
        let mut added = DeviceAddedV1 {
            revision: 0,
            device: device(),
        };
        assert!(matches!(
            added.validate(),
            Err(ValidationError {
                message_type: MessageType::DeviceAdded,
                ..
            })
        ));
        added.revision = 1;
        added.device.id = WireDeviceId([0; 16]);
        assert!(added.validate().is_err());
        added.device.id = DEVICE;
        added.device.host_id = WireHostId([0; 16]);
        assert!(added.validate().is_err());
        added.device.host_id = HOST_A;
        added.device.name = "hidden\npeer-name-marker".to_owned();
        let error = added.validate().unwrap_err();
        assert!(!format!("{error:?} {error}").contains("hidden"));

        for removed in [
            DeviceRemovedV1 {
                revision: 0,
                host_id: HOST_A,
                device_id: DEVICE,
            },
            DeviceRemovedV1 {
                revision: 1,
                host_id: WireHostId([0; 16]),
                device_id: DEVICE,
            },
            DeviceRemovedV1 {
                revision: 1,
                host_id: HOST_A,
                device_id: WireDeviceId([0; 16]),
            },
        ] {
            assert!(matches!(
                removed.validate(),
                Err(ValidationError {
                    message_type: MessageType::DeviceRemoved,
                    ..
                })
            ));
        }
    }

    #[test]
    fn display_and_pointer_diagnostics_are_payload_free() {
        let mut marked = display(DISPLAY_A, HOST_A);
        marked.name = "peer-controlled-display-name-marker".to_owned();
        let snapshot = DisplaySnapshotV1 {
            revision: 91,
            host_id: WireHostId([71; 16]),
            displays: vec![marked.clone()],
        };
        let update = DisplayUpdatedV1 {
            revision: 92,
            display: marked.clone(),
        };
        let pointer = PointerEnterV1 {
            transition_id: 93,
            workspace_epoch: 94,
            sequence: 95,
            source_host: WireHostId([71; 16]),
            destination_host: WireHostId([83; 16]),
            source_display: WireDisplayId([97; 16]),
            destination_display: WireDisplayId([101; 16]),
            destination_edge: WireEdge::Left,
            normalized_position: 0.123_456_789,
        };

        assert_eq!(format!("{marked:?}"), "WireDisplayV1([REDACTED])");
        assert_eq!(
            format!("{snapshot:?}"),
            "DisplaySnapshotV1 { display_count: 1, .. }"
        );
        assert_eq!(format!("{update:?}"), "DisplayUpdatedV1([REDACTED])");
        assert_eq!(format!("{pointer:?}"), "PointerEnterV1([REDACTED])");
        let debug = format!("{:?}", WireMessage::DisplaySnapshot(snapshot));
        assert!(debug.contains("DisplaySnapshot"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("peer-controlled-display-name-marker"));
        assert!(!debug.contains("0.123456789"));
    }

    #[test]
    fn display_snapshots_reject_nil_wrong_duplicate_and_primary_invariants() {
        let assert_invalid = |message: WireMessage| {
            assert!(matches!(
                message.validate(),
                Err(ValidationError {
                    message_type: MessageType::DisplaySnapshot,
                    ..
                })
            ));
        };

        let mut nil_host = DisplaySnapshotV1 {
            revision: 1,
            host_id: WireHostId([0; 16]),
            displays: vec![display(DISPLAY_A, WireHostId([0; 16]))],
        };
        assert_invalid(WireMessage::DisplaySnapshot(nil_host.clone()));
        nil_host.host_id = HOST_A;
        nil_host.displays[0].host_id = HOST_A;
        nil_host.displays[0].id = WireDisplayId([0; 16]);
        assert_invalid(WireMessage::DisplaySnapshot(nil_host));

        let mut wrong_owner = display(DISPLAY_A, HOST_B);
        wrong_owner.primary = true;
        assert_invalid(display_snapshot(vec![wrong_owner]));
        assert_invalid(display_snapshot(vec![
            display(DISPLAY_A, HOST_A),
            display(DISPLAY_A, HOST_A),
        ]));
        let mut no_primary = display(DISPLAY_A, HOST_A);
        no_primary.primary = false;
        assert_invalid(display_snapshot(vec![no_primary]));
        assert_invalid(display_snapshot(vec![
            display(DISPLAY_A, HOST_A),
            display(DISPLAY_B, HOST_A),
        ]));

        let mut zero_revision = display_snapshot(vec![display(DISPLAY_A, HOST_A)]);
        if let WireMessage::DisplaySnapshot(snapshot) = &mut zero_revision {
            snapshot.revision = 0;
        }
        assert_invalid(zero_revision);
    }

    #[test]
    fn display_messages_reject_invalid_names_and_excessive_geometry() {
        let assert_invalid_display = |display: WireDisplayV1| {
            assert!(display_snapshot(vec![display]).validate().is_err());
        };
        for name in [String::new(), "   ".to_owned(), "control\nname".to_owned()] {
            let mut invalid = display(DISPLAY_A, HOST_A);
            invalid.name = name;
            assert_invalid_display(invalid);
        }

        let mut invalid_values = Vec::new();
        let mut invalid = display(DISPLAY_A, HOST_A);
        invalid.logical_size.width = MAX_DISPLAY_LOGICAL_DIMENSION + 1.0;
        invalid_values.push(invalid);
        let mut invalid = display(DISPLAY_A, HOST_A);
        invalid.physical_size = Some(WireSize {
            width: MAX_DISPLAY_PHYSICAL_DIMENSION + 1.0,
            height: 1.0,
        });
        invalid_values.push(invalid);
        let mut invalid = display(DISPLAY_A, HOST_A);
        invalid.scale_factor = MAX_DISPLAY_SCALE_FACTOR + 1.0;
        invalid_values.push(invalid);
        let mut invalid = display(DISPLAY_A, HOST_A);
        invalid.refresh_rate = Some(MAX_DISPLAY_REFRESH_RATE_HZ + 1.0);
        invalid_values.push(invalid);
        let mut invalid = display(DISPLAY_A, HOST_A);
        invalid.native_bounds.x = MAX_DISPLAY_NATIVE_COORDINATE_ABS;
        invalid_values.push(invalid);
        let mut invalid = display(DISPLAY_A, HOST_A);
        invalid.native_bounds.height = f64::INFINITY;
        invalid_values.push(invalid);
        for invalid in invalid_values {
            assert_invalid_display(invalid);
        }

        assert!(WireMessage::DisplayUpdated(DisplayUpdatedV1 {
            revision: 0,
            display: display(DISPLAY_A, HOST_A),
        })
        .validate()
        .is_err());
    }

    #[test]
    fn frame_header_is_fixed_width_and_network_endian() {
        let bytes = FrameHeader {
            protocol_version: 1,
            message_type: MessageType::Input,
            payload_length: 0x0102_0304,
        }
        .encode();
        assert_eq!(&bytes[0..4], b"SKVM");
        assert_eq!(&bytes[4..6], &[0, 1]);
        assert_eq!(&bytes[6..8], &[0, 30]);
        assert_eq!(&bytes[8..12], &[1, 2, 3, 4]);
    }

    #[test]
    fn rejects_version_type_size_and_frame_boundary_errors() {
        let mut wrong_version = FrameHeader {
            protocol_version: 1,
            message_type: MessageType::Ping,
            payload_length: 0,
        }
        .encode();
        wrong_version[5] = 2;
        assert!(matches!(
            FrameHeader::decode(&wrong_version),
            Err(ProtocolError::UnsupportedVersion { received: 2, .. })
        ));

        let mut unknown_type = wrong_version;
        unknown_type[5] = 1;
        unknown_type[6..8].copy_from_slice(&999_u16.to_be_bytes());
        assert_eq!(
            FrameHeader::decode(&unknown_type).unwrap_err(),
            ProtocolError::UnknownMessageType(999)
        );

        let mut oversized = unknown_type;
        oversized[6..8].copy_from_slice(&(MessageType::Ping as u16).to_be_bytes());
        oversized[8..12].copy_from_slice(&1_048_577_u32.to_be_bytes());
        assert!(matches!(
            FrameHeader::decode(&oversized),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));

        let valid = encode_frame(&WireMessage::Ping(PingV1 {
            nonce: 1,
            sent_at_ns: 2,
        }))
        .unwrap();
        assert!(matches!(
            decode_frame(&valid[..valid.len() - 1]),
            Err(ProtocolError::PayloadTruncated { .. })
        ));
        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(
            decode_frame(&trailing).unwrap_err(),
            ProtocolError::TrailingBytes(1)
        );
    }

    #[test]
    fn bootstrap_and_exact_header_parsers_reject_before_payload_buffering() {
        let v2_ping = FrameHeader {
            protocol_version: PROTOCOL_VERSION_V2,
            message_type: MessageType::Ping,
            payload_length: u32::try_from(MAX_FRAME_PAYLOAD).unwrap(),
        }
        .encode();
        assert!(matches!(
            FrameHeader::decode(&v2_ping),
            Err(ProtocolError::UnsupportedVersion {
                received: PROTOCOL_VERSION_V2,
                supported: PROTOCOL_VERSION_V1,
            })
        ));
        assert_eq!(
            FrameHeader::decode_supported(&v2_ping)
                .unwrap()
                .protocol_version,
            PROTOCOL_VERSION_V2
        );
        assert!(matches!(
            FrameHeader::decode_for_version(&v2_ping, PROTOCOL_VERSION_V1),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        let v2_message_in_v1 = FrameHeader {
            protocol_version: PROTOCOL_VERSION_V1,
            message_type: MessageType::ReleaseAppliedAckV2,
            payload_length: u32::try_from(MAX_FRAME_PAYLOAD).unwrap(),
        }
        .encode();
        assert_eq!(
            FrameHeader::decode(&v2_message_in_v1).unwrap_err(),
            ProtocolError::MessageVersionMismatch {
                message_type: MessageType::ReleaseAppliedAckV2,
                version: PROTOCOL_VERSION_V1,
            }
        );
        assert_eq!(
            FrameHeader::decode_for_version(&v2_message_in_v1, PROTOCOL_VERSION_V1).unwrap_err(),
            ProtocolError::MessageVersionMismatch {
                message_type: MessageType::ReleaseAppliedAckV2,
                version: PROTOCOL_VERSION_V1,
            }
        );
    }

    #[test]
    fn rejects_invalid_message_values_before_encoding_and_after_decoding() {
        let invalid = WireMessage::PointerLeave(PointerLeaveV1 {
            transition_id: 1,
            workspace_epoch: 1,
            sequence: 1,
            source_host: HOST_A,
            source_display: DISPLAY_A,
            edge: WireEdge::Bottom,
            normalized_position: f64::NAN,
        });
        assert!(matches!(
            encode_frame(&invalid),
            Err(ProtocolError::InvalidMessage(_))
        ));

        let oversized_clipboard = WireMessage::Clipboard(ClipboardV1 {
            update_id: WireClipboardId([7; 16]),
            origin_host: HOST_A,
            sequence: 1,
            text: "x".repeat(MAX_CLIPBOARD_TEXT_BYTES + 1),
        });
        assert!(matches!(
            encode_frame(&oversized_clipboard),
            Err(ProtocolError::InvalidMessage(_))
        ));
    }
}
