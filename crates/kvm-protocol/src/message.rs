use crate::{
    AuthenticateV1, ClipboardV1, DeviceAddedV1, DeviceRemovedV1, DeviceSnapshotV1,
    DisplaySnapshotV1, DisplayUpdatedV1, HelloV1, InputEventV1, PingV1, PointerEnterV1,
    PointerLeaveV1, PointerTransitionAckV1, PongV1, ProtocolError, ReleaseInputV1, ValidationError,
    WireDisplayV1, WireInputDeviceV1, WireInputPayloadV1, MAX_AUTH_BYTES, MAX_CLIPBOARD_TEXT_BYTES,
    MAX_DEVICE_NAME_BYTES, MAX_DISPLAY_NAME_BYTES, MAX_HOST_NAME_BYTES, MAX_RELEASE_KEYS,
    MAX_SNAPSHOT_ITEMS, PROTOCOL_VERSION,
};
use serde::de::DeserializeOwned;

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
    Clipboard = 40,
    Ping = 50,
    Pong = 51,
    ReleaseInput = 60,
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
            40 => Ok(Self::Clipboard),
            50 => Ok(Self::Ping),
            51 => Ok(Self::Pong),
            60 => Ok(Self::ReleaseInput),
            other => Err(ProtocolError::UnknownMessageType(other)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
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
    Clipboard(ClipboardV1),
    Ping(PingV1),
    Pong(PongV1),
    ReleaseInput(ReleaseInputV1),
}

impl WireMessage {
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
            Self::Clipboard(_) => MessageType::Clipboard,
            Self::Ping(_) => MessageType::Ping,
            Self::Pong(_) => MessageType::Pong,
            Self::ReleaseInput(_) => MessageType::ReleaseInput,
        }
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
                if value.minimum_protocol_version > value.maximum_protocol_version {
                    return Err(invalid(
                        "minimum protocol version exceeds maximum".to_owned(),
                    ));
                }
                if !(value.minimum_protocol_version..=value.maximum_protocol_version)
                    .contains(&PROTOCOL_VERSION)
                {
                    return Err(invalid(
                        "peer does not advertise support for protocol v1".to_owned(),
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
                list_len("devices", value.devices.len(), MAX_SNAPSHOT_ITEMS, &invalid)?;
                for device in &value.devices {
                    validate_device(device, &invalid)?;
                    if device.host_id != value.host_id {
                        return Err(invalid(
                            "snapshot contains a device owned by another host".to_owned(),
                        ));
                    }
                }
            }
            Self::DeviceAdded(value) => validate_device(&value.device, &invalid)?,
            Self::DisplaySnapshot(value) => {
                list_len(
                    "displays",
                    value.displays.len(),
                    MAX_SNAPSHOT_ITEMS,
                    &invalid,
                )?;
                for display in &value.displays {
                    validate_display(display, &invalid)?;
                    if display.host_id != value.host_id {
                        return Err(invalid(
                            "snapshot contains a display owned by another host".to_owned(),
                        ));
                    }
                }
            }
            Self::DisplayUpdated(value) => validate_display(&value.display, &invalid)?,
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
            Self::Clipboard(value) => {
                string_len("text", &value.text, MAX_CLIPBOARD_TEXT_BYTES, &invalid)?;
            }
            Self::ReleaseInput(value) => {
                list_len("keys", value.keys.len(), MAX_RELEASE_KEYS, &invalid)?;
                list_len("buttons", value.buttons.len(), 32, &invalid)?;
            }
            Self::DeviceRemoved(_)
            | Self::PointerTransitionAck(_)
            | Self::Ping(_)
            | Self::Pong(_) => {}
        }
        Ok(())
    }

    pub(crate) fn encode_payload(&self) -> Result<Vec<u8>, postcard::Error> {
        match self {
            Self::Hello(value) => postcard::to_allocvec(value),
            Self::Authenticate(value) => postcard::to_allocvec(value),
            Self::DeviceSnapshot(value) => postcard::to_allocvec(value),
            Self::DeviceAdded(value) => postcard::to_allocvec(value),
            Self::DeviceRemoved(value) => postcard::to_allocvec(value),
            Self::DisplaySnapshot(value) => postcard::to_allocvec(value),
            Self::DisplayUpdated(value) => postcard::to_allocvec(value),
            Self::Input(value) => postcard::to_allocvec(value),
            Self::PointerEnter(value) => postcard::to_allocvec(value),
            Self::PointerLeave(value) => postcard::to_allocvec(value),
            Self::PointerTransitionAck(value) => postcard::to_allocvec(value),
            Self::Clipboard(value) => postcard::to_allocvec(value),
            Self::Ping(value) => postcard::to_allocvec(value),
            Self::Pong(value) => postcard::to_allocvec(value),
            Self::ReleaseInput(value) => postcard::to_allocvec(value),
        }
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
            MessageType::Clipboard => Self::Clipboard(decode(message_type, bytes)?),
            MessageType::Ping => Self::Ping(decode(message_type, bytes)?),
            MessageType::Pong => Self::Pong(decode(message_type, bytes)?),
            MessageType::ReleaseInput => Self::ReleaseInput(decode(message_type, bytes)?),
        })
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
    string_len("device name", &device.name, MAX_DEVICE_NAME_BYTES, invalid)
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
    positive("logical width", display.logical_size.width, invalid)?;
    positive("logical height", display.logical_size.height, invalid)?;
    if let Some(size) = display.physical_size {
        positive("physical width", size.width, invalid)?;
        positive("physical height", size.height, invalid)?;
    }
    positive("scale factor", display.scale_factor, invalid)?;
    if let Some(refresh_rate) = display.refresh_rate {
        positive("refresh rate", refresh_rate, invalid)?;
    }
    finite("native x", display.native_bounds.x, invalid)?;
    finite("native y", display.native_bounds.y, invalid)?;
    positive("native width", display.native_bounds.width, invalid)?;
    positive("native height", display.native_bounds.height, invalid)
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

fn positive(
    name: &str,
    value: f64,
    invalid: &impl Fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(invalid(format!("{name} must be finite and positive")));
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
