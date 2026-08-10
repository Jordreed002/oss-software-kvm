use crate::{MessageType, ProtocolError, WireMessage};

pub const FRAME_MAGIC: [u8; 4] = *b"SKVM";
pub const PROTOCOL_VERSION_V1: u16 = 1;
pub const PROTOCOL_VERSION_V2: u16 = 2;
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u16 = PROTOCOL_VERSION_V1;
pub const CURRENT_PROTOCOL_VERSION: u16 = PROTOCOL_VERSION_V2;
/// First protocol version which normatively requires an application-level
/// applied-release acknowledgement before a held route may move to another
/// peer.
pub const RELEASE_PROOF_PROTOCOL_VERSION: u16 = PROTOCOL_VERSION_V2;
/// Compatibility version used by the original framing helpers.
///
/// Initial Hello frames remain v1 so peers can advertise and authenticate a
/// mutually selected newer version without changing the bootstrap wire shape.
pub const PROTOCOL_VERSION: u16 = PROTOCOL_VERSION_V1;
pub const FRAME_HEADER_LEN: usize = 12;
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

/// Fixed-width, network-byte-order header.
///
/// Layout: `magic[4] | protocol_version:u16 | message_type:u16 |
/// payload_length:u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub protocol_version: u16,
    pub message_type: MessageType,
    pub payload_length: u32,
}

impl FrameHeader {
    #[must_use]
    pub fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let mut bytes = [0_u8; FRAME_HEADER_LEN];
        bytes[0..4].copy_from_slice(&FRAME_MAGIC);
        bytes[4..6].copy_from_slice(&self.protocol_version.to_be_bytes());
        bytes[6..8].copy_from_slice(&(self.message_type as u16).to_be_bytes());
        bytes[8..12].copy_from_slice(&self.payload_length.to_be_bytes());
        bytes
    }

    /// Parses and validates a fixed-width frame header.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] when the header is truncated, has invalid
    /// magic, advertises a version outside the supported range or an unknown
    /// message type, or declares a payload larger than [`MAX_FRAME_PAYLOAD`].
    ///
    /// This compatibility parser accepts only v1. Bootstrap readers use it so
    /// a v2 frame is rejected from its fixed header before any payload is
    /// buffered. Use [`Self::decode_supported`] only after negotiation logic
    /// is ready to select an exact supported version.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let header = Self::decode_supported(bytes)?;
        if header.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ProtocolError::UnsupportedVersion {
                received: header.protocol_version,
                supported: PROTOCOL_VERSION_V1,
            });
        }
        Ok(header)
    }

    /// Structurally parses a header for any supported protocol version.
    ///
    /// Message availability is checked here, before a transport allocates or
    /// buffers the declared payload.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] for malformed headers, unsupported versions,
    /// message/version mismatches, or excessive declared payloads.
    pub fn decode_supported(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(ProtocolError::HeaderTruncated {
                expected: FRAME_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if magic != FRAME_MAGIC {
            return Err(ProtocolError::InvalidMagic(magic));
        }

        let protocol_version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if !is_supported_protocol_version(protocol_version) {
            return Err(ProtocolError::UnsupportedVersion {
                received: protocol_version,
                supported: CURRENT_PROTOCOL_VERSION,
            });
        }

        let message_type = MessageType::try_from(u16::from_be_bytes([bytes[6], bytes[7]]))?;
        require_message_version(message_type, protocol_version)?;
        let payload_length = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if payload_length as usize > MAX_FRAME_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge {
                length: payload_length as usize,
                maximum: MAX_FRAME_PAYLOAD,
            });
        }

        Ok(Self {
            protocol_version,
            message_type,
            payload_length,
        })
    }

    /// Parses a header and enforces one already negotiated framing version.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] for malformed headers, unsupported requested
    /// versions, or a header which does not use `required_version`.
    pub fn decode_for_version(bytes: &[u8], required_version: u16) -> Result<Self, ProtocolError> {
        require_supported_version(required_version)?;
        let header = Self::decode_supported(bytes)?;
        if header.protocol_version != required_version {
            return Err(ProtocolError::UnsupportedVersion {
                received: header.protocol_version,
                supported: required_version,
            });
        }
        Ok(header)
    }
}

/// Validates and serializes a message into one complete v1 frame.
///
/// # Errors
///
/// Returns [`ProtocolError`] if the message is invalid, cannot be serialized,
/// or exceeds the protocol payload limit.
pub fn encode_frame(message: &WireMessage) -> Result<Vec<u8>, ProtocolError> {
    encode_frame_for_version(message, PROTOCOL_VERSION)
}

/// Validates and serializes a message using an exact supported framing
/// version selected by the session.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested version is unsupported, the
/// message requires a newer version, or encoding violates a protocol bound.
pub fn encode_frame_for_version(
    message: &WireMessage,
    required_version: u16,
) -> Result<Vec<u8>, ProtocolError> {
    let mut frame = Vec::new();
    encode_frame_for_version_into(message, required_version, &mut frame)?;
    Ok(frame)
}

/// Validates and serializes a message, appending exactly one complete frame
/// onto `out`.
///
/// Unlike [`encode_frame_for_version`], this serializes the payload directly
/// into the caller's buffer (no intermediate allocation), which is what makes
/// batch framing cheap under a burst: many frames share one growing buffer.
///
/// On error the buffer is left at its entry length.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested version is unsupported, the
/// message requires a newer version, or encoding violates a protocol bound.
pub fn encode_frame_for_version_into(
    message: &WireMessage,
    required_version: u16,
    out: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    require_supported_version(required_version)?;
    require_message_version(message.message_type(), required_version)?;
    message.validate()?;
    let message_type = message.message_type();

    let header_start = out.len();
    // Reserve a placeholder header; the real length is patched in once the
    // payload has been serialized so we never need to know its size up front.
    out.extend_from_slice(&[0_u8; FRAME_HEADER_LEN]);
    let payload_start = out.len();
    message
        .encode_payload_into(out)
        .map_err(|error| ProtocolError::Encode {
            message_type,
            detail: error.to_string(),
        })?;
    let payload_len = out.len() - payload_start;
    if payload_len > MAX_FRAME_PAYLOAD {
        out.truncate(header_start);
        return Err(ProtocolError::PayloadTooLarge {
            length: payload_len,
            maximum: MAX_FRAME_PAYLOAD,
        });
    }

    let payload_length =
        u32::try_from(payload_len).map_err(|_| ProtocolError::PayloadTooLarge {
            length: payload_len,
            maximum: MAX_FRAME_PAYLOAD,
        })?;
    let header = FrameHeader {
        protocol_version: required_version,
        message_type,
        payload_length,
    };
    out[header_start..header_start + FRAME_HEADER_LEN].copy_from_slice(&header.encode());
    Ok(())
}

/// Decodes exactly one complete frame.
///
/// Transport code should first buffer `FRAME_HEADER_LEN`, inspect
/// `payload_length`, and then buffer exactly that many additional bytes. This
/// function intentionally rejects trailing bytes so frame boundaries cannot be
/// confused by callers.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the header, frame boundary, serialized
/// payload, or decoded message values violate protocol v1.
pub fn decode_frame(frame: &[u8]) -> Result<WireMessage, ProtocolError> {
    decode_frame_for_version(frame, PROTOCOL_VERSION)
}

/// Decodes exactly one frame using an already negotiated required version.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the frame version differs, the message is
/// unavailable in that version, or any frame/payload invariant is invalid.
pub fn decode_frame_for_version(
    frame: &[u8],
    required_version: u16,
) -> Result<WireMessage, ProtocolError> {
    let header = FrameHeader::decode_for_version(frame, required_version)?;
    require_message_version(header.message_type, required_version)?;
    let declared = header.payload_length as usize;
    let available = frame.len().saturating_sub(FRAME_HEADER_LEN);
    if available < declared {
        return Err(ProtocolError::PayloadTruncated {
            declared,
            available,
        });
    }
    if available > declared {
        return Err(ProtocolError::TrailingBytes(available - declared));
    }

    let message = WireMessage::decode_payload(header.message_type, &frame[FRAME_HEADER_LEN..])?;
    message.validate()?;
    Ok(message)
}

#[must_use]
pub const fn is_supported_protocol_version(version: u16) -> bool {
    version >= MIN_SUPPORTED_PROTOCOL_VERSION && version <= CURRENT_PROTOCOL_VERSION
}

/// Returns whether an exact supported protocol version provides mandatory
/// application-level release proof.
///
/// Callers should use this semantic capability check instead of comparing raw
/// version numbers when deciding whether cross-peer route movement is safe.
#[must_use]
pub const fn supports_release_proof(version: u16) -> bool {
    is_supported_protocol_version(version) && version >= RELEASE_PROOF_PROTOCOL_VERSION
}

fn require_supported_version(version: u16) -> Result<(), ProtocolError> {
    if is_supported_protocol_version(version) {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion {
            received: version,
            supported: CURRENT_PROTOCOL_VERSION,
        })
    }
}

fn require_message_version(message_type: MessageType, version: u16) -> Result<(), ProtocolError> {
    if version < message_type.minimum_protocol_version() {
        Err(ProtocolError::MessageVersionMismatch {
            message_type,
            version,
        })
    } else {
        Ok(())
    }
}
