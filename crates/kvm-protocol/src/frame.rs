use crate::{MessageType, ProtocolError, WireMessage};

pub const FRAME_MAGIC: [u8; 4] = *b"SKVM";
pub const PROTOCOL_VERSION: u16 = 1;
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
    /// magic, advertises an unsupported version or message type, or declares a
    /// payload larger than [`MAX_FRAME_PAYLOAD`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
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
        if protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                received: protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }

        let message_type = MessageType::try_from(u16::from_be_bytes([bytes[6], bytes[7]]))?;
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
}

/// Validates and serializes a message into one complete v1 frame.
///
/// # Errors
///
/// Returns [`ProtocolError`] if the message is invalid, cannot be serialized,
/// or exceeds the protocol payload limit.
pub fn encode_frame(message: &WireMessage) -> Result<Vec<u8>, ProtocolError> {
    message.validate()?;
    let message_type = message.message_type();
    let payload = message
        .encode_payload()
        .map_err(|error| ProtocolError::Encode {
            message_type,
            detail: error.to_string(),
        })?;
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge {
            length: payload.len(),
            maximum: MAX_FRAME_PAYLOAD,
        });
    }

    let payload_length =
        u32::try_from(payload.len()).map_err(|_| ProtocolError::PayloadTooLarge {
            length: payload.len(),
            maximum: MAX_FRAME_PAYLOAD,
        })?;
    let header = FrameHeader {
        protocol_version: PROTOCOL_VERSION,
        message_type,
        payload_length,
    };
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&payload);
    Ok(frame)
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
    let header = FrameHeader::decode(frame)?;
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
