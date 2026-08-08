use crate::MessageType;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("frame is shorter than its {expected}-byte header (got {actual} bytes)")]
    HeaderTruncated { expected: usize, actual: usize },

    #[error("invalid frame magic {0:?}")]
    InvalidMagic([u8; 4]),

    #[error("unsupported protocol version {received}; this implementation accepts {supported}")]
    UnsupportedVersion { received: u16, supported: u16 },

    #[error("{message_type:?} is unavailable in protocol version {version}")]
    MessageVersionMismatch {
        message_type: MessageType,
        version: u16,
    },

    #[error("unknown message type {0}")]
    UnknownMessageType(u16),

    #[error("payload length {length} exceeds the {maximum}-byte limit")]
    PayloadTooLarge { length: usize, maximum: usize },

    #[error("frame payload is truncated: declared {declared} bytes, available {available}")]
    PayloadTruncated { declared: usize, available: usize },

    #[error("frame contains {0} trailing bytes")]
    TrailingBytes(usize),

    #[error("could not encode {message_type:?}: {detail}")]
    Encode {
        message_type: MessageType,
        detail: String,
    },

    #[error("could not decode {message_type:?}: {detail}")]
    Decode {
        message_type: MessageType,
        detail: String,
    },

    #[error(transparent)]
    InvalidMessage(#[from] ValidationError),
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid {message_type:?} message: {detail}")]
pub struct ValidationError {
    pub message_type: MessageType,
    pub detail: String,
}

impl ValidationError {
    pub(crate) fn new(message_type: MessageType, detail: impl Into<String>) -> Self {
        Self {
            message_type,
            detail: detail.into(),
        }
    }
}
