//! Explicitly versioned wire protocol for Software KVM.
//!
//! Types in this crate are transport DTOs, not the application's domain
//! model. Callers must deliberately translate to and from `kvm-types` and
//! `kvm-input`; this keeps the public wire format independently versionable.

mod error;
mod frame;
mod message;
mod wire;

pub use error::{ProtocolError, ValidationError};
pub use frame::{
    decode_frame, encode_frame, FrameHeader, FRAME_HEADER_LEN, FRAME_MAGIC, MAX_FRAME_PAYLOAD,
    PROTOCOL_VERSION,
};
pub use message::{MessageType, WireMessage};
pub use wire::*;
