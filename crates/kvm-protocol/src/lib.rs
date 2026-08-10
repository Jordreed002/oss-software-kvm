//! Explicitly versioned wire protocol for Software KVM.
//!
//! Types in this crate are transport DTOs, not the application's domain
//! model. Callers must deliberately translate to and from `kvm-types` and
//! `kvm-input`; this keeps the public wire format independently versionable.

mod control;
mod error;
mod frame;
mod message;
mod wire;

pub use control::*;
pub use error::{ProtocolError, ValidationError};
pub use frame::{
    decode_frame, decode_frame_for_version, encode_frame, encode_frame_for_version,
    is_supported_protocol_version, supports_release_proof, FrameHeader, CURRENT_PROTOCOL_VERSION,
    FRAME_HEADER_LEN, FRAME_MAGIC, MAX_FRAME_PAYLOAD, MIN_SUPPORTED_PROTOCOL_VERSION,
    PROTOCOL_VERSION, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2, RELEASE_PROOF_PROTOCOL_VERSION,
};
pub use message::{MessageType, WireMessage};
pub use wire::*;
