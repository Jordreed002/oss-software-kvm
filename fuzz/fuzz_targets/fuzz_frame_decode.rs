//! Fuzzes `kvm_protocol::decode_frame_for_version` with arbitrary bytes and
//! an arbitrary "negotiated" version.
//!
//! The decoder must reject malformed input with an error for every version
//! (including unsupported ones); any panic, hang, or invariant violation is a
//! finding. The first two input bytes select the u16 version; the remainder
//! is the candidate frame.

#![no_main]

use kvm_protocol::{
    decode_frame_for_version, FrameHeader, CURRENT_PROTOCOL_VERSION, MIN_SUPPORTED_PROTOCOL_VERSION,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let derived_version = u16::from_be_bytes([data[0], data[1]]);
    let body = &data[2..];

    // Any u16 must be accepted as a *requested* version without panicking;
    // almost all are rejected as unsupported.
    let _ = decode_frame_for_version(body, derived_version);

    // Sweep the actually-supported range so the fuzzer explores the accepted
    // decoder paths (header, payload, message invariants) too.
    for version in MIN_SUPPORTED_PROTOCOL_VERSION..=CURRENT_PROTOCOL_VERSION {
        let _ = decode_frame_for_version(body, version);
        let _ = FrameHeader::decode_for_version(body, version);
    }
});
