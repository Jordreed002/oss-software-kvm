//! Fuzzes the pointer-datagram plaintext parser with arbitrary input.
//!
//! `parse_pointer_datagram_plaintext` runs post-decryption on untrusted
//! bytes: it must never panic and must round-trip any pointer payload it
//! accepts back through `encode_pointer_plaintext` bit-exactly (the two
//! sides share one wire format). The parse of a `KIND_RELIABLE` body also
//! exercises `kvm_protocol` frame decoding on arbitrary trailing bytes.

#![no_main]

use kvm_network::{
    encode_pointer_plaintext, parse_pointer_datagram_plaintext, PointerDatagramPlaintext,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = parse_pointer_datagram_plaintext(data);
    if let PointerDatagramPlaintext::Pointer {
        flags,
        device,
        timestamp_ns,
        total_x,
        total_y,
    } = &parsed
    {
        // Accepted pointer payloads must survive an encode/parse round-trip
        // unchanged; a mismatch means the encode and decode sides of the
        // shared layout have drifted.
        let encoded =
            encode_pointer_plaintext(*flags, *device, *timestamp_ns, (*total_x, *total_y));
        assert_eq!(parse_pointer_datagram_plaintext(&encoded), parsed);
    }
});
