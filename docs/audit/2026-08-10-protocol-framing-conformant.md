# Audit: §18 Protocol Framing — CONFORMANT (frame-bounds DoS hardening)

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 29
**Spec ref:** `.spec/implementation.md` §18 (Protocol Framing)
**Severity:** N/A — conformance confirmation. Cycle 3 verified version negotiation;
this cycle verifies the frame-length-bounds hardening that prevents unbounded
allocation DoS — the other security-critical half of any length-prefixed wire
protocol.

## What the spec requires

An explicitly versioned wire protocol with `FrameHeader { protocol_version: u16,
message_type, payload_length: u32 }`, where protocol structs are independently
versionable and not auto-serialized internal structs. `payload_length` is a `u32`
— up to ~4 GiB — so the implementation must cap it before allocating, or a peer
(a hostile paired peer, or a MITM pre-auth) can advertise an enormous length and
exhaust receiver memory.

## Implementation evidence (defense-in-depth)

`kvm-protocol/src/frame.rs` + `kvm-protocol/src/error.rs`:

- **`MAX_FRAME_PAYLOAD = 1024 * 1024`** (`:18`) — a hard 1 MiB cap.
- **Decode-time rejection (before allocation)** — `FrameHeader::decode_for_version`
  (`:98`): `if payload_length as usize > MAX_FRAME_PAYLOAD { return
  Err(ProtocolError::PayloadTooLarge { length, maximum }) }`. This is the load-
  bearing guard: it runs inside `read_message` (`codec.rs:99`) **before**
  `Vec::with_capacity(FRAME_HEADER_LEN + payload_length)` (`codec.rs:102`), so an
  oversized advertised length is rejected with no large allocation.
- **Encode-time rejection** — `encode_frame` (`:162`) refuses to emit a payload
  larger than `MAX_FRAME_PAYLOAD`, capping the outbound side too.
- **`u32` overflow guard** (`:170`) — `u32::try_from(payload.len())` prevents
  encoding a length that does not fit in the `u32` header field.
- **Version enforcement** — `decode_for_version` requires the header's
  `protocol_version` to match the connection's negotiated version (the cycle-3
  finding: clean `NoCompatibleProtocolVersion` rejection), so a version-mismatched
  frame is rejected before its payload is read.

The independent **control-plane protocol** (cycle 4) carries its own analogous
bound: `MAX_CONTROL_FRAME_BYTES` with `ControlCodecError::Oversized`
(`kvm-protocol/src/control.rs:205-230`), enforced on both encode and decode.

Within payloads, individual fields carry their own bounds
(`kvm-protocol/src/wire.rs`): `MAX_HOST_NAME_BYTES`/`MAX_DEVICE_NAME_BYTES`/
`MAX_DISPLAY_NAME_BYTES = 255`, `MAX_CLIPBOARD_TEXT_BYTES = 256 KiB`,
`MAX_AUTH_BYTES = 4096`, `MAX_SNAPSHOT_ITEMS = 256`. So a frame that passes the
1 MiB outer cap is still field-validated on decode (defense-in-depth, matching
the §27 clipboard size protection confirmed in earlier cycles).

## Why the cap matters here

This is an authenticated-stream protocol, but the threat is not only post-auth:
the frame reader runs over the TLS stream and allocates from the advertised
length **before** the message is fully decoded and authorized. Without the cap,
a peer could trigger a multi-gigabyte allocation per frame. With the 1 MiB cap,
the worst-case per-frame allocation is bounded regardless of what the peer
advertises. KVM input/display/clipboard messages are all small (the largest
legitimate payload is a clipboard text bounded to 256 KiB), so 1 MiB leaves
generous headroom while staying far below a dangerous allocation.

## Web verification (current best practice)

Capping inbound message size to prevent memory-exhaustion DoS is established best
practice for every length-prefixed protocol: gRPC ships a default
`maxInboundMessageSize` of **4 MiB** explicitly "to protect the receiver from
going out of memory if a malicious peer sends a very large payload"; MQTT and
WebSocket frame limits serve the same purpose. The codebase's stricter 1 MiB cap
is appropriate for a KVM control/input protocol whose messages are tiny. The
principle — reject an oversized advertised length *before* allocating — is
exactly what `decode_for_version` does.

## Non-goals

Did not modify code. §18 is conformant and well-hardened. Did not exhaustively
re-derive every per-field bound (the headline frame cap and the clipboard/auth/
snapshot bounds are verified; the display-dimension/scale bounds
(`MAX_DISPLAY_*`) are present and validated but were not individually
stress-tested this cycle).
