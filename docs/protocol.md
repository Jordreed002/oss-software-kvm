# Protocol

The peer protocol is explicitly versioned and uses length-delimited frames. Wire data is defined
inside `kvm-protocol`; internal Rust domain structs are not serialized as an accidental public
contract.

Version one has logical control, input, clipboard, and diagnostics channels. They may initially
share an encrypted connection, but input scheduling is independent and higher priority. A later
transport may split physical connections without changing message semantics.

Keyboard and pointer-button messages carry monotonically increasing sequence numbers and remain
ordered. Pointer movement can be coalesced only where it cannot cross a button or transition
boundary. Every frame is size-limited and rejected before allocation if its version, kind, or
length is invalid.

Cross-host pointer handoff uses a transition identifier, workspace epoch, source display,
destination display, and normalized edge position. The receiving host acknowledges acceptance;
stale transitions cannot take workspace authority.

## UDP pointer fast path

Alongside the TLS stream, peers that negotiated the pointer-datagram protocol version exchange
encrypted UDP datagrams on port 24802 for latency-sensitive input. Every datagram carries a
13-byte header: the magic `SKVU`, a one-byte format version, and a big-endian 64-bit outer
sequence number. The remainder is a ChaCha20-Poly1305 ciphertext (16-byte tag appended) over a
payload that begins with a one-byte kind:

- kind 0 (probe): readiness check that arms the path in both directions.
- kind 1 (pointer): 42-byte payload of a one-byte flags field, 16-byte device id, 64-bit
  timestamp, and two 64-bit cumulative pointer totals (IEEE-754 bits, big endian).
- kind 2 (feedback): loss feedback; the sender temporarily adds redundant transmissions.
- kind 3 (reliable): a speculative ordered copy of a stateful input frame, prefixed by its own
  64-bit reliable sequence; the TLS stream remains the authoritative fallback.
- kind 4 (reliable-ack): cumulative acknowledgement of the reliable sequence.

Keys are direction-specific: each side derives its send key and the peer's receive key from the
session id and the sending host id, so only one key ever encrypts and nonce reuse across
directions is impossible. The outer sequence number doubles as the nonce input and an
anti-replay window: datagrams whose outer sequence is not strictly greater than the highest
previously accepted one are discarded.

The pointer totals are cumulative per device, so a lost datagram is recovered by the next one
that arrives. Bit 0 of the pointer flags byte is a *rebase* marker: when a sender's cumulative
totals exceed 2^40 in magnitude — the point where f64 addition risks losing pixel-scale
addends — the sender resets its per-device state to zero and transmits totals relative to that
fresh origin. A receiver that sees the rebase bit ignores its stored baseline, emits a move
equal to the transmitted totals, and stores them as the new baseline, restarting accumulation
at full precision.

Reliable-sequenced datagrams may reorder within a bounded window of 128 pending entries.
A reliable sequence further ahead than the window is dropped rather than buffered, since the
entries before it might never arrive to drain it.

Error policy on receive is drop-not-teardown: malformed headers, failed authentication,
replayed outer sequences, non-finite pointer totals, unknown devices beyond the tracking
budget, and reliable frames outside the reorder window are all silently discarded so a single
bad datagram never kills the fast path for the session. Only local socket failures tear the
path down, after which input falls back to the TLS stream.
