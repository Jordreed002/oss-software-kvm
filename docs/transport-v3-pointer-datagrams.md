# Transport v3: low-latency pointer datagrams

Protocol v3 adds an optional UDP fast path for replaceable pointer movement.
The authenticated TLS/TCP session remains authoritative and continues to carry
pairing, admission, keys, buttons, scrolling, ownership transitions, releases,
inventory, clipboard, heartbeat, and fallback pointer traffic.

## Security and activation

- Both peers advertise protocol v3 in the TLS-exporter-bound admission exchange.
- Each host binds UDP port 24802 on the same physical address as the TCP session.
- Directional ChaCha20-Poly1305 keys are derived from the unique TLS exporter
  session identifier and the sending host identifier.
- Datagrams have a monotonically increasing authenticated sequence number.
  Replayed and reordered older pointer updates are discarded.
- Each endpoint sends encrypted probes. Pointer traffic moves to UDP only after
  an authenticated probe arrives from the peer.
- Bind, probe, authentication, or socket failure disables the fast path and
  returns pointer movement to TLS/TCP without affecting critical traffic.
- Datagram size is capped at 1200 bytes to avoid IP fragmentation.

## Delivery semantics

Pointer movement uses bounded, per-device cumulative totals. A newly received
packet is converted back to a relative delta from the last accepted total, so
the next packet recovers motion from a lost packet. The datagram sequence is
separate from the reliable input sequence, preventing UDP/TCP reordering from
making a valid key or button event appear stale. Critical state remains
reliable and ordered on TLS/TCP. This removes TCP head-of-line blocking from
the high-rate pointer lane without weakening release and ownership guarantees.

## Diagnostics

The live network report exposes whether probing activated the fast path and the
cumulative pointer datagrams sent and received. The control panel shows
`UDP ACTIVE` or `TCP FALLBACK` independently for each host.

## Follow-up stages

1. Measure datagram loss, reorder depth, jitter, and fallback causes on physical
   Windows/macOS hosts.
2. Add bounded redundancy and acknowledgements for selected critical events
   only if measurements show a benefit; never move release semantics without a
   proven reconciliation path.
3. Add packet pacing and path-MTU discovery if traffic grows beyond pointer
   movement.
4. Evaluate QUIC datagrams only after comparing their scheduling and binary
   footprint against this narrow fast path.
