# Transport latency hardening

This stage keeps protocol-v3 compatibility while applying ten latency controls
to the authenticated LAN transport. Older peers ignore the new encrypted UDP
packet kinds and continue over TLS.

1. Diagnostics clients reuse a persistent, bounded, low-priority TCP session.
2. UDP telemetry records authenticated sequence gaps, current inter-arrival
   jitter, maximum silence, and recovered movement distance.
3. Pointer input is cumulative and paced at 240 Hz. Faster samples coalesce
   into the next datagram instead of building a queue.
4. Non-pointer input is sent as an ordered, acknowledged UDP shadow with 8 ms
   bounded retransmission. The identical TLS frame remains the final fallback;
   the daemon ignores only exact recent duplicates and still fails closed on an
   unknown stale sequence.
5. UDP sockets use bounded buffers and request DSCP expedited forwarding, which
   maps to a low-latency WMM access category where supported.
6. Diagnostics serving runs on dedicated bounded threads and never shares the
   input session's Tokio task.
7. Authenticated gap feedback temporarily reduces pointer frequency to 125 Hz
   and enables eight packets of selective redundancy.
8. A recovered movement larger than eight logical units is divided across four
   2 ms injections, limiting the visible post-stall jump to 6 ms of catch-up.
9. All new paths are bounded: 64 pointer devices, 128 reliable records, a
   32-event recovery queue, four retransmissions, eight diagnostics clients,
   and 1200-byte datagrams.
10. The dashboard exposes fast-path state, TX/RX, gaps, jitter, maximum silence,
    recovery distance, reliable traffic, and retransmissions.

Release and cleanup proofs remain on ordered TLS. This deliberately preserves
the existing fail-open ownership guarantee while the UDP shadow accelerates
ordinary keys, buttons, and scrolling. A real radio outage cannot be hidden;
these controls prevent local buffering and TCP recovery from extending it.
