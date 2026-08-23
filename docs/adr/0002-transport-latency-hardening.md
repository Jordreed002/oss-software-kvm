# ADR 0002: Transport latency hardening (transport v4)

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

Real two-host sessions run over Wi-Fi, where radio outages and jitter interact
badly with both the TCP fallback and the new v3 UDP fast path: local buffering,
queueing, and retransmission storms could extend a short radio stall into a
long visible freeze, and nothing measured the loss, reorder, and jitter the
path was actually experiencing.

## Decision

Keep protocol-v3 compatibility and apply bounded latency controls to the
authenticated LAN transport: pace cumulative pointer input at 240 Hz with
coalescing instead of queueing; carry non-pointer input as an ordered,
acknowledged UDP shadow with 8 ms bounded retransmission while the identical
TLS frame remains the final fallback; request DSCP expedited forwarding; run
diagnostics on dedicated bounded threads and a persistent low-priority session;
and expose gap/jitter/silence/recovery telemetry plus adaptive frequency
reduction (240 Hz → 125 Hz with selective redundancy) on authenticated gap
feedback. All new paths are explicitly bounded.

## Consequences

Ordinary keys, buttons, and scrolling gain most of the fast path's benefit
without weakening the fail-open ownership guarantee, and a real radio outage
becomes measurable instead of hidden by local recovery. Release and cleanup
proofs deliberately remain on ordered TLS. The ten controls, their bounds, and
the dashboard surface are specified in
[transport latency hardening](../transport-v4-latency-hardening.md); this record
exists to make the decision discoverable from the ADR index.
