# ADR 0001: UDP pointer datagram fast path (transport v3)

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

Protocol v2 carried all input, including replaceable pointer movement, over the
authenticated TLS/TCP session. TCP head-of-line blocking on the single
high-rate pointer lane added latency and jitter whenever any other frame (keys,
buttons, inventory, clipboard, heartbeat) needed retransmission, which is the
wrong trade for a data stream where each new sample supersedes the last.

## Decision

Protocol v3 adds an optional UDP fast path for replaceable pointer movement on
port 24802, activated only after both peers agree in the exporter-bound
admission exchange and authenticated probes succeed in both directions. Keys are
directional ChaCha20-Poly1305 derived from the TLS exporter; datagrams carry
monotonic authenticated sequence numbers with anti-replay; and any bind, probe,
or socket failure returns pointer traffic to TLS/TCP, which stays authoritative
for ordered, release, and ownership traffic.

## Consequences

Pointer latency is no longer coupled to TCP recovery, while every safety-critical
guarantee remains on the reliable path. Loss and reorder of pointer datagrams
are tolerated by cumulative-totals semantics instead of reliability machinery.
The full design, security rationale, and diagnostics surface are documented in
[transport v3: low-latency pointer datagrams](../transport-v3-pointer-datagrams.md);
this record exists to make the decision discoverable from the ADR index.
