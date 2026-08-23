# Performance budget

Latency targets per input-pipeline stage. This document defines the budget and
its measurement method; **hardware validation fills in the numbers**. Every
target below is `TBD` until a physical two-host run produces a measured value —
platform-neutral CI cannot measure input latency.

## Stages

The stages are the five §36 instrumentation stages
(`.spec/implementation.md` §36, see the
[audit entry](audit/2026-08-10-latency-network-subspans-unmeasured.md) for the
current instrumentation state):

| # | Stage | Informal name | Budget (target) | Measured | Notes |
| - | ----- | ------------- | --------------- | -------- | ----- |
| 1 | Physical capture → classification | capture/classify | TBD | — | Native callback to classified, shared-representation event; stamp is `event.timestamp_ns`. |
| 2 | Classification → routing decision → enqueue | enqueue | TBD | — | Includes the authoritative synchronous routing decision and bounded-FIFO enqueue (`with_routing_decision`). |
| 3 | Enqueue → network send | wire (send) | TBD | — | Stamped source-side at the dispatch boundary (`with_network_send`). |
| 4 | Network send → network receive (transit) | wire (in flight) | TBD | — | Cross-host span; requires source stamps to cross the wire plus clock alignment. Deliberately deferred (see audit entry). |
| 5 | Network receive → decode → injection request | decode/inject | TBD | — | Destination-side receive and injection request are near-coincident in the same handler (`with_injection_request`). |
| — | **End to end: capture → injection** | headline | TBD | — | The §36 headline; decomposable into 1–5 once the numbers exist. |

## Measurement method

Measurements come from the diagnostics envelope — the `LatencyStamps` /
`DiagnosticsSnapshot` instrumentation behind the `kvm-daemon/diagnostics`
feature (§35/§36), surfaced through the control panel's diagnostics dashboard
and its JSON export. Record:

- The two-host arrangement (wired Ethernet vs. Wi-Fi), display configuration,
  and pointer event rate (the transport paces pointer input at 240 Hz, reducing
  to 125 Hz under authenticated gap feedback — see
  [ADR 0002](adr/0002-transport-latency-hardening.md)).
- Percentiles (p50/p95/p99), not just means; Wi-Fi jitter is the tail, not the
  average.
- The transport state for each run (UDP active vs. TCP fallback), since the
  wire stages differ substantially between them.

## Filling in the numbers

When a physical validation run produces measured values, replace the `TBD`
targets with budgets the measured hardware actually meets, note the validation
entry that justifies each number, and treat any later measurement exceeding the
budget as a regression. Budgets are per-stage so a regression can be attributed
to source processing, transit, or destination processing instead of only the
headline — which is the entire point of the five-stage model.
