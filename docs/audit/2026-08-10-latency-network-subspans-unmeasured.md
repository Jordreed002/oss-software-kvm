# Audit: §36 Performance Instrumentation — network sub-spans unmeasured

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 35
**Spec ref:** `.spec/implementation.md` §36 (Performance Instrumentation)
**Severity:** Medium — the headline metric works; its *decomposition* does not.

## What the spec requires (§36, implementation.md:1244-1262)

Timestamp events at **all five** stages:

```text
physical capture
routing decision
network send
network receive
injection request
```

and create development-only tracing that can calculate the headline:

```text
capture → injection latency
```

No disk I/O on the real-time path.

The five stages exist precisely so the headline can be **decomposed** — when
end-to-end latency regresses, you need to know whether the cost is source-side
processing, network transit, or destination-side processing. A single
capture→injection number cannot answer that.

## What is live

`kvm-input::LatencyStamps` supports all five stages (`instrumentation.rs:26`,
`with_network_send`/`with_network_receive` builders at `:140`/`:146`, and
`span_ns` can compute any sub-span — its own test exercises the full 5-stage
picture including the `NetworkSend → NetworkReceive` transit span at
`:356`/`:480-492`).

But on the **live daemon hot path** only three stages are ever stamped:

| Stage            | Stamped at                                  | Cycle   |
|------------------|---------------------------------------------|---------|
| Capture          | `event.timestamp_ns` (reused, no extra read)| 20/26   |
| RoutingDecision  | `core.rs:1093` `.with_routing_decision(now_ns)` | 26   |
| NetworkSend      | —                                           | **gap** |
| NetworkReceive   | —                                           | **gap** |
| InjectionRequest | `session.rs:1291` `.with_injection_request(now_ns)` | 20 |

`with_network_send` and `with_network_receive` have **zero call sites outside
the `kvm-input` test module** (grep across the workspace confirms: the only
hits are the type definition and its own unit tests). So while the type can
express the transit sub-span, nothing feeds it at runtime.

Consequence: capture→injection is computable (cycle 20) but it is a **black
box**. A 40 ms headline could be 2 ms source processing + 38 ms network, or
38 ms source processing + 2 ms network — both are indistinguishable today.

## Why the gap is partial, not total — the two-host reality

A single event's five-stage journey spans **two hosts**:

- **Source host** stamps Capture, RoutingDecision, NetworkSend — all local,
  one clock, no wire change needed.
- The frame crosses the network.
- **Destination host** stamps NetworkReceive, InjectionRequest — all local.

This produces two architectural facts that bound what is *locally* measurable
without a wire-protocol change:

1. **NetworkSend is stampable source-side with no wire change.** The send
   boundary is `dispatch_remote_effect` (`session.rs:1532` —
   `outbound.try_send(WireMessage::Input(input))`), reached from
   `route_captured` (`session.rs:777`) which already has `now_ns` in scope.
   Stamping there decomposes the **source host's** processing latency into
   `capture→routing` (cycle 26 ✅) + `routing→send` (the missing piece). High
   local value, fully feasible.

2. **NetworkReceive is ~coincident with InjectionRequest locally.** On the
   destination host both happen inside the one `inject_received` handler
   (`session.rs:1234`) that has a single `now_ns`; the local
   `receive→inject` span is therefore near-zero. It only gains meaning for the
   *cross-host transit* span (`NetworkSend → NetworkReceive`), and that
   requires the source-side stamps to travel with the frame across the wire
   plus cross-clock alignment — a wire-protocol change that is out of scope for
   "development-only tracing" and that cycle-20's dest-side capture→injection
   already glosses over (it compares the source's capture clock against the
   dest's inject clock, implicitly assuming synchronized clocks).

## Web verification

Decomposing latency into **processing delay vs network/transit delay** is the
standard model for distributed systems instrumentation (ScienceDirect's
"Network Latency" overview explicitly separates *processing delay* — "the time
taken in [intermediate processing]" — from transit delay). Remote-desktop /
software-KVM tooling that reports a single end-to-end number is routinely
criticized for hiding *where* the latency lives; the value of §36's five-stage
model is precisely the decomposition. So the gap is real against both the spec
and best practice — not a cosmetic completeness check.

## Recommendation (cycle 36 IMPROVE target)

**Stamp `NetworkSend` source-side at the dispatch boundary** — the one
intermediate stage that is both feasible without a wire change and genuinely
informative. This closes 4 of the 5 §36 stages on the source host
(Capture → RoutingDecision → NetworkSend) and lets a diagnostics surface
attribute source-side processing latency separately from the rest.

`NetworkReceive` should be **documented as deliberately deferred**: locally
near-zero (same handler as InjectionRequest), and its only meaningful span
(cross-host transit) requires the source stamps to cross the wire plus clock
sync — a wire-protocol decision that belongs to the §17/§26/§31 transport
work, not to dev-only instrumentation. The cycle-20 dest-side capture→injection
metric remains the headline.

## Non-goals

Did not modify code this cycle (AUDIT). The improvement lands in cycle 36.
Did not re-audit the already-stamped stages (cycles 20/26 confirmed correct).
