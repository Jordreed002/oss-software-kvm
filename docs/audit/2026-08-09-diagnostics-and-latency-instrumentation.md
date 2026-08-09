# Audit: Diagnostics surface (§35) and capture→injection latency instrumentation (§36)

**Date:** 2026-08-09
**Cycle:** /loop audit cycle 7
**Spec refs:** `.spec/implementation.md` §35 (Diagnostics), §36 (Performance Instrumentation); `.spec/spec.md` §36
**Severity:** Medium — diagnostics *collection* is mostly present but unaggregated; **performance instrumentation (§36) is almost entirely absent**, and end-to-end latency is the single metric the software-KVM domain treats as make-or-break.

## Industry baseline (verified via web)

Input latency is the headline quality metric for software KVMs. Practitioners
state flatly that "a software KVM lives or dies by input latency" and publish
end-to-end capture→display numbers as the primary benchmark (PiKVM: "35–50 ms
total latency, from capture to displaying"; a Rust software KVM: "end-to-end
latency well under 1 ms on a wired LAN"). A project that can *measure*
capture→injection latency is therefore following domain best practice; one that
cannot is flying blind on exactly the number that matters most. Spec §36 asks
for precisely this capability (development-only tracing, no disk I/O on the
real-time path).

## §35 Diagnostics — what the spec wants exposed

```
connection state, round-trip latency, input event rate, dropped packets,
peer uptime, protocol version, active host, active display, last reconnect,
audio buffer health
```

### Collection status (per-metric)

| §35 metric | Collected? | Where / note |
|---|---|---|
| connection state | ✅ | `kvm_network::heartbeat::PeerHealth::state` (`PeerState`) |
| round-trip latency | ✅ | `PeerHealth::last_rtt` (heartbeat ping/pong, nonce-validated) |
| peer uptime | ✅ derivable | `PeerHealth::connected_at` (monotonic-clock origin) |
| last reconnect | ✅ derivable | from `connected_at` transitions |
| protocol version | ✅ | `kvm_protocol::PROTOCOL_VERSION` / negotiated version |
| active host / active display | ✅ | `WorkspaceState` (`kvm-router`) |
| dropped packets | ⚠️ piecemeal | `dropped_events: AtomicU64` in `kvm-network/src/listener.rs`, `kvm-windows/src/native.rs`, `kvm-macos`; no single aggregated counter |
| **input event rate** | ❌ **absent** | no event-rate / events-per-second counter anywhere |
| audio buffer health | N/A | no `kvm-audio` crate (optional per spec non-goals) |

**§35 finding:** the underlying metrics are *mostly* collected, scattered across
`kvm-network`, `kvm-router`, `kvm-windows`/`kvm-macos`, and `kvm-protocol`. Two
gaps: (1) **input event rate is not collected at all** — there is no
events-per-second counter on the capture or injection path; (2) there is **no
unified diagnostics aggregation surface** that joins these into one view. Gap
(2) is upstream-blocked on the daemon↔panel IPC transport (documented in cycle
3 / the cycle-5 conformance map) — without a control channel there is nowhere
to expose a unified view. Gap (1) (input event rate) is independent and could
be a small future improvement cycle.

## §36 Performance Instrumentation — what the spec wants

Timestamp events at five stages:

```
physical capture, routing decision, network send, network receive, injection request
```

…then "create development-only tracing that can calculate **capture → injection
latency**", with "do not perform disk I/O on the real-time input path."

### Status (per-stage)

| §36 stage | Recorded? | Where |
|---|---|---|
| physical capture | ✅ | `InputEvent::timestamp_ns` (set by Windows `started.elapsed().as_nanos()` and macOS `mach_timestamp_ns`) |
| routing decision | ❌ | — |
| network send | ❌ | — |
| network receive | ❌ | — |
| injection request | ❌ | — |
| **capture → injection latency** | ❌ | no stage-2..5 timestamps, so end-to-end latency is uncomputable |

**§36 finding:** performance instrumentation is **almost entirely unimplemented.**
Only the first stage (capture) is timestamped (`InputEvent::timestamp_ns`, which
the diagnostics CLI also prints as `source_timestamp_ns`). The other four stage
timestamps do not exist, so capture→injection latency — the headline metric the
domain uses to judge a software KVM — cannot be measured today. This is a clean,
self-contained gap that does **not** depend on the IPC transport: it is
development-only tracing inside the daemon/network/injection path.

Note the spec's two hard constraints for any future implementation:
- **Development-only** — gate behind a `feature` or runtime flag so it is off by
  default in release builds.
- **No disk I/O on the real-time input path** — stage timestamps must stay
  in-memory (e.g. a ring buffer sampled by the diagnostics surface), never a
  per-event file write.

## Evidence

```
# Only the capture stage is timestamped; no routing/send/recv/inject stage exists.
$ rg "timestamp_ns|injected_at|routing_decision|network_send|network_receive|e2e_latency|capture_to_inject" crates/
crates/kvm-input/src/event.rs:112      pub timestamp_ns: u64,        # ← capture time, the ONLY stage
crates/kvm-windows/src/native.rs:355   let timestamp_ns = ...elapsed().as_nanos()
crates/kvm-macos/src/capture.rs:339    fn mach_timestamp_ns(...)
# (no injection-request timestamp, no latency computation anywhere)

# Heartbeat exposes RTT + connected_at (peer uptime) — §35 round-trip + uptime ARE collected.
$ rg "last_rtt|connected_at" crates/kvm-network/src/heartbeat.rs
crates/kvm-network/src/heartbeat.rs:23     pub last_rtt: Option<Duration>
crates/kvm-network/src/heartbeat.rs:19     pub connected_at: Option<Duration>

# No event-rate counter exists.
$ rg "event_rate|events_per_second|eps|input_rate" crates/   # (no matches)
```

## Recommendation (for an upcoming IMPROVE cycle)

The highest-value, IPC-independent, low-risk slice is a **dev-only latency
probe** for §36:

1. Add an in-memory `LatencyProbe` / stage-timestamp type in `kvm-input` (or a
   small `kvm-instrumentation` module) carrying the five optional stage
   timestamps: `capture_ns`, `routed_ns`, `sent_ns`, `received_ns`,
   `injected_ns`, with a `capture_to_injection_ns()` accessor.
2. Gate it behind a `kvm-instrumentation/latency` Cargo feature (off by default;
   zero cost when off) so it is development-only and adds nothing to release
   input latency.
3. Wire stamps at the four missing call sites (router decision, network send,
   network receive, injector request) — all guarded by the feature so the hot
   path is untouched in release.
4. Keep a bounded in-memory ring buffer of recent latencies (e.g. last N events
   or a rolling p50/p95) that the diagnostics surface can read — **no disk I/O
   on the real-time path**, satisfying the spec constraint.

This delivers the §36 capability the domain treats as essential and leaves the
§35 *exposure* (unified surface) to be solved alongside the IPC transport.

## Non-goals for this audit

Did not modify code. Documented finding; implementation deferred to an
improvement cycle.
