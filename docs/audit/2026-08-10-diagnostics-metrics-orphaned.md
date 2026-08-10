# Audit: §35/§36 input-pipeline diagnostics are collected-in-isolation but orphaned

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 15
**Spec refs:** `.spec/implementation.md` §35 (Diagnostics), §36 (Performance Instrumentation)
**Severity:** Medium-High for §36 — input latency is the headline software-KVM quality metric and is currently unobservable at runtime despite a collector existing.

## Finding

Spec §35 lists ten diagnostics to expose, and §36 requires five-stage event
timestamping to derive **capture → injection latency**. Mapping each §35/§36
item to the code:

| §35 / §36 item | Status | Where |
|---|---|---|
| connection state | ✅ collected | `PeerHealth.state`; `ManagerDiagnosticSnapshot` (`active.rs:679`) emits routing/handoff/authority |
| round-trip latency | ✅ collected | `PeerHealth.last_rtt` (`heartbeat.rs:240`, from ping reply) |
| peer uptime / last reconnect | ✅ derivable | `PeerHealth.connected_at` (`heartbeat.rs:19`) |
| protocol version | ✅ collected | negotiated in `peer.rs`, stored on peer state |
| active host / active display | ✅ collected | `workspace.active_host` / display topology |
| **input event rate** | ❌ **orphaned** | `EventRateMeter` exists (cycle 10) but **0 instantiations** outside kvm-input |
| **capture → injection latency (§36)** | ❌ **orphaned** | `LatencyStamps`/`LatencyHistory` exist (cycle 8) but **0 stamp call sites** |
| dropped packets | ❌ absent | no drop counter anywhere (`EnqueueError` is returned, never counted) |
| audio buffer health | ⚠️ N/A | audio crate absent (optional per spec) |

The two gaps that matter most are both **input-pipeline performance metrics**,
and both are the same defect shape: the collector module was built (and made
wire-serializable in cycle 14) but is **never wired in**.

### The orphaned collectors

`EventRateMeter` (§35 input event rate) and `LatencyStamps`/`LatencyHistory`
(§36 capture→injection latency) are referenced **nowhere outside `kvm-input`**:

```text
$ grep -rn "EventRateMeter\|LatencyHistory" crates/ --include=*.rs | grep -v "kvm-input/"
( no matches )
```

And **no crate in the workspace enables the `latency` or `event-rate` Cargo
features** — so even if a call site existed, the code would not compile in:

```text
$ grep -rn 'latency\|event-rate' crates/*/Cargo.toml   # only kvm-input's own feature defs
```

Concretely:
- The five §36 stages (`Capture`, `RoutingDecision`, `NetworkSend`,
  `NetworkReceive`, `InjectionRequest`) have **no `LatencyStamps::record` call
  sites** on the capture, routing, network-send, network-receive, or injection
  paths. The headline metric — capture→injection latency — is therefore
  **uncomputable at runtime**, even though `LatencyHistory::stats()` would
  produce p50/p95/min/max/mean were it fed.
- `EventRateMeter::record` has no caller on the capture path, so §35 "input
  event rate" is never measured.

### No unified §35 surface

There are two existing diagnostics consumers, neither of which is the §35
unified surface:

1. **`ManagerDiagnosticSnapshot`** (`active.rs:679`) — connection/routing/
   handoff/authority health. Published as a `developer_event` log line and to
   the UI status publisher. Covers ~"connection state" + "active host" only; it
   does not aggregate the performance metrics.
2. **`kvm-diagnostics` CLI** (`crates/kvm-diagnostics`) — the §39 read-only
   physical-host **observation/validation** runner (`probe`/`devices`/`displays`/
   `observe`). It formats *raw captured events* (classification, category,
   sequence, timestamp), privacy-redacted by default. It is event-level
   validation, not aggregate metrics.

So even the §35 items that *are* collected (RTT, connection state, uptime) are
not gathered into one structured snapshot matching the spec's ten-item list, and
the input-pipeline metrics are not gathered at all.

## Why this matters (industry baseline, web-verified)

Input latency is **the** defining quality metric for KVM products. PiKVM
dedicates a documentation page to it ("Latency defines how responsive a
KVM-over-IP device feels … less than 30ms feels nearly instantaneous"); every
hardware KVM switch and KVM-over-IP product is reviewed against input lag; mouse
sensitivity/throughput irregularity is a top user complaint. For a *software*
KVM where the capture→injection path is the entire value proposition, not being
able to measure that latency in dev builds is the single largest observability
gap relative to the spec. Event rate is the natural companion diagnostic (input
storms, capture-backend stalls).

## Recommended fix (improvement cycles)

1. **Wire §36 stamps onto the input path** (dev-only, behind the existing
   `latency` feature): stamp `Capture` at capture, `RoutingDecision` after the
   router, `NetworkSend` at queue push, `NetworkReceive` on decode,
   `InjectionRequest` at the injector. Feed complete stamps into a process-level
   `LatencyHistory`. This is the cycle-8 "deliberately later" step.
2. **Wire `EventRateMeter::record`** into the capture path (reusing the capture
   `timestamp_ns`, so no extra clock read — already designed for this).
3. **Add a dropped-packets counter** at the `OutboundQueue::try_push` →
   `EnqueueError` boundary (§35 "dropped packets").
4. **Introduce a unified `DiagnosticsSnapshot`** that assembles the §35 ten-item
   list from `PeerHealth` + `ManagerDiagnosticSnapshot` + the now-serializable
   `LatencyStats`/`EventRateSnapshot` + the new drop counter. This becomes the
   payload for the control-panel Diagnostics page (§32) once IPC transport lands.

Steps 1–3 are each self-contained and feature-gated (zero release cost); step 4
is the aggregation that turns the collected pieces into the spec's surface.

## Non-goals for this audit

Did not modify code. Documented finding with a verified per-item §35/§36 coverage
map; the wiring is deferred to improvement cycles. (Confirmed along the way that
`failsafe routing_suspend_seconds` is fully enforced — config ≥1s gate,
`activate_failsafe` consumption, routing `suspended_until_ns` check — and that
RTT/uptime/reconnect are collected at the heartbeat layer.)
