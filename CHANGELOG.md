# Changelog

All notable changes to OSS Software KVM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). No releases
have been tagged yet; everything below is unreleased. Entries start at the two-host alpha
era — the full earlier history remains in the git log.

## [Unreleased]

### Added

- Authenticated low-latency UDP pointer transport (protocol v3): exporter-keyed,
  sequence-numbered pointer datagrams on UDP port 24802 with probe-gated activation and
  automatic fallback to TLS/TCP, which remains authoritative for ordered traffic
  ([transport v3](docs/transport-v3-pointer-datagrams.md)).
- Transport latency hardening (protocol v4): 240 Hz paced cumulative pointer input, an
  ordered acknowledged UDP shadow with 8 ms bounded retransmission, DSCP expedited
  forwarding, gap/jitter/silence telemetry, and bounded recovery injection
  ([transport v4](docs/transport-v4-latency-hardening.md)).
- Live diagnostics monitoring dashboard in the control panel: real-time charts with hover
  tooltips, sortable capture-counter and network-activity tables, an input-routing-split
  composition bar, outbound drop-rate health gauge, per-host drop-rate sparkline, and
  pause/resume, manual refresh, and JSON export controls.
- Live session network telemetry: a separate-channel diagnostics transport, a live report
  published from `kvm-runtime` and exposed to the control panel, and a capture-metric
  envelope (§35/§36).
- §36 latency instrumentation: capture→injection latency at the inject site, source-side
  capture→routing and network-send sub-spans, an injected-events counter at the destination
  inject site, and a dev-only input-event-rate meter, composed into a unified
  `DiagnosticsSnapshot` behind the `kvm-daemon/diagnostics` feature.
- Mutual-consent LAN pairing with nearby-machine discovery in the control panel, including
  stale-pairing replacement from the ready screen.
- A spec-conformance audit trail under `docs/audit/` and Windows physical validation
  entries under `docs/validation/windows/`.
- Process panic failsafe: a lock-free panic hook trips a flag the armed peer manager
  observes on every capture callback and service tick, releasing held input and gating
  suppression through the existing native-capture-discontinuity cleanup path.
- Routing-budget watchdog (default 50 ms), pressed-state reconciliation sweep, and a
  bounded failsafe audit trail recording every tripwire.
- Pairing failure lockout (5 attempts / 60 s cooldown, injectable clock) and a
  constant-time comparison audit across `kvm-security`.
- Discovery conflict detection: the same peer-ID advertised with differing address or
  port is excluded from scheduling and surfaced through
  `DiscoverySnapshot::conflicted()`.
- Per-origin clipboard rate limiting (default 16 updates/s, memory-capped across
  origins).
- Repository infrastructure: `CHANGELOG.md`, `SECURITY.md`, ADRs, performance-budget
  and validation-matrix docs, a `justfile`, dependabot, and CI jobs for the control
  panel, cargo-deny, MSRV (1.91), coverage, cargo-machete, and `cargo doc`.

### Fixed

- UDP pointer path resilience: corrupt or forged ciphertext, non-finite totals,
  receive-side device-capacity overruns, and far-future reliable sequences now drop the
  single packet instead of permanently downgrading the session to the TLS path; pointer
  totals rebase past 2^40 to protect f64 delta resolution (wire format gains a flags
  byte); datagram key material is zeroized on drop; IPv6 datagrams are marked for
  expedited forwarding; packet encoding no longer allocates per datagram; reconnect
  backoff gained optional ±25% jitter.
- Failsafe: the emergency chord now releases peer-injected inbound keys (§25/F-02), and
  failsafe routing suspension is enforced on all egress paths (§24).
- Pointer handoff across display edges: an edge dwell is required before handoff, dwell
  hysteresis keeps the return handoff alive through trackpad jitter, and edge tolerance and
  cursor inset were adjusted for reliable handoff.
- High-refresh input path: data-loss and O(n²) drain bugs, per-event latency for 175 Hz
  throughput, preservation of high-rate pointer updates, and cross-platform mouse and
  scroll stabilization.
- macOS backend: modifiers emit `kCGEventFlagsChanged` with cumulative flags, Quartz
  whole-host timestamps are converted to nanoseconds, Input Monitoring/Accessibility
  permissions are preflighted before IOHID capture, whole-host callbacks are bounded by a
  100 ms tap-dispatch watchdog, and remote pointer injection is smoothed.
- Security and robustness hardening from the audit pass: release-all-keys invariant gaps
  closed (F-01/F-02/F-03), native capture fails closed on drop (F-07), peer-reachable
  panics eliminated (F-12/F-13/F-25/F-32), discovery dial port pinned against SSRF (F-08),
  fail-closed routing on a nil workspace host (F-14), discovery broadcast hardening,
  pairing debug redaction, bounded LRU eviction for remote display inventory (F-05),
  graceful SIGTERM shutdown (F-06), and clipboard `Debug` redaction (F-11).

### Changed

- The realtime transport is hardened against Wi-Fi jitter: pointer input is paced and
  coalesced instead of queueing, non-pointer input rides an acknowledged UDP shadow with
  the identical TLS frame as final fallback, and diagnostics serving moved to dedicated
  bounded threads so it never shares the input session's task.
- Diagnostics capture refreshes on the transport tick without clobbering network metrics,
  correcting the live dashboard telemetry.
