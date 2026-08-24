# Remediation loop — audit/fix cycle record

**Date started:** 2026-08-24
**Branch:** `code-review-remediation`
**Method:** independent audit subagents review recently-added and adjacent code →
prioritized findings → fix subagents (or direct fixes) → full verification →
commit → re-audit. Each cycle appends its findings and status here.

Legend: ✅ fixed · 🔧 fix in flight · ⏸ deferred (with reason) · ❌ audit finding open

## Cycle 1 (2026-08-24)

Auditors: runtime/panel/config, natives+protocol-v4, daemon-modules
(network/IPC auditor failed twice on API errors; re-running).

### Runtime / panel / config audit

| ID | Finding | Status |
|---|---|---|
| H1 | §31 status DTO serialized snake_case; panel read camelCase → DaemonStatusCard crashed the webview in production | ✅ `edec6af` |
| H2 | kvm-runtime binary (the one the panel spawns) never installed the panic failsafe hook | ✅ `edec6af` |
| H3 | Control-plane socket test unconditionally binds a Unix path → deterministic windows-CI failure | ✅ `edec6af` |
| M1 | CI never compiled/tested `apps/control-panel/src-tauri` | ✅ `d12c243` (panel-rust job, mac+win) |
| M2 | DaemonStatusCard had zero tests; mock fidelity masked H1 | ✅ `d12c243` (8 tests incl. regression) |
| L1 | `run_transport` discarded composed §31 display/topology seeds | ✅ `d12c243` |
| L2 | `uuidToBytes` failure conflated with "active host is peer" | ✅ `d12c243` |
| L3 | Card swallowed poll errors; duplicated daemon-link detail in peer row | ✅ `d12c243` |
| L4 | Inverted reply/payload type names | ✅ `d12c243` (DaemonStatus/DaemonStatusReply) |
| L5 | v3 migration silently switches existing users to functional mapping | ⏸ accepted (documented product decision; changelog covers it) |
| L6 | Docs job on floating `stable` → spurious rustdoc-lint breaks | ✅ `d12c243` (pinned to 1.91) |

### Natives / credential-store / protocol-v4 audit

| ID | Finding | Status |
|---|---|---|
| H-1 | Windows hotplug dereferenced unvalidated lParam from thread messages (forged PostThreadMessageW → wild read → daemon abort) | ✅ `7a13ef6` |
| M-1 | macOS CG display-callback teardown use-after-free window | ✅ `7a13ef6` (detached flag + bounded grace) |
| M-2 | FileCredentialStore accepted pre-existing dirs/temp files with unverified permissions | ✅ `7a13ef6` |
| L-1 | Double `DestroyWindow` after explicit teardown | ✅ `7a13ef6` |
| L-2 | Watcher startup-timeout detach could wedge process-global ownership forever | ✅ `7a13ef6` (generation-checked reclaim) |
| L-3 | `SecretBytes::new` empty-error path left bytes un-zeroized; file read reallocated | ✅ `7a13ef6` |
| L-4 | NumLock mapped as extended scan code — needs physical-hardware confirmation | ⏸ hardware validation list |
| — | Verified sound: modifier bijections, protocol-v4 triple version gating, chord teardown, cfg hygiene, CredFree/CFAutorelease discipline | — |

### Daemon-modules audit

| ID | Finding | Status |
|---|---|---|
| H1 | `selected_lifecycle_tick` error ordering starved the stuck-key sweep; stale comment claimed supervisor also sweeps | ✅ `2434316` |
| H2 | Zero tests for the manager-level failsafe interlock (watchdog/panic gate/reconcile) | ✅ `2434316` (9 discriminating tests) |
| H3 | `EnableKvm` silently no-ops after `TriggerFailsafe`; panel shows enabled | ✅ `2434316` (FailsafeLatched + control=kvm_enable_rejected) |
| M1 | Panic-failsafe one-shot skipped deeper cleanup on later observations | ✅ `2434316` |
| M2 | Semantic tracker could over-count (observe skipped on dangling pending_remote) | ✅ `2434316` |
| M3 | Control connection parked forever on broadcast Closed (task leak) | ✅ `2434316` |
| M4 | Watchdog remediation did sync file I/O inside the capture callback | ✅ `2434316` (queue + flush on service tick) |
| M5 | Failsafe audit JSONL sink never wired in production | ✅ `2434316` (SOFTWARE_KVM_DATA_DIR; panel sets it) |
| M6 | Inbound held state has no age-based sweep (only peer-liveness) | ⏸ cycle 2 (M/L effort) |
| L1-L4 | Unlogged TriggerFailsafe errors; poisoned test guard; unbounded panel-connection tasks; hot-path audit record | L1/L2 ✅ `2434316`; L3 ❌ open (cap concurrent panel connections); L4 ✅ via M4 |
| — | Verified sound: panic-hook lock-freedom, watchdog mechanics, semantic chord lifecycle bounds, control-service discipline, single-mutex concurrency | — |

### Network / IPC audit (cycle 1, completed late)

| ID | Finding | Status |
|---|---|---|
| H-1 | `ReliableReorderBuffer` wedges permanently: retransmissions of delivered-but-unacked sequences insert below-`next_sequence` entries that never drain; at capacity every later insert is dropped for the session's lifetime (masked by TLS fallback) | ✅ `16955e4` |
| H-2 | Adaptive pacing escalation (8/16 ms) never reaches the wire: `flush_pending` has no pacing gate, so the 4 ms tick pins effective cadence; only redundancy escalation is real | ✅ `16955e4` |
| M-1 | IPC socket 0600-after-bind umask window on Linux `/tmp` defaults; the umask mitigation the docs assume is performed nowhere | ❌ open (cycle 2) |
| M-2 | One transient accept error (EMFILE/ECONNABORTED/pipe-busy) permanently kills the control plane until restart | ✅ `16955e4` |
| M-3 | Blocking `UnixStream::connect` stale-probe on the async runtime can pin a Tokio worker when the live daemon's accept loop is saturated | ❌ open (cycle 2) |
| L-1 | `next_delay_with_jitter` is dead in production; docs claim otherwise | ❌ open (cycle 2) |
| L-2 | Client `connect` deadline arithmetic can panic on absurd timeouts; overshoots budget by up to one cadence | ✅ `16955e4` |
| L-3 | `shadow_reliable` counts a never-sent `WouldBlock` datagram as attempt 1 | ✅ `16955e4` |
| L-4 | Pacing comment describes a state healthy links can't reach | ✅ `16955e4` |
| — | Verified sound: framing bounds-before-alloc, accept/permit race, named-pipe rotation, stale-socket recovery, Zeroizing keys + directional nonces, pacing arithmetic, tooling-fn equivalence (benches/fuzz exercise production symbols) | — |

### Standing backlog (pre-audit, hardware-independent)

Layout-translation tables · semantic vocabulary expansion · lock-state sync ·
UnmatchedRepeat softening · held-key re-press on re-admission · §32-34 panel
runtime pages · deferred §31 commands (SetTopology/SetDeviceRoute/clipboard) ·
RTT population · cursor-signal items (flush-tick floor, SendInput batching,
CGEvent timestamps, jitter buffer, cursor re-sync, multi-device batching) ·
cert issuance/rotation (rcgen) · heartbeat cadence adaptation · listener
counters in dashboard · specta type-gen · eslint/prettier · a11y · QR pairing ·
wizard resume · Prometheus/OTLP export · fuzz-in-CI · release scaffolding ·
clipboard image types · README modifier-mapping section · PeerState::Discovering.

### Loop status

Cycle 1 complete (2026-08-24): all four audits delivered, every High fixed
(`edec6af`, `7a13ef6`, `d12c243`, `2434316`, `16955e4`); 35 commits on the
branch; workspace clippy clean (pedantic + diagnostics), 859+ tests plus 63
panel tests green (only the documented macOS-firewall listener flake varies).

Open for cycle 2: network M-1 (umask window) + M-3 (blocking probe) + L-1
(jitter dedup); daemon M6 (inbound age sweep) + L3 (connection cap);
NumLock-extended hardware check; the standing feature backlog above.
