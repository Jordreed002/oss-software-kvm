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
| H1 | `selected_lifecycle_tick` error ordering starved the stuck-key sweep; stale comment claimed supervisor also sweeps | 🔧 round B |
| H2 | Zero tests for the manager-level failsafe interlock (watchdog/panic gate/reconcile) | 🔧 round B |
| H3 | `EnableKvm` silently no-ops after `TriggerFailsafe`; panel shows enabled | 🔧 round B |
| M1 | Panic-failsafe one-shot skipped deeper cleanup on later observations | 🔧 round B |
| M2 | Semantic tracker could over-count (observe skipped on dangling pending_remote) | 🔧 round B |
| M3 | Control connection parked forever on broadcast Closed (task leak) | 🔧 round B |
| M4 | Watchdog remediation did sync file I/O inside the capture callback | 🔧 round B (stretch) → cycle 2 if deferred |
| M5 | Failsafe audit JSONL sink never wired in production | 🔧 round B |
| M6 | Inbound held state has no age-based sweep (only peer-liveness) | ⏸ cycle 2 (M/L effort) |
| L1-L4 | Unlogged TriggerFailsafe errors; poisoned test guard; unbounded panel-connection tasks; hot-path audit record | 🔧 round B (L1, L2, L3) / falls out of M4 (L4) |
| — | Verified sound: panic-hook lock-freedom, watchdog mechanics, semantic chord lifecycle bounds, control-service discipline, single-mutex concurrency | — |

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

Cycle 1 fixes: 2 commits of direct fixes (`edec6af`, plus `7a13ef6`/`d12c243`),
round B in flight (daemon hardening + tests). Next: network/IPC audit results →
cycle 2 (M4/M6 + standing backlog top items) → re-audit until no Highs remain.
