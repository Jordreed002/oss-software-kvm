# Audit: Spec conformance map (cycle-5 consolidated review)

**Date:** 2026-08-09
**Cycle:** /loop audit cycle 5
**Spec refs:** `.spec/implementation.md` (39-task Codex sequence, §1–§40), `.spec/spec.md`
**Purpose:** Map the spec's phased task sequence to verified implementation status and prioritise remaining gaps. Distilled from direct code review in cycles 1–5.

## Industry scope baseline (verified via web)

Comparable open-source software-KVM tools (Barrier, Synergy) scope the **initial
release** to keyboard + mouse sharing + clipboard sync. Audio is explicitly out
of scope for Barrier ("Clipboard sharing is supported. That's it."). This
project's own spec (`spec.md` §34 priority order, §38 non-goals) matches that
baseline, so the core KVM (input + topology + clipboard + networking) is the
right bar for initial-release conformance; audio and UI polish are lower
priority by design.

## Phase → status

| Spec phase / area | Status | Evidence |
|---|---|---|
| 1 Workspace + foundation | ✅ Done | Cargo workspace, `kvm-types`, `kvm-config` (versioned + migration), `tracing` logging |
| 2 Networking (discovery, pairing, auth, transport, framing, heartbeat, reconnect) | ✅ Done | `kvm-discovery`, `kvm-security` (pairing, allowlist, admission), `kvm-network` (rustls, heartbeat, reconnect, bounded queues), `kvm-protocol` framing |
| 3 Keyboard (bidirectional, modifiers, suppression, injected filtering) | ✅ Done | `kvm-windows`/`kvm-macos` capture+inject, injected-event classification (`EventClassifier`) |
| 4 Pointer (move/click/scroll) | ✅ Done | platform backends, `InputPayload` |
| 5 Logical workspace (topology, normalised transition, DPI) | ✅ Done + tested | `kvm-topology` (mismatched-resolution + Retina-DPI transition test, gap/partial-overlap tests) |
| 6 Follow active host | ✅ Done | `kvm-router`, `WorkspaceState` |
| 7 Per-device routing | ✅ Done | `RoutingTable`, `DeviceRoute` |
| 8 Logitech/trackpad extras | ✅ Done | XBUTTON1/2, h/v wheel in Windows backend |
| 9 Clipboard (text, loop suppression) | ✅ Done + tested | `kvm-clipboard` (echo suppression, dedup, bounded replay, rollback) |
| Failsafe + stuck-key recovery (§24/§25) | ✅ Done + tested | `PressedState` consumed on disconnect/route-change/failsafe/shutdown; emergency shortcut |
| Discovery trust-gating (§20) | ✅ Done + tested | `PairedPeerAllowlist` fail-closed; `discovery_or_unknown_identity_never_implies_trust` test |
| Semantic translation (§17/§26) | ⚠️ Partial | resolver/translator exist (`kvm-input::semantic`, cycle 2) but **not wired** into daemon injection; `KeyboardMode::Semantic` still a no-op on the input path |
| Daemon↔panel IPC (§31/§32) | ⚠️ Handler done, transport missing | protocol contract (cycle 4) + **daemon-side `ControlHandler`** (§31 command→response mapping, validation, serve loop over `LocalControlTransport`, injectable read/effect seams, 14 loopback tests) now exist; **no named-pipe/Unix-socket transport** and no production backend/main-loop wiring yet |
| Control panel (§32–§34) | ⚠️ Partial | setup/pairing wizard + Tauri commands exist; runtime status/control blocked on the IPC gap; full UI page set (Workspace/Devices/Connections/Audio/Settings/Diagnostics) not verified |
| macOS selective suppression (§15) | ⚠️ Known limitation | `kvm-macos` docs: selective suppression unavailable pending IOHID↔CGEvent correlation (whole-host suppression available) |
| Audio (§28–§30) | ❌ Absent | no `kvm-audio` crate; consistent with industry v1 scope and spec non-goals — lowest priority |
| Diagnostics surface (§35) | ⚠️ Unverified | metrics exist piecemeal (latency, event rate) but a unified diagnostics exposure is not confirmed |

## Prioritised remaining gaps

1. **Daemon↔panel IPC transport + wiring (§31).** Highest user-facing impact: until
   the named-pipe/Unix-socket transport exists and the daemon answers the §31
   commands, the control panel cannot show runtime status or issue runtime
   commands. Protocol contract is ready (cycle 4). First slice = read side.
2. **Wire semantic translation into the input path (§17/§26).** Resolver is ready
   (cycle 2); needs gating on `KeyboardMode::Semantic` and consumption in the
   Windows/macOS injectors. Otherwise semantic mode stays inert.
3. **Duplicate `KeyboardMode` definitions** (`kvm-config` vs `kvm-input`). Mild
   DRY/drift risk — the same two-variant enum is defined in both crates and kept
   in sync manually (the kind of silent drift that nearly caused the cycle-1
   semantic no-op). Consolidation is a layering judgment (config→input coupling
   vs an intentional config-schema/domain split); flag for maintainer decision.
4. **macOS selective suppression (§15).** Hard problem (IOHID identity ↔ CGEvent);
   already a documented known limitation. Whole-host suppression covers safety.
5. **Unified diagnostics surface (§35).** Verify/consolidate existing metrics.
6. **Audio (§28–§30).** Optional; defer per spec non-goals.

## Note

No code changed in this audit. This map supersedes nothing; the per-area audit
docs (semantic, IPC) remain the detailed records. Items 1–2 are the recommended
targets for upcoming improvement cycles.
