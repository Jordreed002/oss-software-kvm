# Audit: Local display hotplug is undetected at runtime (displays enumerated once at boot)

**Date:** 2026-08-09
**Cycle:** /loop audit cycle 11
**Spec refs:** `.spec/implementation.md` §11 (logical workspace), §33 (Workspace UI), §39 (acceptance: multi-monitor); `.spec/spec.md`
**Severity:** Medium — a monitor plugged/unplugged, or a resolution/DPI/scale/refresh change made *after* the daemon starts, is never observed locally; the workspace topology and the §33 UI fields (resolution/scale/refresh) silently go stale.

## Finding

The local host's displays are **enumerated exactly once, at daemon startup**, and
never again. Both platform entry points call `enumerate_displays()` a single time
and feed the result into the composed runtime:

- Windows — `crates/kvm-runtime/src/platform_run.rs:114` (`WindowsDisplayBackend::new(local_host).enumerate_displays()`)
- macOS — `crates/kvm-runtime/src/platform_run.rs:144` (`MacDisplayBackend::new(local_host).enumerate_displays()`)

There is **no runtime display-change detection** on either platform. A repo-wide
search for the canonical mechanisms finds nothing:

```
$ rg "ReconfigurationCallback|RegisterReconfiguration|DISPLAYCHANGE|display.*callback|display.*notification|WTSRegister" crates/
# (no matches)
```

- Windows: no hidden message-only window receiving the `WM_DISPLAYCHANGE`
  broadcast (the standard signal that a display was added/removed/reconfigured).
- macOS: no `CGDisplayRegisterReconfigurationCallback` registration (the Core
  Graphics callback fired on any display add/remove/resolution/DPI change).

Because the snapshot is fixed at boot, a local monitor hot-plug, a resolution or
refresh-rate change, a Windows DPI/scale ("make text bigger") change, or a
display rearrangement made while the daemon runs is **invisible to the local
daemon**. Consequences against the spec:

- §11 logical-workspace topology becomes stale: a newly attached monitor never
  appears as a handoff edge; a removed monitor stays as a dead edge.
- §33 Workspace UI fields (resolution / scale / refresh rate) won't reflect
  runtime changes.
- §39 acceptance assumes stable multi-monitor layouts across a session; a mid-
  session monitor change breaks pointer handoff geometry with no recovery.

## What *does* exist (so this is an integration gap, not a missing capability)

The cross-host plumbing for display change is fully present — it just only ever
carries **remote** peer display state, never re-snapshots the local host:

- `DisplaySnapshotV1` / `DisplayUpdatedV1` wire messages exist and are handled
  (`kvm-daemon/src/display_inventory.rs` apply paths; `workspace_control.rs:467,477`).
- `display_inventory.rs` can apply incoming snapshots/updates.
- The macOS backend even documents the intent —
  `crates/kvm-macos/src/native.rs:2178`: *"the daemon refreshes display
  snapshots on change events"* — but the change-event source is not wired in
  the runtime startup path.

So the inventory layer is ready to absorb a refreshed local snapshot; what's
missing is the **local change detector** that triggers a re-enumeration and
re-publishes the local host's `DisplayUpdated`.

## Recommended fix (improvement cycle)

Wire per-platform runtime display-change detection, re-enumerate on change, and
republish the local snapshot through the existing inventory path:

1. **macOS:** register a `CGDisplayRegisterReconfigurationCallback`; on a
   reconfiguration event, re-run `enumerate_displays()` and emit a local
   `DisplayUpdated` (the backend already exposes the snapshot builder).
2. **Windows:** create a message-only window (or reuse the existing input hook
   window if it has a message pump) to receive `WM_DISPLAYCHANGE`; on receipt,
   re-enumerate via `EnumDisplayMonitors` (already used for the one-shot boot
   enumeration at `kvm-windows/src/native.rs:2481`) and emit a local
   `DisplayUpdated`.
3. Debounce/coalesce rapid reconfiguration bursts (a single dock/undock can
   fire several events) before republishing, and guard topology edges that
   reference a now-removed display (fail-safe to local, mirroring §23 recovery).

This is self-contained: it consumes the already-implemented inventory apply
path and the existing `DisplayUpdated` message, and it touches capture/geometry
state rather than the encrypted input hot path.

## Industry baseline (verified)

The detection mechanisms are the documented platform standards: `WM_DISPLAYCHANGE`
is the Windows broadcast sent to top-level windows on any display-configuration
change, and `CGDisplayRegisterReconfigurationCallback` is the macOS Core Graphics
callback for display add/remove/move/resolution changes. Comparable software-KVM
tools re-snapshot on these events so multi-monitor layouts track reality across a
session. (Web search surfaced mostly hardware/driver hot-plug behaviour rather
than the in-app APIs; the platform-standard mechanisms above are the operative
reference.)

## Non-goals for this audit

Did not modify code. Documented finding; the per-platform change detector is
deferred to an improvement cycle.

## Also verified conformant this cycle (not gaps)

- **§23 Failure Recovery:** the recovery sequence (stop remote routing → release
  suppression → mark active host local → restore local pointer) is implemented
  in `kvm-daemon/src/core.rs` — `active_host` is forced to `local_host` at ~15
  disconnect sites, `restore_local_device` restores the pointer, and all paths
  are in the daemon core (UI-independent, satisfying "recovery must not depend
  on the UI").
- **Protocol-version negotiation:** `negotiate_protocol_version`
  (`kvm-network/src/peer.rs:1755`) selects the highest mutually-supported version
  and cleanly rejects no-overlap with `SessionError::NoCompatibleProtocolVersion`;
  admission validates Hello version bounds; `FrameHeader::decode_supported`
  rejects unsupported versions.
- **§27/§30 Clipboard:** text-only is spec-compliant (images/files/rich types are
  explicitly "Later"); loop-suppression is implemented.

## Update 2026-08-23 — remediation landed (code complete; hardware validation pending)

The local display-change detector recommended in this audit is implemented and
wired into the runtime's inventory-refresh path. Full closure still requires
physical-hardware validation entries (see below); this repository requires
hardware validation before any native-behavior claim is accepted.

### What landed

- **macOS** (`crates/kvm-macos/src/hotplug.rs`, plus FFI exposure in
  `native.rs`): `MacHotplugWatcher` registers
  `CGDisplayRegisterReconfigurationCallback` on a dedicated watcher thread that
  owns its own `CFRunLoop`. The native callback performs exactly one
  non-blocking `try_send` into a bounded raw channel (capacity 64) — no work
  runs on the Carbon/CG callback thread. The watcher thread drains the raw
  channel and coalesces bursts.
- **Windows** (`crates/kvm-windows/src/hotplug.rs`): `WindowsHotplugWatcher`
  runs a dedicated message thread with a hidden **top-level** window (not the
  message-only capture window — message-only windows do not receive system
  broadcasts) receiving `WM_DISPLAYCHANGE`, and a 50 ms `WM_TIMER` tick driving
  the coalescer's trailing edge. A `cfg(windows)` const-assertion pins the
  local message constants to the `windows` crate values.
- **Coalescing** (both platforms): a leading-edge + single-trailing-edge
  debouncer collapses each burst to at most one hint per 200 ms quiet window
  per kind (`HOTPLUG_COALESCE_WINDOW`), so one physical dock/undock yields at
  most two re-enumerations (immediate plus post-settle).
- **Runtime wiring** (`crates/kvm-runtime/src/active.rs`,
  `platform_run.rs`): each platform entry point starts its watcher (degrading
  to the previous boot-time-snapshot behavior, with a developer event, if the
  watcher cannot start — monitoring is not an authority gate). The service
  loop polls the bounded hint channel on its existing 4 ms lifecycle tick,
  re-enumerates through fresh stateless backends on `spawn_blocking` (never
  through the capture-owned backend), and applies the snapshot via the
  existing `PeerManager::apply_local_display_snapshot` path with
  monotonically increasing revisions. Rejected applies (for example a newly
  attached display with no configured topology placement) are logged and
  abandoned; the daemon's own retry machinery reconciles partial updates, and
  the next physical change produces a fresh hint.

### Verification

- `cargo fmt --all --package kvm-macos --package kvm-windows --package kvm-runtime` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean (cfg hygiene
  proven on a macOS host; internals are `cfg(any(platform, test))`-gated so
  Linux CI stays green).
- `cargo test --package kvm-macos --package kvm-windows --package kvm-runtime --all-targets` —
  42 + 45 + 2 + 35 passing. Platform-neutral coverage: burst coalescing
  (leading/trailing edge, per-window bound, kind independence), bounded-channel
  drop accounting (never blocks or panics on a full or disconnected channel),
  full dock-burst collapse, and — on the macOS host — direct invocation of the
  native callback bodies with injected contexts, plus a native watcher
  start/stop/exclusivity lifecycle test.
- The `cfg(windows)` watcher code cannot run on this host; it was
  type-checked against the real `windows` 0.62 crate for the
  `x86_64-pc-windows-gnu` target via a throwaway out-of-tree harness (zero
  warnings). Runtime behavior on Windows remains compile-verified only.

### Hardware validation still required before full closure

Record entries under `docs/validation/{macos,windows}/` per the repository's
hardware-validation workflow. Minimum matrix:

- **macOS:** plug/unplug a monitor (direct and via USB-C/Thunderbolt/HDMI
  dock) mid-session; change resolution, refresh rate, and scaling in System
  Settings mid-session; rearrange displays; sleep/wake with an external
  monitor attached. For each: exactly the expected re-enumeration cadence (one
  immediate plus at most one post-settle refresh per 200 ms window), the local
  `DisplayUpdated` is re-published to the peer, workspace topology recompiles,
  and pointer handoff geometry tracks the new layout. Also: revoke Input
  Monitoring while the daemon runs and confirm display watching continues
  (device watching degrades by design; see the device-hotplug audit).
- **Windows:** dock/undock and resolution/DPI/scale changes on single- and
  mixed-DPI multi-monitor setups; confirm the hidden top-level window receives
  `WM_DISPLAYCHANGE` on the target Windows builds (10/11), the snapshot is
  re-published, and virtual-screen coordinates remain consistent for handoff
  geometry.
- **Both:** confirm the watcher threads add no measurable input-latency
  regression (they never touch the capture/injection hot path) and that
  repeated watcher start/stop (daemon restart, profile reload) leaks no native
  resources (CFRunLoop retain/release balance on macOS; window/timer/device
  notification teardown on Windows).
