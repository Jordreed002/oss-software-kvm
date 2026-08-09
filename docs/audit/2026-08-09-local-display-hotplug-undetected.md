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
