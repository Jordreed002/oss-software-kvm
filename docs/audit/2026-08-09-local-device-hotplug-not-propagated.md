# Audit: Local input-device hotplug is not propagated to the device inventory (§7/§34)

**Date:** 2026-08-09
**Cycle:** /loop audit cycle 13
**Spec refs:** `.spec/implementation.md` §6 (Input Device Model), §7 (per-device routing), §34 (Device UI); §39 (acceptance: stable device set across a session)
**Severity:** Medium — a keyboard/mouse/trackpad plugged in or unplugged *after* the daemon starts is not reflected in the device inventory, so it is invisible to per-device routing (§7), the §34 Device UI, and peer advertisement.

## Finding

Local input devices are seeded into the device inventory **once, at runtime
composition** (startup), and never refreshed from local hotplug:

```
crates/kvm-runtime/src/active.rs:1127
    manager.replace_local_device_inventory(INITIAL_DEVICE_REVISION, local_devices, INITIAL_NOW_NS)
```

`INITIAL_DEVICE_REVISION` is the only production call. After that, a local
device added or removed at runtime does **not** update the inventory on either
platform:

- **Windows:** no device-change detection at all — no `WM_DEVICECHANGE` handler,
  no `RegisterDeviceNotification`. `enumerate_devices()` runs once at startup
  (`platform_run.rs` → `WindowsInputBackend::enumerate_displays`). A repo-wide
  search for `WM_DEVICECHANGE` / `DBT_DEVICEARRIVAL` / `RegisterDeviceNotification`
  finds **zero** matches.
- **macOS:** IOHID *does* detect add/remove — `iohid_device_matched` /
  `iohid_device_removed` (`kvm-macos/src/native.rs:1710`) — but the removal
  callback only prunes the **capture** layer's internal map:
  ```rust
  // kvm-macos/src/native.rs:1723
  context.devices.remove(&device.addr());
  ```
  It does **not** re-enumerate, does **not** call `replace_local_device_inventory`,
  and does **not** emit a `DeviceSnapshot`/`DeviceRemoved`. So on macOS a newly
  matched device may be *captured* (input flows) but is still absent from the
  inventory/routing/UI, and a removed device stays as a stale routing target.

So the inventory's local device set is frozen at boot regardless of platform.

## Consequences against the spec

- **§7 per-device routing:** a device plugged in mid-session has no inventory
  record, so it cannot be given a per-device route; a removed device remains as a
  dead routing target until restart.
- **§34 Device UI:** the device list and per-device routing radios would show a
  stale set.
- **Peer advertisement:** the local host's `DeviceSnapshot` (revisioned) is
  published once; peers never learn about a locally added/removed device, so
  their view of this host's devices is wrong.
- **§39 acceptance** assumes a stable device set across a session; a mid-session
  dock/undock of a peripheral silently breaks the model.

## What already exists (so this is a wiring gap, not missing capability)

The cross-host device-change plumbing is complete and only ever carries *remote*
peer device state — exactly paralleling the cycle-11 display-hotplug finding:

- `DeviceAddedV1` / `DeviceRemovedV1` / `DeviceSnapshotV1` messages exist, are
  validated, and are applied (`kvm-daemon/src/device_inventory.rs`,
  `workspace_control.rs:453-465`).
- A fully revisioned, ordered, retry/abort **local** update mechanism exists:
  `PeerManager::replace_local_device_inventory` / `retry_local_device_inventory_update`
  / `abort_local_device_inventory_update` (`peer_manager.rs:709-825`), with tests
  covering ordering and retry.
- `kvm-windows` / `kvm-macos` `enumerate_devices()` is the one-shot enumeration
  used at startup.

So the inventory layer is ready to absorb a refreshed local device set; what is
missing is the **local change detector** that triggers a re-enumeration and calls
`replace_local_device_inventory` to republish.

## Recommended fix (improvement cycle)

1. **macOS (smaller lift):** the IOHID matched/removed callbacks already fire on
   add/remove. Debounce a burst, re-run `enumerate_devices()`, and call
   `replace_local_device_inventory(next_revision, devices, now)` so the inventory
   and peers converge. (The capture device map already tracks the live set.)
2. **Windows:** create a message-only window (or reuse an existing message pump)
   and register for `WM_DEVICECHANGE` — optionally `RegisterDeviceNotification`
   filtered to the HID interface for finer-grained, lower-noise notifications. On
   arrival/removal, debounce, re-enumerate via the existing `enumerate_devices()`,
   and call `replace_local_device_inventory`.
3. Reuse the existing revisioned/retry path for both, so a transient enumeration
   race is reconciled by the next snapshot rather than corrupting the inventory.

This is self-contained: it consumes the already-implemented, already-tested
`replace_local_device_inventory` path and adds no encrypted-input hot-path risk.

## Industry baseline (verified via web)

The platform-standard mechanisms are confirmed: on Windows, `WM_DEVICECHANGE`
(with `DBT_DEVICEARRIVAL` / `DBT_DEVICEREMOVECOMPLETE`) is the documented
broadcast for device add/remove, with `RegisterDeviceNotification` for
interface-filtered HID notifications (multiple Stack Overflow / Microsoft Learn
references for "detecting input device arrival/removal"). On macOS, IOHID
matching/removal callbacks are the standard — and this codebase already
registers them in the capture layer; they just need to feed the inventory.

## Non-goals for this audit

Did not modify code. Documented finding; the per-platform change detector is
deferred to an improvement cycle (macOS is the lower-effort first slice since the
IOHID callbacks already exist).
