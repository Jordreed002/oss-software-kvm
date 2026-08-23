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

## Update 2026-08-23 — remediation landed (code complete; hardware validation pending)

The local device-hotplug detector and the `replace_local_device_inventory`
wiring recommended in this audit are implemented. Full closure still requires
physical-hardware validation entries (see below); this repository requires
hardware validation before any native-behavior claim is accepted.

### What landed

- **macOS** (`crates/kvm-macos/src/hotplug.rs`): the watcher's dedicated
  IOHIDManager registers device-matching/removal callbacks on its own
  `CFRunLoop` (a separate manager from the capture layer's). The callbacks
  perform exactly one non-blocking `try_send` into a bounded raw channel —
  no re-enumeration, allocation, or other work runs on the callback thread.
  `IOHIDManagerOpen` needs the Input Monitoring grant: without it the watcher
  degrades to display-only watching rather than failing, and
  `HotplugStatistics::device_watch_active` reports `false`.
- **Windows** (`crates/kvm-windows/src/hotplug.rs`): device attach/detach
  arrives as `WM_DEVICECHANGE` with `DBT_DEVICEARRIVAL` /
  `DBT_DEVICEREMOVECOMPLETE` on the watcher's hidden top-level window, after
  `RegisterDeviceNotificationW` filtered delivery to the HID device-interface
  class (`GUID_DEVINTERFACE_HID`); the `DEV_BROADCAST_HDR` device type is
  validated before a directional hint is emitted, and undirected broadcasts
  (for example `DBT_DEVNODES_CHANGED`) are ignored.
  `WM_INPUT_DEVICE_CHANGE` was deliberately **not** used as the watch source:
  `RegisterRawInputDevices` replaces the process-wide registration, so an
  independent `RIDEV_INPUTSINK` registration here would silently steal
  `WM_INPUT` delivery from the active capture session. The existing capture
  loop keeps its internal `WM_INPUT_DEVICE_CHANGE` cache rebuild unchanged.
- **Coalescing**: same leading-edge + single-trailing-edge debouncer as the
  display watcher (200 ms quiet window, per-kind), so a dock firing many
  matching/removal callbacks yields at most two re-enumerations.
- **Runtime wiring** (`crates/kvm-runtime/src/active.rs`, `platform_run.rs`):
  hints are folded into a device-refresh demand on the existing service tick,
  re-enumerated through a fresh stateless backend on `spawn_blocking`, and
  applied via the existing revisioned
  `PeerManager::replace_local_device_inventory` path (monotonically increasing
  revisions seeded after the startup revision; best-effort with developer-event
  logging on rejection — the daemon's own retry machinery reconciles partial
  updates). Note for the current alpha: the runtime composes whole-host-alpha
  capture, whose inventory is the two stable aggregate devices, so a device
  refresh today republishes that same set; the wiring becomes observable as
  per-device inventory once a per-device capture mode is composed.

### Verification

Same three gates as the display-hotplug remediation (fmt, workspace clippy
`-D warnings`, tests: 42 + 45 + 2 + 35 passing). Platform-neutral coverage:
coalescing bounds and kind independence, bounded-channel drop accounting,
dock-burst collapse through `DeviceAdded`/`DeviceRemoved`, Windows message
classification (arrival/removal/undirected/unknown), and — on the macOS host —
direct invocation of the native IOHID callback bodies with injected contexts
(including rejection of null contexts and non-zero IOKit results) plus a
watcher start/stop/exclusivity lifecycle test. The `cfg(windows)` code was
type-checked against the real `windows` 0.62 crate for
`x86_64-pc-windows-gnu` via a throwaway out-of-tree harness (zero warnings);
its runtime behavior on Windows remains compile-verified only.

### Hardware validation still required before full closure

Record entries under `docs/validation/{macos,windows}/` per the repository's
hardware-validation workflow. Minimum matrix:

- **macOS:** attach/detach USB and Bluetooth keyboards and mice mid-session
  (with the Input Monitoring grant held); confirm `DeviceAdded`/`DeviceRemoved`
  hints fire, the refreshed inventory matches `system_profiler`/IOHID reality,
  stable `DeviceId`s across re-attach, and peers receive the revised
  `DeviceSnapshot`. Also: confirm the degraded path (grant revoked) leaves
  display watching intact with `device_watch_active: false`.
- **Windows:** attach/detach USB and Bluetooth keyboards and mice; confirm the
  HID-interface registration delivers precise arrival/removal events (not just
  `DBT_DEVNODES_CHANGED`) on the target Windows builds, the refreshed
  inventory matches Device Manager, and container-scoped `DeviceId`s stay
  stable across replug. Note any HID devices that do not expose
  `GUID_DEVINTERFACE_HID` (for example some RDP-induced collections) as known
  blind spots.
- **Both:** confirm rapid replug storms stay coalesced (no more than one
  inventory revision per 200 ms window plus a trailing edge), routing targets
  never reference removed devices after the next refresh, and watcher
  start/stop cycles leak no native resources.
