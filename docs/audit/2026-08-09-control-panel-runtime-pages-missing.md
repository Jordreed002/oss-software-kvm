# Audit: Control-panel runtime pages (§32–§34) are not implemented — only the setup wizard exists

**Date:** 2026-08-09
**Cycle:** /loop audit cycle 9
**Spec refs:** `.spec/implementation.md` §32 (Control Panel), §33 (Workspace UI), §34 (Device UI)
**Severity:** Medium — the panel can install and start the daemon but cannot observe or control a *running* KVM (live workspace, device routing, connections, diagnostics). Upstream-blocked on the daemon↔panel IPC gap (cycle 3).

## What the spec requires (§32–§34)

§32 mandates a Tauri + React + TypeScript control panel with six runtime pages:

```
Workspace, Devices, Connections, Audio, Settings, Diagnostics
```

§33 (Workspace UI): show every screen as a **draggable rectangle** carrying host,
display name, resolution, scale, refresh rate; allow drag/drop layout changes.

§34 (Device UI): per-device **routing radios** — Follow active host / a specific
host / Local — for each input device (mouse, keyboards, trackpad).

§32 also gates the work: *"Do not implement it until core KVM routing is
operational."* Core routing is operational (cycles 1–8 verified router, topology,
backends), so the panel is no longer spec-gated from providing these pages.

## What is actually implemented

The entire frontend is **one setup/pairing wizard** — a 4-step flow
(`apps/control-panel/src/App.tsx`, 514 lines):

```
"This computer" → "Pair" → "Arrange" → "Ready"
```

The data surface confirms this is setup-only. `bridge.ts` exposes exactly these
Tauri commands and nothing runtime-querying:

```
setup_status, create_local_identity, import_peer_bundle,
request/accept/confirm/decline_nearby_pairing, forget_paired_computer,
repair_lan_binding, finalize_setup, validate_setup, start_runtime, stop_runtime
```

`types.ts` carries a single `SetupSnapshot` (identity, peer, displays, placement,
runtime on/off, a DEV-only `developerDiagnostics` blob). There is **no** runtime
snapshot, no peer-health/RTT type, no device list, no routing type.

### Page-by-page vs §32

| Spec page | Present? | Evidence |
|---|---|---|
| Workspace | ⚠️ setup only | the wizard's "Arrange" step sets *initial* display placement (`Placement = local_left \| local_right`, `DisplayPlacement[]`); it is not the §33 live draggable-rectangle workspace with per-display host/name/resolution/scale/refresh |
| Devices | ❌ | no device list, no per-device routing; §34 radios absent entirely |
| Connections | ❌ | no peer-state/RTT/connection surface |
| Audio | ❌ | no audio UI (consistent with audio being a spec non-goal / not yet built) |
| Settings | ⚠️ partial | runtime start/stop + LAN repair exist within the wizard; no standalone settings page (keyboard mode, clipboard toggles, failsafe trigger) |
| Diagnostics | ⚠️ debug only | `developerDiagnostics` blob shown in DEV (`import.meta.env.DEV`); not the §35 unified diagnostics page and absent in production |

**Result: 0 of the 6 required runtime pages are implemented as such.** The panel
is a bootstrap/installer that can bring the daemon up and down, but once the KVM
is running the user has no panel surface to observe or steer it.

## Why this is upstream-blocked (not just missing UI)

Even with the pages built, the panel has **no runtime data source**: the
daemon↔panel IPC transport does not exist (cycle-3 finding; protocol contract
added cycle 4, loopback transport cycle 6, but no named-pipe/Unix-socket backend
and no daemon/panel wiring). So the `bridge.ts` commands can only talk to
setup-time state, never to a live `DaemonCore`/`WorkspaceState`. The runtime
pages are therefore blocked on **two** gaps in sequence: IPC transport/wiring
first, then the page UI.

## Evidence

```
# Frontend is a single wizard file; no router, no page components, no runtime views.
$ find apps/control-panel/src -name "*.tsx" -o -name "*.ts"
apps/control-panel/src/App.tsx       # 514-line 4-step wizard
apps/control-panel/src/bridge.ts     # setup-only Tauri commands
apps/control-panel/src/types.ts      # SetupSnapshot + setup types only
apps/control-panel/src/main.tsx

# bridge.ts command set: all setup/pairing/lifecycle, nothing runtime-querying.
create_local_identity, import_peer_bundle, *_nearby_pairing,
forget_paired_computer, repair_lan_binding, finalize_setup,
validate_setup, start_runtime, stop_runtime

# No §34 device-routing type or command exists anywhere.
$ rg "SetDeviceRoute|deviceRoute|device_route|routing radio" apps/   # (no matches)
```

## Industry baseline (verified)

Established in the cycle-5 conformance map: software-KVM tools (Barrier,
Synergy) ship a runtime status surface — a tray icon plus a status window
showing connection state and the active screen/server, with a settings window
for screen layout and hotkeys. The spec's six-page set (Workspace / Devices /
Connections / Audio / Settings / Diagnostics) is a superset of that convention,
so the gap is a real shortfall against both spec and domain norm, not a
speculative nice-to-have. (Web search for software-KVM-specific UI taxonomies
returned mostly hardware/IP-KVM results; the spec itself and the
Barrier/Synergy baseline are the operative references here.)

## Recommendation

This is the largest user-facing remaining gap but it is **not** the right next
slice, because it is gated on the IPC transport. Suggested ordering:

1. **First** land the daemon↔panel IPC transport + read-side wiring (cycle-3/4/6
   follow-through) so a runtime snapshot is reachable from the panel. Without
   it, any page is a static mock.
2. **Then** build the read-only runtime pages in dependency order: Connections
   (peer state/RTT), Workspace (live draggable displays), Devices (read device
   inventory), Diagnostics (§35). These map directly onto the `ControlResponse`
   payloads already defined in `kvm-protocol::control` (Status/Peers/Devices/
   Displays/Topology).
3. **Last** add the write surfaces: Device routing radios (§34 →
   `SetDeviceRoute`), topology drag/drop (§33 → `SetTopology`), and the
   enable/disable/failsafe toggles (→ `EnableKvm`/`DisableKvm`/`TriggerFailsafe`).

The control-plane protocol (cycle 4) already carries every payload these pages
need, so once IPC wiring lands the UI work is straightforward React on top of
decoded `ControlFrame`s.

## Non-goals for this audit

Did not modify code. Documented finding; UI implementation deferred to
improvement cycles, sequenced after the IPC transport.
