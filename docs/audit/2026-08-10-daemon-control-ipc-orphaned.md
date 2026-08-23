# Audit: §31 daemon↔panel IPC — protocol exists but is orphaned; no OS transport

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 19 (updates cycle-3 finding with post-cycle-4/6 reality)
**Spec refs:** `.spec/implementation.md` §31 (Daemon IPC), §32-34 (Control Panel), §35 (Diagnostics)
**Severity:** High (blocker) — this is the upstream gate for the control-panel runtime pages (§32-34, cycle 9) and for exposing the §35/§36 diagnostics surface (cycles 7/15) and the cycle-16/18 metrics.

## Spec requirement (§31)

> Provide local IPC between daemon and control panel.
>
> Commands: GetStatus, GetPeers, GetDevices, GetDisplays, GetTopology,
> SetDeviceRoute, SetTopology, EnableKvm, DisableKvm, EnableClipboard,
> DisableClipboard, SetAudioRoute, TriggerFailsafe
>
> Events: PeerChanged, DeviceChanged, DisplayChanged, ActiveHostChanged,
> ActiveDisplayChanged, LatencyChanged, ErrorOccurred

## Current state: protocol + loopback exist, both orphaned; no OS transport

| Layer | Status | Where |
|---|---|---|
| §31 command/event model | ✅ defined | spec §31 |
| Control-plane protocol (encode/decode, versioned) | ✅ implemented | `kvm-protocol/src/control.rs` (cycle 4) |
| `LocalControlTransport` trait | ✅ defined | `control.rs:302` |
| `LoopbackControlTransport` (in-memory mpsc) | ✅ implemented | `control.rs:328` (cycle 6) |
| **OS-backed transport** (Windows named pipe / macOS Unix socket) | ❌ absent | none |
| **Daemon control server** (listens, handles §31 commands) | ❌ absent | none |
| **Panel control client** | ❌ absent | panel uses Tauri invoke, setup-only (cycle 9) |

The decisive evidence: the protocol, the trait, the loopback transport, and
`encode_control`/`decode_control` have **zero callers outside `kvm-protocol`**:

```text
$ grep -rn "LocalControlTransport\|LoopbackControlTransport\|encode_control\|decode_control" crates/ --include=*.rs | grep -v kvm-protocol/
( no matches )
```

So even the implemented layers are test-only. A repo-wide search for
`CreateNamedPipe`/`ConnectNamedPipe` (Windows) and `UnixListener`/`AF_UNIX`
(macOS) finds **nothing** — no OS-backed transport exists. And the control panel
(`apps/control-panel`) uses Tauri's own webview `invoke` bridge (`connect-src
ipc:` in tauri.conf.json), not the control-plane protocol; it issues setup-only
commands (cycle 9).

## Why this is the keystone gap

§31 is the upstream gate for nearly every other open item in this loop:

- **§32-34 control-panel runtime pages** (cycle 9): Workspace / Devices /
  Connections / Audio / Settings / Diagnostics can't exist as live views without
  a data path from the daemon. Today the panel is exclusively a 4-step pairing
  wizard.
- **§35/§36 diagnostics surface** (cycles 7, 15, 16, 18): the event-rate meter
  (now wired, cycle 18), the latency history, and the dropped-packets counter
  (cycle 16) are collected server-side but unreachable by any consumer. §31's
  `LatencyChanged` event has no emitter.
- **Runtime device-route / topology changes** (`SetDeviceRoute`, `SetTopology`):
  the daemon has the state and the revisioned update paths, but no command
  ingress from the panel.

All of the daemon-side *data* these features need already exists (peer state,
device inventory, display topology, routing, the new metrics). What is missing is
the single local channel that carries it to the panel.

## Industry baseline (web-verified)

The canonical local daemon↔GUI transport is **Unix domain sockets on macOS/Linux
and named pipes on Windows** — both first-class, bidirectional, and
access-controllable. TCP loopback is explicitly noted as ~3× slower than Unix
sockets *and* offers no security (any local process can connect) — so it is the
wrong choice for a security-sensitive daemon. Socket file permissions (macOS) and
the named pipe's security descriptor / owner ACL (Windows) are how local access is
restricted. There is even Tauri-specific guidance ("IPC Pipe vs Unix Socket for a
Resident Daemon in Tauri") confirming this is the standard pattern for a Tauri
app with a separate resident daemon — exactly this product's shape.

## Recommended path (improvement cycles)

1. **OS transport impls:** `NamedPipeControlTransport` (Windows, via
   `windows-sys` `CreateNamedPipe`/`ConnectNamedPipe` with a restricted SDDL) and
   `UnixSocketControlTransport` (macOS, `std::os::unix::net::UnixListener` with
   `0600` socket perms), both implementing the existing `LocalControlTransport`
   trait. Reuses the cycle-4 framing (`encode_control`/`decode_control`) verbatim.
2. **Daemon control server:** a small task that binds the OS transport, decodes
   `ControlRequest`s, and maps each §31 command to the existing daemon state /
   revisioned update paths (e.g. `SetDeviceRoute` → the staged route-policy
   transaction; `GetDevices` → device inventory snapshot; `TriggerFailsafe` →
   `activate_failsafe`). Emit the §31 events on the matching state changes.
3. **Access control:** bind the socket/pipe under the user's runtime dir with
   restrictive perms so only the same-user panel can connect (the daemon already
   carries TLS identity material; local IPC should at minimum be same-user).
4. **Panel client:** a thin Tauri command (or sidecar) that opens the transport
   and surfaces §31 data to the React views, replacing the setup-only bridge.

Step 1 is the self-contained first slice (one transport, behind a cfg, with a
loopback/real round-trip test) and unblocks the rest.

## Non-goals for this audit

Did not modify code. Updated the cycle-3 picture with the post-cycle-4/6 reality:
the protocol and loopback transport are themselves orphaned (zero callers), and
no OS-backed transport or daemon server exists. §31 remains the keystone blocker
for §32-34 and for exposing §35/§36.

## Update 2026-08-23

Update 2026-08-23: OS transport landed (`kvm-network::local_ipc`, UDS + named
pipe, framed via kvm-protocol control codec, loopback tests). Remaining for
full §31 closure: daemon-side service wiring and panel-side client (next).

What landed, in recommendation-1 terms:

- `crates/kvm-network/src/local_ipc.rs`: `LocalControlServer` (bind/accept,
  bounded concurrent connections, default 1, hard max 16) and
  `LocalControlClient` (connect with startup-race retry), exchanging
  `ControlFrame`s over a length-prefixed reuse of `encode_control`/
  `decode_control` — no new wire format.
- Platform split: `#[cfg(unix)]` Unix domain socket (caller-supplied path,
  `default_control_path()` under `$TMPDIR`, stale-socket-file recovery,
  `0600` file permissions as the same-user local trust boundary);
  `#[cfg(windows)]` named pipe (`\\.\pipe\software-kvm-control`,
  remote clients rejected), mirroring tokio's documented server pattern.
- Tests (Unix): loopback command/response/event round trip, oversized and
  wrong-version frame rejection before payload buffering, connection-bound
  hold/release, clean shutdown and drop closure, stale vs live endpoint
  rebinding. Every await is `tokio::time::timeout`-wrapped.

## Final closure 2026-08-23: daemon service, runtime wiring, and panel client landed

§31 is no longer orphaned end to end: protocol → OS transport → daemon-side
service → runtime wiring → panel client all exist and are covered by tests.

What landed:

- `crates/kvm-daemon/src/control_service.rs`: `ControlService` over
  `LocalControlServer`. Read-only commands are answered from a bounded
  `ControlViewSource` snapshot; the mutating commands travel through a
  bounded mpsc queue (`CONTROL_COMMAND_QUEUE_CAPACITY = 8`) to the owner
  loop; §31 events fan out from a bounded broadcast
  (`CONTROL_EVENT_CHANNEL_CAPACITY = 16`) to every connected panel; the
  service never locks the capture path. Lists and names are hard-capped to
  the protocol bounds before encoding. `poll_default_control_status` gives
  local consumers a bounded GetStatus poll with "unreachable" mapping.
- `crates/kvm-runtime/src/active.rs`: `ControlPlane` starts the service
  alongside the transport loop (best-effort — a bind failure logs and the
  runtime continues, mirroring the diagnostics-server pattern), refreshes
  the view on the existing ~8 ms service tick under the same manager lock
  the diagnostics snapshot already takes, drains forwarded commands there,
  and publishes `PeerChanged` / `ActiveHostChanged` on state transitions.
  Display inventory is seeded at composition and refreshed on every hotplug
  pass; `TriggerFailsafe` trips the documented
  `kvm_daemon::failsafe_hook::trip()` path plus an immediate manager gate.
- `apps/control-panel/src-tauri/src/control.rs` + `src/bridge.ts` +
  `src/types.ts` + `src/App.tsx`: the `control_status` Tauri command polls
  the daemon over the real UDS/pipe transport with short bounded waits and
  maps transport absence to a friendly "daemon not running" state; the
  Ready screen gains a minimal read-only status card (daemon link, peer
  connection + RTT, KVM routing gate, input destination).

### §31 command surface: live vs deferred

Live (served by the daemon, answered honestly):

| Command | Behaviour |
|---|---|
| `GetStatus` | Live status from the manager routing snapshot + owner-loop KVM gate; `clipboard_enabled` honestly `false` (no clipboard path exists); RTT `None` (telemetry lives on the diagnostics channel). |
| `GetPeers` | One entry for the selected peer (identity retained at composition), state from the routing table with a count-derived fallback. |
| `GetDevices` | Live device-inventory snapshot; routes report the default follow-active-host policy (the inventory snapshot does not carry per-device overrides). |
| `GetDisplays` | Runtime-retained local display inventory (seeded at composition, refreshed on every hotplug pass). |
| `GetTopology` | Configured topology edges, mapped bidirectionally per link (static in this alpha). |
| `TriggerFailsafe` | Enqueued; executed on the owner tick via `failsafe_hook::trip()` + immediate `native_capture_discontinued` gate (fail-open). |
| `EnableKvm` / `DisableKvm` | Enqueued; executed on the owner tick via `rearm_native_capture(Running)` / `native_capture_discontinued`. |

Events live (server-initiated): `PeerChanged`, `ActiveHostChanged`.

Deferred (answered with the protocol's existing `Error { Internal }`
response — no new wire types; revisit as the matching subsystems land):

- `SetDeviceRoute`, `SetTopology` — the revisioned daemon update paths
  exist, but command ingress from the panel is not wired to them yet.
- `EnableClipboard`, `DisableClipboard`, `SetAudioRoute` — no clipboard or
  audio-routing subsystem exists to command.
- Events `DeviceChanged`, `DisplayChanged`, `LatencyChanged`,
  `ErrorOccurred` — no emitters yet (devices/displays refresh by poll;
  RTT is not folded into the control status).

Known honest limits of the live surface: `round_trip_time_ms` is always
`None`; per-device route overrides are not readable from the inventory
snapshot; `GetDisplays` reports the locally observed inventory only.

Transport-level guarantees (frame caps, version rejection, connection
bounds, same-user endpoint permissions) were closed by the 2026-08-23
transport update above and are reused unchanged.
