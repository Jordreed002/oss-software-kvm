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
