# Audit: Daemon↔control-panel local IPC control surface is missing

**Date:** 2026-08-09
**Cycle:** /loop audit cycle 3
**Spec refs:** `.spec/implementation.md` §31 (Daemon IPC), §32 (Control Panel); `.spec/spec.md` §32, §33
**Severity:** High — the control panel cannot query runtime state or issue commands to a running daemon over a defined local channel

## Summary

The spec requires a local IPC channel between the daemon and the control panel
with a defined command/event surface:

- Commands (`implementation.md` §31): `GetStatus`, `GetPeers`, `GetDevices`,
  `GetDisplays`, `GetTopology`, `SetDeviceRoute`, `SetTopology`, `EnableKvm`,
  `DisableKvm`, `EnableClipboard`, `DisableClipboard`, `SetAudioRoute`,
  `TriggerFailsafe`.
- Events (`implementation.md` §31): `PeerChanged`, `DeviceChanged`,
  `DisplayChanged`, `ActiveHostChanged`, `ActiveDisplayChanged`,
  `LatencyChanged`, `ErrorOccurred`.
- `spec.md` §32: "The control panel should communicate with the daemon via
  local IPC rather than directly managing input hooks."

## Current implementation state

- **Daemon runtime** (`kvm-runtime`) listens on **TCP** for encrypted *peer*
  KVM traffic (`crates/kvm-runtime/src/active.rs`, `BoundedLanListener`). That
  is the inter-host transport, not a local control channel.
- **Control panel** (`apps/control-panel/src-tauri/src/setup.rs`, `nearby.rs`)
  exposes Tauri commands, but they are a **bootstrap / pairing wizard**:
  `create_local_identity`, `import_peer_bundle`, `request_nearby_pairing`,
  `accept_nearby_pairing`, service install, etc. Runtime control of the peer
  link is absent.
- The only panel→runtime channel is a **file-based stop signal**: the managed
  runtime polls a control path with `managed_stop_requested(&control)`
  (`crates/kvm-runtime/src/main.rs`). This is a one-shot "stop" trigger, not a
  status/command IPC.
- `kvm-protocol` defines only the **peer wire protocol**; there are no
  daemon↔panel IPC message types.

## Gap (verified)

There is **no local IPC server** in the daemon — no Windows named pipe, no Unix
domain socket, no localhost TCP control port. None of the 13 §31 commands or 7
§31 events are exposed. A repo-wide search for `named_pipe` / `NamedPipe` /
`local_socket` / `UnixListener` finds **zero** matches in daemon or runtime
code; `TcpListener` matches are all the peer transport or in-test harnesses.

Concretely, with the daemon running and a peer connected, the control panel
cannot today:

- read connection state / RTT / active host / active display,
- list peers, devices, or displays,
- change a device route or topology,
- enable/disable KVM or clipboard,
- trigger the failsafe.

The underlying state the IPC would expose **does** exist —
`DaemonCore`, `PeerManagerSnapshot`, `DeviceInventorySnapshot`,
`DisplayInventorySnapshot`, `RoutingSnapshot` (see `crates/kvm-daemon/src/lib.rs`
exports) — so this is a missing integration/exposure layer, not missing
capability.

## Evidence

```
$ rg "named_pipe|NamedPipe|local_socket|LocalSocket|UnixListener" crates/
# (no matches in daemon/runtime source)

$ rg "GetStatus|GetPeers|SetDeviceRoute|EnableKvm|TriggerFailsafe|…" crates/
# (no matches — §31 command surface not implemented)
```

## Recommended fix (improvement cycle(s))

Current best practice (confirmed via web references): Rust daemons expose local
control over **named pipes (Windows) / Unix domain sockets (macOS)** with a
serde/bincode-framed request/response (+ event stream). Windows named pipes are
noted as fiddly, so a maintained abstraction (or per-platform backend behind a
trait) is worth it.

Suggested phasing:

1. Add IPC message types to `kvm-protocol` (versioned, independent of the peer
   wire protocol) for the §31 commands and events.
2. Add a local IPC transport in `kvm-runtime` (trait `LocalControlTransport`
   with Windows-named-pipe and Unix-socket backends) bound to localhost only.
3. Wire the transport to the existing daemon snapshots (`DaemonCore`,
   `PeerManager`, inventories) for the read commands and to the control plane
   (`WorkspaceControlPlane`, failsafe) for the write commands.
4. Replace the file-based managed-stop hack with `DisableKvm`/stop over IPC
   (keep the file path as a fallback for service-supervisor stop).
5. Add Tauri command shims that call the IPC client so the React UI drives the
   daemon rather than setup-only state.

This is large enough to span more than one improvement cycle; the natural first
slice is the read side (status/peers/devices/displays/topology) since it has no
input-path risk.

## Non-goals for this audit

Did not modify code. Documented finding; implementation deferred to improvement
cycles.
