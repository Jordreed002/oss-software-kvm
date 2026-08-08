# Architecture

OSS Software KVM runs one native Rust daemon on each host. The daemons own input capture,
routing, suppression, injection, peer communication, configuration, and recovery. The control
panel is an optional local IPC client; daemon correctness must never depend on it.

## Version-one scope

Version one targets Windows 11 and macOS and includes keyboard and pointer routing, a logical
display workspace, per-device routes, pairing, encrypted LAN transport, plain-text clipboard
synchronisation, startup integration, diagnostics, and a functional control panel. Audio,
advanced gestures, Linux, display streaming, and WAN control are deliberately deferred.

## Crate boundaries

- `kvm-types`: stable platform-neutral domain values.
- `kvm-input`: physical key vocabulary, semantic commands, and pressed-input tracking.
- `kvm-protocol`: independently versioned wire data and framing.
- `kvm-router`: device-route decisions against an immutable workspace snapshot.
- `kvm-topology`: logical display geometry and cross-display transitions.
- `kvm-network`: authenticated-stream framing, admitted persistent peer sessions, channel
  scheduling, peer health, reconnect policy, and a sealed outbound TCP/rustls adapter. Production
  inbound listening and discovery remain integration work.
- `kvm-security`: host identity, pairing, authorization, and credential interfaces. Native
  credential stores remain integration work; paired session admission now consumes the
  network-owned, direction-bound TLS exporter proof.
- `kvm-config`: versioned non-secret persistent configuration.
- `kvm-clipboard`: loop-free clipboard synchronisation.
- `kvm-windows` and `kvm-macos`: native device/display enumeration, observation-only capture,
  injection, identity, and capability/permission surfaces. Selective suppression remains behind
  the native feasibility gate described in `platform-notes.md`.
- `kvm-daemon`: safety-state, deliberate wire/domain conversion, and simulated admitted-peer
  coordination. Full native composition, local IPC, and service lifecycle remain integration work.
- `kvm-diagnostics`: read-only physical-host evidence collection. It never suppresses or routes
  input and redacts captured payload values by default.

Platform crates depend inward on shared crates. Shared crates never depend on operating-system
APIs. Wire structs remain separate from domain structs so either side can evolve deliberately.

## Input path

Native callbacks classify an event as physical, KVM-injected, or unknown and convert physical
events into the shared representation immediately. A routing decision uses a read-only workspace
snapshot. Local events are released to the OS; remote events are suppressed locally and offered
to a bounded, high-priority input channel. Injection updates pressed state before acknowledging
the event.

Clipboard, discovery, diagnostics, configuration, logging, and the UI use separate bounded work
queues. They cannot apply backpressure to keyboard or pointer processing. Mouse movement may be
coalesced only after measurement; keys and pointer buttons are always ordered and lossless while
the peer is healthy.

## Workspace authority

The daemon hosting the active display is authoritative for the logical pointer. A cross-host
transition carries a monotonically increasing workspace epoch and transition identifier. The new
host acknowledges the transition before it becomes authoritative. Stale epochs are rejected.
During ambiguity or connection failure both peers converge to safe local control rather than
continuing remote suppression.

## Native execution model

Capture and suppression callbacks run on platform-appropriate native threads and must be bounded,
non-blocking, and allocation-conscious. Network, discovery, configuration, diagnostics, and IPC
run on the asynchronous runtime. Injection is isolated behind a platform worker so slow OS calls
cannot block capture callbacks.

## Failure invariant

At every milestone, loss of peer health, daemon shutdown, a route change, or the emergency chord
must stop remote suppression and release logically pressed keys and buttons. The control panel is
never part of this recovery path.
