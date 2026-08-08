# OSS Software KVM

OSS Software KVM is a planned open-source, bidirectional software KVM for Windows 11 and macOS. Its goal is to make computers and their displays feel like one logical workspace: move the pointer across a configured display boundary and keyboard focus follows automatically.

## Intended experience

- Control either host with keyboards, mice, and trackpads attached to either machine.
- Treat Windows monitors and a MacBook display as one configurable workspace.
- Route input according to pointer position without manual hardware switching.
- Preserve safe local control through disconnects, crashes, and an emergency shortcut.
- Keep the native Rust daemon running independently from the control-panel UI.

## Architecture

The core is a Rust Cargo workspace with platform-neutral domain, protocol, routing, topology, networking, security, configuration, clipboard, and daemon crates. Native Windows and macOS crates currently provide device and display discovery, input injection, capability reporting, and safe unsupported-platform stubs.

A separate Tauri, React, and TypeScript control panel will configure and monitor the daemon over local IPC. Peer communication will be authenticated and encrypted over the local network.

## Status

The initial engineering foundation is implemented and covered by automated tests. It includes the
shared input path, protocol, routing, topology, configuration, persistent admitted peer sessions,
pairing and authorization state, bounded LAN discovery/peer scheduling, daemon safety state,
logical-workspace pointer handoff, authenticated Follow Active Host keyboard routing, clipboard
synchronization, and native enumeration, observation, and injection surfaces.

An explicit aggregate whole-host alpha capture path now exists for Windows and macOS, together
with exact-session routing, native lifecycle gating, and a fail-closed two-host runtime preparation
boundary. The foreground runtime now composes secure listener/dialer ownership, exact session
pumps, native inventory, synchronous capture/suppression, configured edge handoff, and gate-first
shutdown. It is runnable as a manually provisioned two-host engineering alpha, but physical
bidirectional acceptance on Windows 11 and macOS is still required before it can be called a usable
release. Per-device suppression remains deferred until the aggregate alpha is proven on hardware.

The detailed product and engineering requirements live in:

- [Product and technical specification](.spec/spec.md)
- [Implementation specification](.spec/implementation.md)
- [Milestone 02: observable native capture](.spec/milestone-02-capture-transport.md)
- [Milestone 03: secure session composition](.spec/milestone-03-secure-session-composition.md)
- [Milestone 04: bidirectional peer establishment](.spec/milestone-04-bidirectional-peer-establishment.md)
- [Milestone 05: LAN discovery and peer scheduling](.spec/milestone-05-lan-discovery-peer-scheduling.md)
- [Milestone 06: logical workspace and pointer handoff](.spec/milestone-06-logical-workspace-pointer-handoff.md)
- [Milestone 07: Follow Active Host keyboard routing](.spec/milestone-07-follow-active-host-keyboard-routing.md)
- [Milestone 08: authenticated device inventory and routing](.spec/milestone-08-authenticated-device-routing.md)
- [Milestone 09: exact-generation multi-peer device routing](.spec/milestone-09-multi-peer-routing.md)
- [Milestone 10: two-host native runtime alpha](.spec/milestone-10-two-host-native-alpha.md)

The evolving engineering decisions live in:

- [Architecture](docs/architecture.md)
- [Protocol](docs/protocol.md)
- [Security](docs/security.md)
- [Platform notes](docs/platform-notes.md)
- [Windows Codex worktree and hardware-validation handoff](docs/windows-codex-worktree.md)

## Initial scope

The first release targets Windows 11 and macOS. It focuses on reliable low-latency keyboard and pointer routing, display-boundary transitions, reconnection, failsafe behavior, per-device routing, and plain-text clipboard synchronization.

Linux support, display streaming, WAN remote control, advanced trackpad gestures, and audio forwarding are outside the initial release scope.

## Contributing

Install the current stable Rust toolchain with the `rustfmt` and `clippy` components. The standard
checks are:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The same checks run on Linux, Windows, and macOS in CI. Native KVM behavior must additionally be
tested on physical Windows and macOS systems; platform-neutral CI cannot validate input
suppression, injection, permissions, or end-to-end latency.
