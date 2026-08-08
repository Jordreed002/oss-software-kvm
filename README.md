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
pairing and authorization state, daemon safety state, clipboard synchronization, and native
enumeration, observation, and injection surfaces.

Device-aware capture and per-device suppression are deliberately still gated on physical Windows
and macOS validation. No release currently provides working KVM control.

The detailed product and engineering requirements live in:

- [Product and technical specification](.spec/spec.md)
- [Implementation specification](.spec/implementation.md)

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
