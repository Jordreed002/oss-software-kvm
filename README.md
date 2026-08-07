# OSS Software KVM

OSS Software KVM is a planned open-source, bidirectional software KVM for Windows 11 and macOS. Its goal is to make computers and their displays feel like one logical workspace: move the pointer across a configured display boundary and keyboard focus follows automatically.

## Intended experience

- Control either host with keyboards, mice, and trackpads attached to either machine.
- Treat Windows monitors and a MacBook display as one configurable workspace.
- Route input according to pointer position without manual hardware switching.
- Preserve safe local control through disconnects, crashes, and an emergency shortcut.
- Keep the native Rust daemon running independently from the control-panel UI.

## Planned architecture

The core will be a Rust Cargo workspace with platform-neutral domain, protocol, routing, topology, networking, security, configuration, and clipboard crates. Native Windows and macOS backends will handle input capture, suppression, injection, and display discovery.

A separate Tauri, React, and TypeScript control panel will configure and monitor the daemon over local IPC. Peer communication will be authenticated and encrypted over the local network.

## Status

This repository is in the specification and project-initialization phase. No working KVM implementation exists yet.

The detailed product and engineering requirements live in:

- [Product and technical specification](.spec/spec.md)
- [Implementation specification](.spec/implementation.md)

## Initial scope

The first release targets Windows 11 and macOS. It focuses on reliable low-latency keyboard and pointer routing, display-boundary transitions, reconnection, failsafe behavior, per-device routing, and plain-text clipboard synchronization.

Linux support, display streaming, WAN remote control, advanced trackpad gestures, and audio forwarding are outside the initial release scope.

## Contributing

The implementation sequence and acceptance criteria are documented in the implementation specification. Contribution guidance will be added once the initial Cargo workspace and development workflow are established.
