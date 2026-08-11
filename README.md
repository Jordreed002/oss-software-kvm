# OSS Software KVM

[![CI](https://github.com/Jordreed002/oss-software-kvm/actions/workflows/ci.yml/badge.svg)](https://github.com/Jordreed002/oss-software-kvm/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust: stable](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform: macOS · Windows](https://img.shields.io/badge/platform-macOS%20%C2%B7%20Windows-lightgrey.svg)](#initial-scope)

OSS Software KVM is a planned open-source, bidirectional software KVM for Windows 11 and macOS. Its
goal is to make computers and their displays feel like one logical workspace: move the pointer across
a configured display boundary and keyboard focus follows automatically.

## Intended experience

- Control either host with keyboards, mice, and trackpads attached to either machine.
- Treat Windows monitors and a MacBook display as one configurable workspace.
- Route input according to pointer position without manual hardware switching.
- Preserve safe local control through disconnects, crashes, and an emergency shortcut.
- Keep the native Rust daemon running independently from the control-panel UI.

## Architecture

The core is a Rust Cargo workspace with platform-neutral domain, protocol, routing, topology,
networking, security, configuration, clipboard, and daemon crates. Native Windows and macOS crates
currently provide device and display discovery, input injection, capability reporting, and safe
unsupported-platform stubs.

A separate Tauri, React, and TypeScript control panel configures and monitors the two-host runtime.
It provides native identity creation, public pairing-card exchange, visual display placement, secure
profile validation, and gate-first start/stop controls. Peer communication is authenticated and
encrypted over the local network.

### Repository layout

```text
.
├── crates/                 # Rust workspace members (platform-neutral + native backends)
│   ├── kvm-input/          #   Platform-neutral input model and state tracking
│   ├── kvm-protocol/       #   Versioned wire protocol and framing
│   ├── kvm-router/         #   Deterministic per-device input routing
│   ├── kvm-topology/       #   Logical display workspace topology
│   ├── kvm-network/        #   Authenticated-stream transport primitives
│   ├── kvm-security/       #   Pairing, peer identity, authorization, credentials
│   ├── kvm-config/         #   Versioned persistent configuration
│   ├── kvm-clipboard/      #   Bounded plain-text clipboard synchronization
│   ├── kvm-daemon/         #   Production daemon lifecycle and safety coordinator
│   ├── kvm-runtime/        #   Fail-closed runtime composition boundary
│   ├── kvm-discovery/      #   Bounded untrusted LAN reachability discovery
│   ├── kvm-diagnostics/    #   Read-only physical-host validation runner
│   ├── kvm-types/          #   Platform-neutral domain types
│   ├── kvm-macos/          #   macOS native backend (input, display, permissions)
│   └── kvm-windows/        #   Windows native backend (input, injection, display)
├── apps/control-panel/     # Tauri + React + TypeScript Link Console UI
├── docs/                   # Evolving engineering decisions
└── .spec/                  # Product, technical, and milestone specifications
```

## Status

The initial engineering foundation is implemented and covered by automated tests. It includes the
shared input path, protocol, routing, topology, configuration, persistent admitted peer sessions,
pairing and authorization state, bounded LAN discovery/peer scheduling, daemon safety state,
logical-workspace pointer handoff, authenticated Follow Active Host keyboard routing, clipboard
synchronization, and native enumeration, observation, and injection surfaces.

An explicit aggregate whole-host alpha capture path now exists for Windows and macOS, together with
exact-session routing, native lifecycle gating, and a fail-closed two-host runtime preparation
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

To try the current Mac/Windows source alpha, follow the
[Link Console setup guide](apps/control-panel/README.md). It replaces the earlier hand-written
profile workflow, while keeping the daemon independent from the UI.

The evolving engineering decisions live in:

- [Architecture](docs/architecture.md)
- [Protocol](docs/protocol.md)
- [Security](docs/security.md)
- [Platform notes](docs/platform-notes.md)
- [Windows Codex worktree and hardware-validation handoff](docs/windows-codex-worktree.md)

## Initial scope

The first release targets Windows 11 and macOS. It focuses on reliable low-latency keyboard and
pointer routing, display-boundary transitions, reconnection, failsafe behavior, per-device routing,
and plain-text clipboard synchronization.

Linux support, display streaming, WAN remote control, advanced trackpad gestures, and audio
forwarding are outside the initial release scope.

## Getting started (development)

Install the current stable Rust toolchain with the `rustfmt` and `clippy` components, then build the
workspace:

```sh
cargo build --locked --workspace
```

To run the Link Console alpha end-to-end (including the `kvm-runtime` sidecar), see the
[Link Console setup guide](apps/control-panel/README.md). macOS requires Accessibility and Input
Monitoring permissions for the runtime; Windows requires the C++ build tools and allows the runtime
on Private networks (TCP port 24800). Mutually negotiated protocol-v3 sessions
also use exporter-authenticated UDP port 24802 for replaceable pointer movement;
stateful input also takes an ordered, acknowledged UDP shadow while TLS remains
the safety fallback. The paced, QoS-marked path and gap/jitter telemetry are
documented in [transport latency hardening](docs/transport-v4-latency-hardening.md).

The emergency escape is **Ctrl + Alt + Shift + Backspace**. Routing is fail-open: if a callback,
session, or native capture path cannot prove that an event was queued safely, that event stays on the
local computer.

## Contributing

Contributions are welcome! Please read the [contributing guide](CONTRIBUTING.md) before opening a
pull request, and note that this project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

The standard checks are:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The same checks run on Linux, Windows, and macOS in CI. Native KVM behavior must additionally be
tested on physical Windows and macOS systems; platform-neutral CI cannot validate input suppression,
injection, permissions, or end-to-end latency.

## Security

Software KVM captures and injects keyboard and pointer input and authenticates peers over your local
network. Please review [docs/security.md](docs/security.md) for the threat model and trust boundary.
Report security-sensitive vulnerabilities privately rather than in a public issue — see
[Reporting a vulnerability](https://github.com/Jordreed002/oss-software-kvm/security/advisories/new).

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
