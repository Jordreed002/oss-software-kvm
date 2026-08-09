# Contributing to OSS Software KVM

Thanks for your interest in improving OSS Software KVM! This guide explains how to set up a local
build, run the same checks CI runs, and land a change. The project is an early engineering alpha, so
most work targets the Rust workspace or the Tauri/React control panel.

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Table of contents

- [Ways to help](#ways-to-help)
- [Development setup](#development-setup)
- [Building and running](#building-and-running)
- [Code quality checks](#code-quality-checks)
- [A note on hardware testing](#a-note-on-hardware-testing)
- [Commit messages](#commit-messages)
- [Pull requests](#pull-requests)
- [Reporting bugs](#reporting-bugs)

## Ways to help

- **Platform backends** — input injection, display enumeration, and capture on Windows and macOS.
- **Routing and topology** — pointer handoff, per-device routing, and multi-monitor correctness.
- **Control panel** — the Tauri/React/TypeScript Link Console in `apps/control-panel`.
- **Tests and validation** — the platform-neutral test suite grows continuously; new edge-case
  tests are always welcome.
- **Documentation** — `docs/` and `.spec/` track the evolving design.

If you're planning a large change, please open an issue first so we can discuss scope and approach
before you invest significant time.

## Development setup

You need the stable Rust toolchain (with `rustfmt` and `clippy`) and Node.js 20 or newer. The
toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

```sh
# Rust workspace
rustup show          # installs the pinned stable toolchain

# Control panel (apps/control-panel)
cd apps/control-panel
npm ci
```

Platform prerequisites for native backends:

- **macOS** — Xcode Command Line Tools. Before routing input, grant the built `kvm-runtime`
  Accessibility and Input Monitoring permissions under **System Settings → Privacy & Security**.
- **Windows 11** — Visual Studio Build Tools with the *Desktop development with C++* workload.
  WebView2 ships with Windows 11. Allow the runtime on **Private networks** if Windows Firewall
  prompts when it first listens on TCP port 24800.

## Building and running

```sh
# Build the entire Rust workspace
cargo build --locked --workspace

# Run the Link Console (finds target/release/kvm-runtime by default)
cargo build --locked -p kvm-runtime --release
cd apps/control-panel
npm run dev:desktop     # = tauri dev
```

Set `SOFTWARE_KVM_RUNTIME` to an absolute runtime path to point the console at a different build.
See the [Link Console setup guide](apps/control-panel/README.md) for full pairing instructions.

## Code quality checks

These three commands run on Linux, Windows, and macOS in CI. They must pass before a pull request is
merged:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The workspace denies `unsafe_code` and enables `clippy::pedantic` — see the `[workspace.lints]`
table in [`Cargo.toml`](Cargo.toml). Match the surrounding style: no `unsafe`, exhaustive match
arms, and `#[must_use]` where the existing crates use it.

For the control panel, type-check and build the frontend before opening a PR:

```sh
cd apps/control-panel
npm run build      # tsc && vite build
```

## A note on hardware testing

Platform-neutral CI **cannot** validate native KVM behavior — input suppression, injection,
permissions, secure-desktop/UIPI boundaries, or end-to-end latency. If your change touches a native
backend (`kvm-macos`, `kvm-windows`), capture/suppression, or the runtime session pump, please note
in your PR description what was tested on physical hardware and what still needs validation, so a
maintainer can schedule the physical acceptance pass.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Use a lowercase type
and, where helpful, a scope matching the crate or area:

```
<type>(<scope>): <imperative summary>
```

Examples from the history of this repo:

```
fix(router): fail-closed on a nil workspace host
feat(control-panel): synchronize paired display maps
fix(macos): bound whole-host callback with a 100ms tap-dispatch watchdog
docs: harden and document remaining audit findings
fix(ci): resolve platform-specific clippy failures
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`. Keep the summary under
~72 characters and reference an issue number in the body when applicable.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make your change with focused commits following the convention above.
3. Ensure all three Rust checks pass locally, plus `npm run build` for control-panel changes.
4. Open a pull request against `main` and fill in the PR template.
5. New, user-facing behavior should include tests; documentation changes should update the relevant
   `docs/` or `.spec/` page.

Keep PRs scoped — one logical change per PR makes review faster and reduces risk to the fail-closed
runtime path.

## Reporting bugs

Open a [GitHub issue](https://github.com/Jordreed002/oss-software-kvm/issues/new/choose) and pick the
bug report template. Include the OS and version, the Software KVM build, the two-host arrangement,
and the exact steps that reproduce the problem.

Software KVM captures and injects keyboard and pointer input. If you have found a vulnerability that
could leak input, bypass authentication, or escape suppression, **do not open a public issue** —
report it privately via
[GitHub Security Advisories](https://github.com/Jordreed002/oss-software-kvm/security/advisories/new).
See [docs/security.md](docs/security.md) for the threat model.
