# Rust rebuild reuse register

Initial register, 2026-11-17. No legacy component is accepted for reuse yet. Candidates below are source-inspection leads; native behavior and performance remain unmeasured. Base reference: `9edb5ed`, with the current overhaul branch retaining the legacy build for comparison.

| Candidate | Source | Contract to preserve | Evidence and work before acceptance | Decision |
| --- | --- | --- | --- | --- |
| Functional modifier maps | `crates/kvm-windows/src/mapping.rs`, `crates/kvm-macos/src/native/mapping.rs` | Role mapping, left/right distinction, exact chord teardown | Pure test coverage plus physical shortcut/release matrix in both directions; audit dependencies before extraction | Candidate |
| Layout geometry | `crates/kvm-topology/src` | Finite coordinates, deterministic seams, explicit edges and epochs | Legacy library tests pass locally; new contract/differential cases, multi-monitor physical evidence and routing benchmark needed | Candidate |
| Physical key/semantic vocabulary | `crates/kvm-input/src` | Stable physical identity and explicit semantic behavior | Legacy library tests pass locally; decide new domain contract without pulling old orchestration; validate unsupported usages | Candidate |
| Local framing | `crates/kvm-protocol/src/control.rs` | Bounds before allocation and independent local protocol version | Existing queue acknowledgement is insufficient for new command semantics; endpoint authorization reviewed separately; new schema and parser tests required | Candidate, redesign DTOs |
| OS credential adapters | `crates/kvm-windows/src/credential_store.rs`, `crates/kvm-macos/src/keychain.rs` | Secret ownership, lifetime, store errors and redaction | Native store tests, interruption-safe migration, signed identity and rollback evaluation required | Candidate |
| TLS/session primitives | `crates/kvm-security/src`, `crates/kvm-network/src` | Authenticated peer identity, exact session, replay/order limits | Legacy security library tests pass locally; new transport boundaries, dependency audit, enrollment review and production-path performance tests required | Candidate |
| Legacy runtime composition | `crates/kvm-runtime/src/active.rs`, `apps/control-panel/src-tauri/src/setup.rs` | Behavioral requirements only | Monolithic composition is not a reuse target. Write new owners and contracts; use legacy behavior to build regression scenarios | Replace |

For every accepted component add source revision, exact retained files/symbols, license, reviewer, dependency impact, test commands/results and benchmark artifacts. Source-level tests are not physical latency, Windows/macOS permission or hardware acceptance evidence.

## Initial baseline check

Coordinator ran `cargo test -p kvm-router -p kvm-topology -p kvm-input -p kvm-security --lib` on Windows on 2026-11-17. All four library suites passed. This establishes a limited legacy regression reference; it does not cover the full workspace or native input stacks. No new capture engine was activated.
