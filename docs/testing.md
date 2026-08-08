# Testing strategy

## Automated layers

Platform-neutral crates use deterministic unit tests for identifiers, geometry, routing,
normalized edge mapping, key/button state, protocol framing, sequencing, configuration migration,
clipboard loop suppression, client-certificate-enforcing loopback TLS, exporter-bound mutual
admission, and daemon peer reconciliation. Simulated native backends allow daemon and peer
integration tests without capturing the developer's real keyboard or pointer.

Repository checks run on Linux, Windows, and macOS:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Fuzz targets will cover untrusted frame decoding, configuration parsing, and topology operations
once those formats stabilize.

## Physical-host gates

Native milestones require one Windows 11 machine and one supported macOS machine on the same LAN.
Each backend is tested first with capture and injection disabled by default, then with a dedicated
input monitor, and finally through the production daemon.

The observation-only evidence pass uses `cargo run -p kvm-diagnostics -- all
--duration-seconds 30`. See `crates/kvm-diagnostics/README.md` for platform setup, privacy-safe
output, and the complete checklist. The dedicated Windows agent setup, ownership boundary, test
matrix, and evidence template are in `docs/windows-codex-worktree.md`. Detailed payload logging is
opt-in and should not be shared without review.

The safety suite covers emergency release, cable loss, peer process termination, local daemon
termination, permission revocation, held modifiers and buttons, route changes, and rapid boundary
crossings. Every failure must restore local input without the control panel.

## Performance

Development tracing timestamps physical capture, route decision, network send/receive, and
injection request. The latency tool reports percentiles rather than only an average. Input-path
instrumentation is bounded and does not write to disk synchronously.

The initial LAN objective is less than 10 ms capture-to-injection latency with idle CPU close to
zero. Release readiness also requires extended sleep/wake and reconnect soak tests.
