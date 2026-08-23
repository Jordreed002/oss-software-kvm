# Local development tasks mirroring CONTRIBUTING.md and CI
# (.github/workflows/ci.yml). Requires `just` (https://github.com/casey/just),
# a stable Rust toolchain with rustfmt and clippy, and Node.js 20+ for the
# control-panel recipes.

default:
    @just --list

# Format all Rust code (CI checks the same thing with --check).
fmt:
    cargo fmt --all

# Lint the workspace with warnings denied (default features).
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Lint the workspace with the dev-only diagnostics feature enabled, matching CI.
clippy-diagnostics:
    cargo clippy --workspace --all-targets --features kvm-daemon/diagnostics -- -D warnings

# Run the test suite (default features).
test:
    cargo test --workspace --all-targets

# Run the test suite with the dev-only diagnostics feature enabled, matching CI.
test-diagnostics:
    cargo test --workspace --all-targets --features kvm-daemon/diagnostics

# Type-check and build the control-panel frontend (tsc && vite build).
panel:
    cd apps/control-panel && npm run build

# Run the three enforced checks from CONTRIBUTING.md: fmt --check, clippy, test.
check:
    cargo fmt --all --check
    just clippy
    just test

# Everything CI runs for the Rust workspace (both feature sets), minus the
# control-panel build and native-platform matrix. Run before opening a PR.
ci: check
    just clippy-diagnostics
    just test-diagnostics

# Verify dependencies against deny.toml (advisories, licenses, bans, sources).
deny:
    cargo deny --manifest-path Cargo.toml check

# Build docs with warnings denied, matching the CI docs job.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
