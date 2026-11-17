#!/bin/sh
# Software checks only. No physical/native input certification.
set -eu
panel=false
tauri=false
macos=false
for option in "$@"; do
    case "$option" in
        --panel) panel=true ;;
        --tauri) tauri=true ;;
        --macos) macos=true ;;
        --help) printf '%s\n' 'Usage: check-rebuild.sh [--panel] [--tauri] [--macos]' 'Core: focused fmt, locked offline library/integration tests, strict all-target clippy.' 'Panel: existing npm test/build. Tauri: separately excluded crate checks.' 'macOS: strict cross-clippy only for installed Apple targets; never installs.' 'Software checks only; no physical/native input certification.'; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$option" >&2; exit 2 ;;
    esac
done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
# Missing toolchains/components must fail, never trigger rustup installation.
export RUSTUP_AUTO_INSTALL=0
run() { printf '\nRunning:'; printf ' %s' "$@"; printf '\n'; "$@"; }
core() { run cargo "$@" -p kvm-foundation -p kvm-agent-model -p kvm-agent-ipc -p kvm-agent-api -p kvm-agent -p kvm-input-engine; }
printf '%s\n' 'Software checks only; no physical/native input certification.'
run cargo fmt -p kvm-foundation -p kvm-agent-model -p kvm-agent-ipc -p kvm-agent-api -p kvm-agent -p kvm-input-engine -- --check
core test --locked --offline --lib --tests
# Package options must precede the rustc/clippy argument separator.
run cargo clippy --locked --offline -p kvm-foundation -p kvm-agent-model -p kvm-agent-ipc -p kvm-agent-api -p kvm-agent -p kvm-input-engine --all-targets -- -D warnings
if "$macos"; then
    installed=$(rustup target list --installed)
    found=false
    for target in aarch64-apple-darwin x86_64-apple-darwin; do
        case "
$installed
" in
            *"
$target
"*) found=true; run cargo clippy --locked --offline -p kvm-foundation -p kvm-agent-model -p kvm-agent-ipc -p kvm-agent-api -p kvm-agent -p kvm-input-engine --all-targets --target "$target" -- -D warnings ;;
        esac
    done
    if ! "$found"; then printf '%s\n' 'Skipping macOS: no Apple target installed.'; fi
fi
if "$panel"; then
    (cd "$repo/apps/control-panel"; run npm run test; run npm run build)
fi
if "$tauri"; then
    run cargo fmt --manifest-path apps/control-panel/src-tauri/Cargo.toml -- --check
    run cargo test --manifest-path apps/control-panel/src-tauri/Cargo.toml --locked --offline --lib --tests
    run cargo clippy --manifest-path apps/control-panel/src-tauri/Cargo.toml --locked --offline --all-targets -- -D warnings
fi
printf '%s\n' 'Selected software checks passed. Physical/native input certification remains pending.'
