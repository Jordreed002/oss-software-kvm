#!/bin/sh
# Dev runner for the two-host KVM stack.
#
# Usage:
#   scripts/dev.sh          # build + (re)start the stack once
#   scripts/dev.sh watch    # hot-reload: rebuild + restart whenever a
#                           # workspace crate changes
#
# Why the whole stack restarts: the panel spawns target/release/kvm-runtime
# as a managed child, so a rebuilt daemon needs the panel to respawn it.
# Workspace-crate changes are invisible to `tauri dev` (it only watches
# src-tauri), so this watcher covers them and bounces the stack the same way
# tauri would for its own sources.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PANEL_DIR="apps/control-panel"
RUNTIME_BIN="target/release/kvm-runtime"
DEV_LOG="/tmp/kvm-dev.log"
MARKER="target/.dev-watch-marker"

log() { printf '[dev] %s\n' "$*"; }

stop_stack() {
    pkill -f software-kvm-control-panel 2>/dev/null || true
    pkill -f 'kvm-runtime run-managed' 2>/dev/null || true
    pkill -f 'tauri dev' 2>/dev/null || true
    # A killed tauri dev can leave vite holding port 1420.
    lsof -nP -tiTCP:1420 -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
    sleep 1
}

build_runtime() {
    log "building $RUNTIME_BIN ..."
    cargo build --release -p kvm-runtime
}

# Stable code-signing identity keeps macOS TCC grants (Accessibility, Input
# Monitoring) alive across rebuilds; unsigned binaries silently lose them.
sign_binaries() {
    identity=$(security find-identity -v -p codesigning |
        sed -n 's/^.*[0-9A-F]\{40\} "\(.*\)"$/\1/p' | head -1)
    [ -n "$identity" ] || return 0
    for binary in \
        "$RUNTIME_BIN" \
        target/debug/software-kvm-control-panel \
        target/debug/kvm-runtime \
        apps/control-panel/src-tauri/target/debug/kvm-runtime \
        apps/control-panel/src-tauri/target/debug/software-kvm-control-panel
    do
        [ -x "$binary" ] &&
            codesign --force --sign "$identity" "$binary" >/dev/null 2>&1 || true
    done
    log "signed binaries with: $identity"
}

launch() {
    log "starting stack (log: $DEV_LOG)"
    : >"$DEV_LOG"
    (cd "$PANEL_DIR" && nohup npm run dev:desktop >>"$DEV_LOG" 2>&1 &)
    activate_daemon
}

# Mirrors the panel's start_runtime command (apps/control-panel/src-tauri/
# src/setup.rs): write `run` to the control file, then spawn the managed
# runtime. The panel only spawns the daemon from its UI toggle, so doing it
# here makes `once` and post-rebuild `watch` restarts hands-free.
activate_daemon() {
    service_dir="$HOME/Library/Application Support/dev.software-kvm.control-panel"
    [ -f "$service_dir/runtime.toml" ] || {
        log "no provisioned profile yet - enable KVM in the panel once"
        return 0
    }
    sleep 5 # let the panel finish binding its local IPC endpoint first
    printf 'run\n' >"$service_dir/runtime.control"
    rm -f "$service_dir/runtime.status"
    log "activating managed runtime"
    SOFTWARE_KVM_DATA_DIR="$service_dir" SOFTWARE_KVM_DEV_LOG=1 \
        nohup "$RUNTIME_BIN" run-managed \
        "$service_dir/runtime.toml" "$service_dir/runtime.control" \
        >>"$service_dir/runtime.log" 2>&1 &
}

changed_sources() {
    find crates "$PANEL_DIR/src-tauri/src" \
        \( -name '*.rs' -o -name 'Cargo.toml' \) \
        -newer "$MARKER" -print 2>/dev/null | head -1
}

case "${1:-once}" in
once)
    stop_stack
    build_runtime
    sign_binaries
    launch
    ;;
watch)
    touch "$MARKER"
    log "watching workspace crates for changes (ctrl-c stops)"
    while :; do
        if [ -n "$(changed_sources)" ]; then
            # Debounce editor save bursts: wait for writes to settle.
            sleep 3
            stop_stack
            if ! build_runtime; then
                log "BUILD FAILED - fix errors; stack stays down until clean"
                touch "$MARKER"
                while :; do
                    sleep 2
                    [ -z "$(changed_sources)" ] && continue
                    touch "$MARKER"
                    break
                done
                continue
            fi
            touch "$MARKER"
            sign_binaries
            launch
        fi
        sleep 1
    done
    ;;
*)
    echo "usage: scripts/dev.sh [once|watch]" >&2
    exit 1
    ;;
esac
