# Windows agent handoff — 2026-08-24

Context file for an agent starting work on the Windows 11 hardware machine.
Read this fully before running anything. Companion documents:
`docs/windows-codex-worktree.md` (lane rules), `docs/platform-notes.md`
(feasibility gates, modifier mapping), `docs/audit/2026-08-24-remediation-loop.md`
(the full audit/fix ledger this file summarizes).

## Baseline

- Branch: **`code-review-remediation`** (34 commits ahead of `main` as of
  `16955e4`-lineage tip; run `git log --oneline main..HEAD | wc -l` after sync
  to confirm you have it all).
- Everything below was developed and verified on macOS. Workspace state:
  clippy clean (`--workspace --all-targets -- -D warnings`, pedantic lints,
  including the `kvm-daemon/diagnostics` feature), 859+ workspace tests green,
  63 panel vitest tests green, 20 panel src-tauri tests green.
- Windows-relevant code **compiles** (cross-checked against
  `x86_64-pc-windows-gnu` where toolchains allowed) but much of it has
  **never executed on real Windows**. That is your lane's primary job.

## Environment

- Rust stable + MSRV floor 1.91 (`rust-toolchain.toml` says stable; CI pins
  the MSRV job to 1.91). C++ build tools are required (the `ring` dependency
  builds native code).
- Ports: TCP 24800 (mTLS session), UDP 24802 (pointer datagrams),
  24801 (diagnostics), named pipe `\\.\pipe\software-kvm-control` (§31 IPC).
  Private-network firewall allowance covers the TCP port.
- Standard checks (same as CI, run these before and after any change):
  `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
  && cargo test --workspace --all-targets` plus the same two commands with
  `--features kvm-daemon/diagnostics`. The control-panel lane:
  `cd apps/control-panel && npm ci && npx tsc --noEmit && npm test && npm run build`
  and `cargo test --manifest-path apps/control-panel/src-tauri/Cargo.toml`.

## What is done (don't redo these)

Everything in `docs/audit/2026-08-24-remediation-loop.md` cycle 1, plus the
feature waves before it. The highlights that touch your machine:

1. **Modifier role mapping (behavior change!)** — destinations now remap
   shortcut modifiers by *role*, default `functional`: Mac Cmd→Windows Ctrl,
   Mac Ctrl→Win; Windows Ctrl→Mac Cmd (inverse). Config:
   `keyboard.modifier_role_mapping` = `functional|positional|identity`
   (config v3; old profiles migrate). Legacy positional behavior is opt-in.
   Tables in `docs/platform-notes.md`.
2. **Protocol v4 semantic input** — `WireMessage::SemanticInput` carries
   resolved shortcut intents + the originating physical press; destinations
   replay native chords with exact teardown; pre-v4 peers fail open to
   physical. Wire gating is triple-layered and tested.
3. **Windows hotplug watcher** (`crates/kvm-windows/src/hotplug.rs`) — hidden
   top-level window thread: `WM_DISPLAYCHANGE` + `WM_DEVICECHANGE` filtered to
   HID interfaces; 200 ms coalescing; lParam validation (window-delivery
   required, header size-checked) after an audit found a forged-thread-message
   dereference; ownership reclaim after wedged startup.
4. **Windows Credential Manager adapter** (`credential_store.rs`) —
   CredReadW/CredWriteW/CredDeleteW, upsert semantics, `Win32_Security_Credentials`
   feature enabled.
5. **Named-pipe IPC** (`kvm-network/src/local_ipc.rs` + daemon
   `control_service.rs`) — §31 commands live (GetStatus/Peers/Devices/Displays/
   Topology, TriggerFailsafe, Enable/DisableKvm) with event push; accept loop
   survives transient errors; panel has a live status card.
6. **Transport hardening** — UDP pointer path drops bad packets instead of
   tearing down; totals rebase past 2^40; adaptive pacing now actually gates
   the wire; reliable reorder buffer no longer wedges on retransmissions;
   keys zeroized; reconnect jitter; DSCP EF on v4 (IPv6 traffic class pending).
7. **Daemon safety** — process panic failsafe (hook + armed manager, now
   installed in the runtime binary the panel spawns), routing-budget watchdog,
   stuck-key reconciliation (runs unconditionally on the tick), failsafe
   audit trail (ring + JSONL via `SOFTWARE_KVM_DATA_DIR`), `EnableKvm` after a
   failsafe trip returns `FailsafeLatched`.
8. **Keymap coverage** — 143 KeyCodes, 152 Windows scan-code arms, media keys
   via consumer page both directions, bijection-proven modifier tables.

## Windows code that has never run — your validation priorities

In priority order. Record each as a dated entry under `docs/validation/windows/`
(follow `TEMPLATE.md`; the 2026-08-08-ms-7d96.md entry shows the format).

1. **Modifier mapping end-to-end** (highest user impact). With a Mac peer:
   Cmd+C/X/V/Z/A/W on the Mac must trigger Copy/Cut/Paste/Undo/SelectAll/Close
   on Windows; Cmd+Shift+Z, right-Cmd, Cmd+Ctrl dual-hold; Option as Alt;
   releases in inverted order (release Cmd before the letter) must not stick.
   Then toggle `positional` and `identity` modes and confirm behavior matches
   the tables. **Check Task Manager hotkeys and elevated apps (UIPI)** —
   injection into elevated processes may fail; note which apps reject it.
2. **NumLock scan code** (`kvm-windows/src/mapping.rs:205` maps NumLock as
   extended `E0 45`; canonical set-1 says base-only). Press NumLock from the
   Mac peer and locally: does the injected toggle work? If not, change to
   `(0x45, false)` and keep the capture-side extended decode as an input quirk.
   This is a one-line fix with an audit trail — you are authorized to land it.
3. **Hotplug watcher**: plug/unplug a USB keyboard, mouse, and monitor;
   change resolution/scale/refresh mid-session; verify `GetDevices`/
   `GetDisplays` over the §31 pipe reflect reality, dock/undock bursts
   coalesce, no leaks across repeated watcher restarts (the macOS lane pinned
   CFRunLoop balance; verify the message-window teardown equivalent).
4. **§31 named pipe**: panel status card against the running runtime; a
   second panel connecting while one is attached (bounded concurrency holds);
   `TriggerFailsafe` releases everything; `EnableKvm` after failsafe returns
   latched (panel shows disabled) until process restart.
5. **Credential Manager**: round-trip put/get/replace/delete under a test
   service name (mirror the macOS keychain test pattern); confirm no
   credentials linger after.
6. **Whole-host capture/injection sanity** (observation only — no suppression):
   key/pointer/scroll events from the Mac arrive, inject, and the Windows
   `listener::tests`-style LAN session holds under load. Note: the macOS lane
   saw its Application Firewall silently drop freshly-built test binaries that
   bind the LAN IP — expect the same class of environment flake on Windows
   Defender/Firewall first runs and record it rather than chasing code.

Standing hardware questions from earlier milestones (secondary): per-device
suppression feasibility (Raw Input ↔ hook correlation — do NOT implement, only
gather evidence per `docs/platform-notes.md`), login-screen behavior (out of
scope, just note), 175 Hz input throughput feel.

## What's left to do (hardware-independent, pick up if idle)

From the cycle-2 queue in the loop record — none of it requires your machine
but all of it compiles/testable anywhere: IPC socket umask window (Linux-relevant),
blocking stale-probe connect, jitter implementation dedup, inbound age-based
key sweep, panel connection cap. Standing feature backlog (layout translation
tables, semantic vocabulary growth, lock-state sync, §32-34 panel pages,
cursor-signal optimizations, cert rotation tooling) is listed in the loop
record; coordinate before starting any of it so the macOS lane isn't
duplicated.

## Rules of engagement

- Lane split per `docs/windows-codex-worktree.md`: you own
  `crates/kvm-windows/**`, Windows validation evidence, and Windows-only
  fixes. Shared crates, CI, specs, and macOS code stay with the primary lane.
- Every behavior claim needs a validation entry with the machine, build SHA,
  and observed evidence. "Works on my machine" without an entry doesn't count.
- If a Windows-only bug is found: fix it in `crates/kvm-windows/**` with a
  test that runs on Windows CI (`windows-latest` runs the full workspace
  suite), keep the Linux CI green (cfg hygiene is enforced by clippy).
- The failsafe chord is **Ctrl+Alt+Shift+Backspace**. Routing is fail-open by
  design: if capture/suppression can't prove an event was queued safely, it
  stays local. Verify the chord actually releases peer-injected modifiers on
  your hardware — that's invariant F-02 and it is test-covered in code but
  never yet on real Windows input stacks.
