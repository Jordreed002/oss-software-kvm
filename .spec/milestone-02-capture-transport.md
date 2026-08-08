# Milestone 02 — Observable Native Capture and Persistent Peer Sessions

## Status

Automated implementation completed on 2026-08-08; physical-host acceptance remains pending. This
milestone follows the foundation implemented in the Rust workspace and advances Tasks 7, 10, and
12 from `implementation.md`.

## Objective

Prove that both supported operating systems can produce canonical, device-attributed input
observations, while composing the existing protocol, queue, heartbeat, and reconnect primitives
into a persistent peer-session layer.

This milestone does **not** enable local suppression or claim an operational KVM. Captured events
remain observable only until physical-host testing proves that an event can be suppressed without
guessing its originating device.

## Safety invariants

1. Unknown or ambiguous native events always remain local and are never remotely routed.
2. Events tagged as KVM-injected never enter remote-routing logic.
3. Starting capture must not suppress, seize, or disable a physical device.
4. Capture teardown must be bounded and restore the pre-capture operating-system state.
5. Native callbacks must not perform network I/O, disk I/O, configuration writes, or unbounded
   queue waits.
6. Peer input and clipboard messages are rejected until the transport supplies an authenticated,
   encrypted peer identity that is accepted by the authorization boundary.
7. Queue exhaustion, peer failure, cancellation, and protocol failure are explicit outcomes; no
   ordered keyboard or pointer-button event is silently dropped.

## Workstream A — Windows Raw Input capture

Implement a lifecycle-owned Raw Input observation service in `kvm-windows`.

Required behavior:

- enumerate and retain stable device identity for every Raw Input device handle;
- observe keyboard, relative pointer, button, vertical-wheel, and horizontal-wheel records;
- translate supported records into `kvm-input::InputEvent` without changing their ordering;
- surface explicit `Physical`, `InjectedByKvm`, or `Unknown` classification only when native
  metadata proves the classification;
- refresh device identity when Windows reports device arrival or removal;
- use a bounded, non-blocking handoff from the Windows message-loop callback;
- expose idempotent start/stop lifecycle and explicit already-running/not-running errors;
- keep suppression capability reported as `NotImplemented`.

Raw Input identity and low-level-hook suppression correlation remains a separate feasibility test.
No event may be suppressed based on timing-only correlation in production code.

## Workstream B — macOS IOHID capture

Implement a lifecycle-owned IOHID observation service in `kvm-macos`.

Required behavior:

- schedule an `IOHIDManager` on a dedicated run-loop thread;
- observe keyboard, relative pointer, button, and scroll HID values where the device reports them;
- derive the same stable `DeviceId` used by enumeration;
- translate supported values into `kvm-input::InputEvent` without changing their ordering;
- preserve explicit classification and treat unprovable origin as `Unknown`;
- use a bounded, non-blocking handoff from native callbacks;
- expose idempotent start/stop lifecycle and permission/error diagnostics;
- keep selective suppression unavailable.

An IOHID observation identifies a device, while a Quartz event tap can suppress and inspect the
KVM injection tag but does not reliably expose that device identity. Their correlation remains a
physical-host feasibility test; production code must not infer it from timestamps alone.

## Workstream C — Persistent peer session

Compose `kvm-network` primitives around an `AsyncRead + AsyncWrite` stream whose peer identity has
already been authenticated and whose bytes are already encrypted.

Required behavior:

- maintain explicit connecting, authenticating, connected, degraded, and disconnected states;
- run framed read and priority-aware write paths with bounded cancellation;
- preserve FIFO order within each traffic class and prioritize input over control/background;
- integrate ping, pong, RTT, degradation, disconnect, and reconnect policy;
- gate input and clipboard dispatch on authenticated identity and authorization;
- surface queue-full, remote-close, invalid-frame, timeout, and shutdown outcomes;
- provide an adapter boundary for later TCP/rustls and credential-store integration;
- permit explicit development addresses without providing a plaintext production bypass.

mDNS, certificate issuance, native credential persistence, and socket/rustls adapters are the next
security integration milestone. Discovery never implies authorization.

## Automated acceptance

The repository must pass:

```text
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p kvm-windows --target x86_64-pc-windows-gnu --all-targets -- -D warnings
cargo clippy -p kvm-macos --target aarch64-apple-darwin --all-targets -- -D warnings
```

Tests must cover native-record translation, device lifecycle, bounded handoff behavior, start/stop
state, peer state transitions, pre-auth rejection, ordered delivery, priority scheduling,
heartbeat timeout, reconnect reset, remote closure, and clean shutdown.

## Physical-host acceptance

Automated cross-compilation does not complete this milestone. On physical Windows 11 and macOS
hosts, record:

- built-in and external device identities before and after reconnect/reboot;
- key, pointer, button, and wheel observations with no local suppression;
- whether KVM-tagged injected events appear in each capture API;
- permission denial/revocation behavior;
- CPU usage while idle and callback-to-observer latency under load;
- device arrival/removal and sleep/wake behavior.

Only after this evidence exists may a follow-up milestone design selective suppression and connect
capture to remote routing.

Use the read-only `kvm-diagnostics` runner to collect this evidence. It must always return
`AllowLocal` from its capture callback, default to payload-redacted event summaries, stop after a
bounded duration, and never alter routes or enable suppression.

The Windows physical-host pass uses the isolated worktree, Codex prompt, ownership boundary, and
report template in `docs/windows-codex-worktree.md`. Its branch may produce an evidence-only commit;
shared API changes and suppression experiments remain outside that worktree.

## Explicitly deferred

- production local suppression;
- timing-only correlation between unrelated native event streams;
- mDNS and concrete TLS credential provisioning;
- startup agents and native credential-store adapters;
- daemon IPC and the Tauri control panel;
- clipboard platform watchers;
- audio and advanced gestures.
