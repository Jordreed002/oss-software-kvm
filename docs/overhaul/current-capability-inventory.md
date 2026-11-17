# Current application capability inventory

Repository evidence for the overhaul comparison, inspected at base `9edb5ed` on 2026-11-17. This inventory describes available code paths, not certification that those paths work on physical hardware.

| Capability | Current implementation | Requirement for the new utility |
| --- | --- | --- |
| Local identity | `setup.rs`: `create_local_identity` | Preserve identity and peer trust across upgrade; keep private material outside webviews |
| Discover and mutually pair | `setup.rs`: request/accept/confirm/decline nearby pairing; `nearby.rs` | Keep mutual verification and explicit expiry/retry states |
| Manual pairing | `setup.rs`: `import_peer_bundle` | Keep a fallback for blocked discovery; never imply discovery proves identity |
| Forget computer | `setup.rs`: `forget_paired_computer` | Define safe stop and local trust removal semantics; do not claim the remote host was also revoked |
| Display placement | `setup.rs`: `finalize_setup`, layout signing and synchronization | Retain individual displays, scale and bounds; support keyboard editing and confirmed revisions |
| Validation | `setup.rs`: `validate_setup`; `kvm-runtime::prepare` | Explain actual blockers without enabling unsafe start |
| Runtime launch | `setup.rs`: `start_runtime`; `main.rs`: `run-managed` | One runtime per user session; attach/relaunch policy and verified binary identity |
| Runtime shutdown | `setup.rs`: `stop_runtime`; runtime stop-file polling | Cleanup before exit; timeout is a visible unresolved shutdown, not success |
| Runtime observation | Setup child state and lock detection; `control.rs`: `control_status` | Reconcile process existence with readiness, freshness, permission and input authority |
| Read control inventory | `control_service.rs`: GetStatus/Peers/Devices/Displays/Topology | Feed one authoritative typed app snapshot; expose no synthetic live data |
| Pause/resume input | Control service supports EnableKvm/DisableKvm | Add actual frontend/native-menu bridge and completion semantics |
| Emergency failsafe | Control service supports TriggerFailsafe; runtime panic hook and emergency chord | Preserve UI-independent recovery and explicit latched-state reporting |
| Change routing/topology live | Protocol has SetDeviceRoute/SetTopology; service returns Internal | Do not render as operational; implement transactions or safe stop/edit/restart |
| Change clipboard live | Protocol has EnableClipboard/DisableClipboard; service returns Internal | Define clipboard policy and implement control semantics before presenting a live toggle |
| Audio routing | Protocol vocabulary exists; service returns Internal | Exclude from initial utility scope |
| Command completion | Control service mutating commands enqueue to owner loop | Queue acknowledgement cannot prove application; add correlated outcome or revision confirmation |
| Diagnostics | `fetch_diagnostics`, dedicated dashboards and metrics | Make troubleshooting on demand; redact exports and stop hidden UI work |
| LAN repair | `setup.rs`: `repair_lan_binding` | Convert developer-oriented repair into a contextual recovery action |
| Permissions | Platform preflight and setup/runtime validation | Dedicated guidance plus revoked-permission handling; validate against packaged signed builds |
| Native credential storage | Security abstraction and platform adapters exist | Integrate with application identity persistence as a separate rollback-safe migration |
| Tray/menu bar | No integration in current Tauri entry point | New native shell, icon/menu, keyboard access, open/close/quit policy |
| Packaging | `tauri.conf.json`: `bundle.active = false` | Installable compatible host/runtime artifacts, signing, startup, update and uninstall |
| Preview mode | `bridge.ts`: in-memory mock outside Tauri | Explicit fixture adapter for design/tests; never silently substitute simulated success in production |

Source paths are relative to the repository: application Rust files are under `apps/control-panel/src-tauri/src`, frontend files under `apps/control-panel/src`, daemon service under `crates/kvm-daemon/src/control_service.rs`, protocol vocabulary under `crates/kvm-protocol/src/control.rs`, and runtime entry point under `crates/kvm-runtime/src/main.rs`.

## Required decisions before implementation

Resolve these against the consolidated proposal rather than implementing contradictory defaults:

- Whether “Pause sharing” gates input only or also clipboard, and whether settings edits require a controlled restart.
- Whether explicit Quit terminates the runtime; closing or dismissing a task window must have a different, documented outcome.
- Whether a pinned widget is initial scope or follows the anchored tray widget.
- Whether one paired peer remains the first release scope, despite lower layers containing multi-peer concepts.
- Whether startup launches only the shell, restores a prior sharing preference after validation, or requires manual resume. A failsafe latch must never disappear into automatic recovery.
- Whether signed automatic updates are initial release scope or follow signed manual installation.

## Validation record to establish

For each scenario record OS/build, host and runtime SHA, peer version, permission state, display topology, direction of routing, action, expected input cleanup, observed cleanup, final app status, and redacted logs.

Cover first install, existing paired upgrade, denied/revoked permissions, both directions of handoff, held key/button during pause/quit, UI/webview crash, native host crash, runtime crash, duplicate launch, peer crash, link blackhole, sleep/wake, LAN change, monitor removal, IPC event loss, interrupted migration, binary mismatch, update rollback, startup disabled, and uninstall. Verify keyboard navigation, screen-reader output, high contrast, reduced motion, text scaling, and focus restoration separately from input safety.
