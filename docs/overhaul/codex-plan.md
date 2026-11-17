# Codex application overhaul proposal

Independent proposal by the coordinating Codex agent, prepared on 2026-11-17 against `9edb5ed`. Status: proposed, awaiting comparison and user sign-off. Branch: `overhaul/widget-app-planning`.

## Product decision

Rebuild the daily application experience around a native tray/menu-bar entry and a compact control widget. Replace the frontend composition, application state model, and desktop lifecycle integration. Retain the Rust input engine initially, audit its integration boundaries, and replace individual subsystems only when acceptance evidence justifies it. A fresh UI should not require re-proving every input-routing invariant at once.

The everyday question is “Which computer am I controlling, and is sharing safe and ready?” The widget answers that immediately. Setup and troubleshooting remain available as focused task windows. The application should feel like a small operating-system utility rather than a monitoring console.

The alternative is a complete engine rewrite. Its benefit is freedom to simplify accumulated boundaries. Its cost is simultaneous uncertainty in capture, suppression, injection, reconnection, trust, and UI lifecycle. There is no repository evidence yet that replacing those algorithms solves the requested experience. Inventory and benchmark first; authorize a replacement only against a specific deficiency.

## Verified starting point

- `apps/control-panel/src-tauri/tauri.conf.json` creates a single 1180 by 790 window and disables bundling. This is not currently a packaged background utility.
- `apps/control-panel/src-tauri/src/lib.rs` registers setup commands plus a read-only control-status bridge. Tray integration and an explicit exit policy are absent there.
- `apps/control-panel/src/App.tsx` combines setup progression, pairing, arrangement, runtime readiness, and diagnostics entry. It polls setup state every 400 or 1200 ms in later setup stages.
- `apps/control-panel/src-tauri/src/setup.rs` owns persisted setup, nearby pairing, configuration generation, validation, diagnostics, and a `Mutex<Option<Child>>`. `start_runtime` launches `kvm-runtime run-managed`; `stop_runtime` writes a stop file and waits up to 15 seconds. Runtime-lock detection also handles a process the current UI did not launch.
- `crates/kvm-runtime/src/main.rs` installs the panic hook, holds a managed-runtime lock, handles shutdown signals, and checks the managed stop file every 250 ms.
- `crates/kvm-daemon/src/control_service.rs` already has bounded command/event channels and snapshots. Its existence does not make all setup/configuration commands available to the frontend.
- `apps/control-panel/src-tauri/capabilities/default.json` currently grants `core:default` to `main`. Multiple windows and plugin commands need a deliberate capability map.
- `docs/audit/2026-08-24-remediation-loop.md` and `docs/windows-agent-handoff-2026-08-24.md` contain unresolved integration and physical-validation work. Existing documentation mixes intended architecture with implementation checkpoints, so code is the deciding evidence.

## Proposed interaction model

### Tray and widget

Use the Windows notification area and macOS menu bar, not an embedded Windows taskbar toolbar. Single activation opens an anchored widget, approximately 360 by 420 logical pixels, expanding vertically for errors and text scaling. Native context actions remain available without creating a webview: Open controls, Pause sharing, Settings, Troubleshoot, Quit Software KVM.

The widget has a compact identity row, an explicit state sentence, the paired computer, a simple two-computer workspace sketch, and one primary action. Use “Sharing ready”, “Controlling MacBook”, “Paused”, or “Connection lost” only when the runtime can substantiate them. Do not present an “active computer” selector until the backend supports safe explicit ownership transfer; the current automatic edge handoff remains the initial mechanism.

The primary control is Pause sharing / Resume sharing. Pausing disables remote input and reconciles held state without discarding trust or stopping discovery. Clipboard policy must be explicit. Recommend that Pause sharing pauses both input and clipboard, with independent clipboard preference in Settings. Resume is unavailable while failsafe is latched; offer an explicit safe recovery flow instead.

Dismissal returns focus to the prior application. Opening the widget must not change the KVM input destination. Esc dismisses; keyboard activation and a native menu provide alternatives to pointer use. No hover-only essential controls. Tray state includes shape and accessible text, not color alone.

An optional pinned widget can follow after the anchored widget works on both platforms. It should not be always on top by default. Position must survive normal restarts and recover visibly when its monitor disappears.

### Focused task windows

1. First launch opens a compact, resizable setup window rather than the widget. Identify this computer, explain and check permissions, discover and mutually verify the peer, arrange displays, test the boundary, then choose launch-at-login. Pairing expiry, peer refusal, blocked discovery, and manual public-bundle exchange have named recovery paths. Never auto-approve a nearby peer.
2. Settings contains Computers, Displays, Keyboard and clipboard, Startup, and About. Preserve multiple display geometry and modifier mapping; provide a keyboard arrangement alternative to dragging. Invalid edits remain drafts. Applying a change may safely pause and restart the runtime until a transactional live-update contract exists.
3. Troubleshoot opens only on request or a useful error action. Show the actual blocker, the next repair step, and expandable technical details with redacted export. Keep high-frequency charts out of the default widget.

### Visual direction

Propose a quiet instrument panel: graphite and warm off-white themes, a small teal readiness accent, amber recovery states, clear separators, compact but readable spacing, and a custom two-host connection mark. Use one readable bundled sans family, restrained numeric text, crisp icons, and short state transitions. No decorative animated charts or large marketing typography. Native accessibility and contrast requirements override decorative consistency.

## Proposed architecture

Keep Tauri 2, React 19, TypeScript, Vite, and Rust as the first implementation baseline. A framework replacement adds migration work without a demonstrated user benefit. Introduce small frontend feature modules and one application-state store driven by a typed client adapter. Components render domain state, not process guesses.

The Tauri Rust host owns the tray, task windows, lifecycle coordinator, and a control-client connection. It must remain useful when every webview is closed. The runtime owns input authority and peer state. Extract setup orchestration from the large `setup.rs` into identity, pairing, profile, runtime-controller, and diagnostics services with explicit dependencies. Avoid creating a second general-purpose daemon just to coordinate the UI.

Use a per-user runtime, not a privileged Windows service or system macOS daemon in the initial overhaul. Session input and macOS permission behavior need physical validation before any stronger service model. Login-screen control and injection into elevated Windows applications remain separate platform questions, not promised capabilities.

A resident native host supervises one runtime per user session. “Close window” hides or destroys its webview but leaves the native host and runtime alive. Explicit Quit stops sharing, requests held-input cleanup and graceful runtime exit, verifies termination, then exits the host. A timeout shows a failure with a safe recovery choice rather than silently claiming shutdown. A host crash does not make the input engine depend on webview liveness. Relaunch attaches to the existing runtime by validated instance identity, never by PID alone. Runtime crashes leave sharing stopped; restart can be offered with explicit state, and a latched failsafe never automatically resumes.

### Contract and ownership migration

Define one versioned local app contract with instance identity, capabilities, snapshot revision, runtime lifecycle, readiness blockers, peer health, input authority, failsafe latch, config revision, and command results. Reuse existing bounded IPC transport; do not casually change the inter-peer input protocol to support UI state.

Commands need correlation identifiers, deadlines, explicit unsupported responses, and authoritative resulting revisions. Acknowledging queue admission is not acknowledging application. Distinguish desired, pending, confirmed, failed, and unknown state. Repeated user actions must be idempotent or rejected as already in progress. Reconnect obtains a fresh snapshot before subsequent deltas; gaps invalidate the local state until resynchronized. Unknown or stale state disables unsafe mutations and reports “Status unavailable”.

Initially adapt existing setup and control commands behind this contract. Then move durable ownership deliberately, service by service. Never let old setup files and the new runtime independently overwrite trust or topology. Keep an explicit capability matrix covering status, pause/resume, failsafe, peers, pairing, layout, settings, and shutdown. Add missing commands in the runtime owner loop or route through a safe stop/edit/validate/restart transaction.

## Safety and trust

Keep capture callbacks independent of UI, logs, disk I/O, or IPC backpressure. Preserve exact-session held-input accounting, emergency chord, panic gate, bounded queues, and local fallback on lost authority. Revisit outstanding IPC permission and connection-limit findings before making the control endpoint the resident application's main interface. Authenticate and authorize local clients using platform-supported user identity and endpoint access controls; schema validation is not authorization.

Stage identity migration separately from layout/settings migration. Preserve peer IDs and trust, integrate existing native secret-store adapters with rollback-safe writes, and never log private keys or clipboard contents. Migration prepares a backup, validates a new profile, commits atomically, and retains the last working profile. A secret-store failure leaves the old identity usable or blocks with an explicit recovery path. Backups require restrictive permissions and a retention policy.

## State and recovery requirements

Represent process lifecycle, pairing, permissions, transport, authority, user pause, and failsafe as separate state dimensions. Derive one user-facing summary through tested precedence: failsafe or unsafe permission state first, explicit pause next, connection readiness last. A running process alone never means sharing is ready.

Cover empty setup, waiting for peer, unverified identity, outdated peer, permission revoked, stale control state, runtime absent, runtime fault, display removed, network address changed, sleep/wake, and failed update. Notifications occur on actionable transitions, not each retry. Suppress repeat alerts while retaining a visible recovery action. Runtime safety precedes UI notifications.

## Delivery phases and acceptance gates

1. **Evidence and design contract.** Record current builds and physical two-host behavior; inventory all existing user actions and commands; produce approved widget/setup/settings mockups plus lifecycle and state tables. Gate: every current capability has a destination, defer decision, or removal approval; no unowned shutdown path.
2. **Native shell and lifecycle spike.** Add tray/menu-bar operation, single instance, anchored window positioning, close/hide behavior, and explicit shutdown to a vertical slice. Gate: 100 open/close cycles without duplicate processes or leaked connections; usable at 100%, 150%, and 200% scaling; secondary-monitor removal recovers onscreen. No automatic remote input during a spike.
3. **Control contract and services.** Implement typed snapshots, commands, event subscription, capability negotiation, backpressure, and reconnect. Extract backend orchestration incrementally. Gate: injected delays, duplicate commands, stale revisions, event gaps, and old/new binary combinations produce explicit safe states; closing every webview leaves routing stable.
4. **New daily UI.** Replace the old ready screen with the widget, implement tray-native pause and recovery actions, add theming and keyboard navigation. Gate: UI state matches runtime confirmations in success, disconnection, and failsafe scenarios; hidden webviews stop polling and animation.
5. **Setup, settings, migration.** Rebuild permission guidance, mutual pairing, display arrangement, mapping and clipboard preferences, config transactions, secret migration, and troubleshooting. Gate: clean install and existing paired install work on both OSes; interrupted migration restores the prior working configuration; all former supported actions have parity or approved deferral.
6. **Packaging and release candidate.** Bundle host and runtime as a compatible versioned pair; sign and notarize where required; add opt-in login startup, manual update first, uninstall cleanup, and redacted diagnostics. Gate: install/update/restart/rollback/uninstall matrix passes on physical Windows and macOS. No automatic update while remote input is active; pause, clean up, update, then revalidate.
7. **Soak and default cutover.** Keep the old frontend available to developers during migration, then remove it after parity. Gate: eight-hour two-host run, repeated disconnect/sleep/display changes, verified emergency chord both ways, no stuck keys or suppressed local input after shutdown. Release notes list supported platform limitations.

Each phase should be reviewable independently. Do not promise calendar estimates before the lifecycle spike and baseline measurements.

## Proposed quality budgets

These are targets to validate on named reference machines, not current measurements. Visible widget from warm tray activation: p95 under 150 ms. UI state change after a runtime acknowledgement: p95 under 250 ms. Hidden host with no active setup/diagnostics: average under 0.5% of one CPU core over ten minutes. Record host, runtime, and webview memory separately; establish a ceiling from measured platform baselines rather than claiming a universal RAM target. Input-path p95 and p99 latency must stay within the approved baseline regression budget; choose the numeric tolerance after noise measurement in phase one.

Automate state reducer/contract tests, runtime lifecycle tests, pairing and migration integration tests, and critical keyboard UI flows. Keep existing Rust safety suites and panel backend coverage. Physical tests must include both directions, held modifiers during pause/quit, peer crash, local runtime crash, host UI crash, network blackhole, denied/revoked permissions, high-DPI and multiple monitors, VoiceOver/Narrator, reduced motion, and high contrast. Synthetic UI mocks cannot certify native input safety.

## Principal weaknesses of this proposal

Retaining Tauri and the core constrains a completely fresh architecture; the benefit must be checked against real lifecycle problems rather than assumed. A resident host is simpler than OS service installation but still needs crash/relaunch and autostart evidence. Event-driven state is more work than polling and requires careful resynchronization. Separate task windows are more usable for setup but may exceed a literal single-widget product interpretation. Native secret migration and packaging could dominate the UI work unless phased carefully.

## Sign-off choices

Recommend approving a complete frontend and application-shell rebuild with selective core refactoring, tray/menu-bar as the default home, focused setup/settings windows, one paired peer initially, Windows and macOS parity, opt-in login startup, and explicit Quit that stops sharing. Defer optional pinned widget until the shell gate; defer new platforms, WAN, video, privileged services, and a full input-engine rewrite. Ask the user to confirm this scope and visual direction after comparing the independent proposals.

## External implementation references

Tauri documents [native tray support](https://v2.tauri.app/learn/system-tray/), [window close events](https://v2.tauri.app/reference/javascript/api/namespacewindow/), [autostart integration](https://v2.tauri.app/plugin/autostart/), and [signed updater artifacts](https://v2.tauri.app/plugin/updater/). These establish available mechanisms, not proven behavior of this application. Validate the shipped dependency versions and platform behavior during the lifecycle spike.
