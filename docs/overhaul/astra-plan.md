# Software KVM as a desktop utility

Independent design plan, 17 November 2026. Planning only. Inspected checkout `overhaul/widget-app-planning` at `9edb5ed`, the supplied remediation base. No other overhaul proposals were read. No implementation or native execution was performed. This document requires approval as part of the consolidated plan before implementation.

## Evidence and limits

The following are verified source facts, not claims that installed builds pass hardware validation. Paths are repository-relative.

| Area | Verified source evidence | Consequence |
| --- | --- | --- |
| Desktop shell | `apps/control-panel/src-tauri/tauri.conf.json` opens a 1180 by 790 window with a 760 by 640 minimum; bundling is disabled. `src-tauri/src/lib.rs` registers setup commands and one control-status command, with no tray lifecycle wiring. | A smaller CSS layout alone cannot deliver the requested utility. |
| Runtime owner | `apps/control-panel/src-tauri/src/setup.rs` holds `Mutex<Option<Child>>`, launches `kvm-runtime run-managed`, writes a stop file, and waits up to 15 seconds. `runtime_binary` accepts an environment override, sibling executable, or workspace release executable. | Production launch, ownership, recovery, and installed binary discovery need explicit contracts. |
| Executable distinction | `crates/kvm-daemon/src/main.rs` describes itself as a lifecycle skeleton with random identities. `crates/kvm-runtime/src/main.rs` is the managed entry point, installs the panic failsafe, acquires an exclusive lock, and polls the stop file every 250 ms. | Keep the actual runtime composition; do not accidentally ship the skeleton as the background agent. |
| Runtime composition | `crates/kvm-runtime/src/active.rs` assembles peer management, workspace control, native capture state, diagnostics and local control. Its failsafe test verifies that enabling KVM cannot clear a latched failsafe. | Runtime state and safety authority belong here, outside the renderer. |
| IPC | `crates/kvm-daemon/src/control_service.rs` offers snapshots, events and queued enable/disable/failsafe commands. Topology, device-route, clipboard and audio mutations return `Internal`. Acknowledgment means queue acceptance. `apps/control-panel/src-tauri/src/control.rs` projects only part of live status. | Product controls must be capability-driven and distinguish acceptance from completion. |
| Setup and persistence | `setup.rs` owns stored setup, identities, profile generation, layout signatures, LAN repair and runtime-status-file interpretation. `crates/kvm-config/src/store.rs` supplies a separate durable config abstraction and backups; `migrate.rs` migrates earlier TOML versions and rejects future versions. | Consolidate writers without discarding migration and validation work. |
| Pairing | `apps/control-panel/src-tauri/src/nearby.rs` implements expiring request/accept/confirm/decline sessions and cleartext UDP pairing packets. Its commentary describes operator confirmation and certificate pinning. `setup.rs` verifies signed workspace and acknowledgment messages. | Preserve expiration and explicit consent, but independently review initial identity authentication. Certificate pinning after enrollment does not by itself establish that enrollment was authentic. |
| Permissions | `crates/kvm-macos/src/native.rs` preflights Accessibility and Input Monitoring. `crates/kvm-runtime/src/main.rs` has a native diagnostic path. `apps/control-panel/src-tauri/Info.plist` declares local-network purpose and Bonjour service types. | Permissions must refer to the installed process that captures input. A renderer checkbox cannot prove permission readiness. |
| Frontend | `apps/control-panel/src/App.tsx` combines setup, runtime and monitoring, polls at 400 or 1200 ms, and stops the runtime before editing arrangement. `bridge.ts` includes browser preview behavior. `DiagnosticsDashboard.tsx` separately polls diagnostics. | Rebuild navigation and state consumption; retain useful layout geometry and diagnostic presentation selectively. Preview data must never masquerade as installed runtime health. |
| Delivery | `.github/workflows/ci.yml` covers Rust, frontend and separate desktop Rust checks. The Tauri crate has its own manifest. Bundling is disabled in the inspected shell configuration. | These checks are valuable but do not establish signed installer, update, uninstall, login or permission continuity. |
| Performance | `docs/performance-budget.md` explicitly leaves latency targets unmeasured pending physical runs and identifies cross-host clock alignment limitations. | Do not sell a latency number derived from local timestamps or simulated charts. |

Source inspection did not establish the full local IPC authorization policy, crash cleanup on every OS path, actual signed-app permission behavior, or update infrastructure. These are validation tasks, not presumed vulnerabilities or completed features.

## Product principles and scope

The product should answer three practical questions immediately: where input goes, whether sharing is active, and how to return control locally. Opening a dashboard should never be necessary to pause sharing.

Proposed first release stays within the current two-computer, local-network model. One paired computer can have multiple displays. Do not imply arbitrary multi-peer switching, audio, per-device routing or working clipboard controls until their runtime capabilities are implemented and verified. Keep clipboard off for the first utility release unless separately approved and validated.

Closing a window hides it. Pausing sharing restores local input while keeping the utility available. Quitting stops sharing and exits the utility. Starting at login and automatically resuming sharing are separate choices, both explained at setup. Default to login startup off and explicit first activation.

State claims must come from the runtime. An accepted Start command shows “Starting” until capture, permissions, topology and session readiness are confirmed. “Connected” never doubles as “controlling this computer.”

## Concrete windows and interaction

### Tray or menu-bar entry

Use a monochrome template icon with a shape or badge distinction for sharing, paused and attention. The tooltip and accessible name include status and input destination. Left click opens the widget; the platform context menu provides Open, Pause or Resume, Return input here, Settings, Help, and Quit Software KVM. Every action routes through the same command client.

The native menu remains usable if the webview fails. A second application launch reveals the existing widget. Position the widget against the invoking icon where supported, otherwise use the nearest safe work area. Clamp placement after display removal and respect taskbar position, menu-bar notch and mixed DPI. No taskbar or Dock window for steady-state operation; ordinary settings windows may use native conventions.

### Compact widget

Proposed default is 360 logical pixels wide and approximately 300 to 420 high. Content can scroll at large text sizes; it must not shrink controls to preserve these dimensions.

Reading order is app status, current input destination, paired-computer row, primary Pause or Resume action, secondary Return input here, then Arrange displays and Settings. Show a small two-computer diagram only if it adds clarity. Keep charts and IP addresses out of this view. Show the configured emergency shortcut persistently in readable text.

Clicking outside dismisses the widget; Escape dismisses only when no confirmation is active. Opening it must not move remote pointer authority or synthesize a modifier. A keyboard shortcut can open the widget, subject to conflict detection. It must remain distinct from the native emergency shortcut.

### Setup window

A separate resizable window, initially about 560 by 620 logical pixels, handles longer work. Steps are name this computer, grant required permissions, pair, arrange, then test and enable. Save progress after each completed step. Returning to setup resumes the relevant unfinished task.

Pairing lists nearby candidates as untrusted. Selecting one sends a request; the other machine shows who is asking and offers Accept or Decline. Proposed stronger enrollment shows a short authentication string derived from both identities and a fresh authenticated transcript, with explicit comparison on both devices. Do not invent cryptography in the UI layer; select and review an established protocol before committing to this flow. Expiration clears pending consent without installing credentials. Mismatch cancels enrollment and offers a new attempt. Manual address entry and public-bundle exchange remain advanced recovery options only with equivalent identity verification.

Arrangement begins with simple left/right placement and exposes a larger editor for multiple monitors. Retain useful geometry from `src/lib/displayLayout.ts` and inspect `src/components/DisplayLayoutEditor.tsx` before reuse. Provide keyboard move controls, numeric placement and textual adjacency. Identify displays locally with an explicit user action. Changes form a draft; Apply pauses sharing, validates both inventories, obtains peer acknowledgment, commits a revision, then offers Resume. Cancellation restores the previous committed arrangement. A disconnected follower cannot silently accept an unconfirmed map.

The test step explains and exercises local recovery, then asks the user to move across the chosen edge. Completion requires observed session readiness and user confirmation of the input test. Never infer successful injection solely from a socket connection.

### Settings and support

Use a compact conventional window with General, Computers, Displays, Permissions, and Troubleshooting. General contains login startup and resume policy. Computers supports rename and forget. Forget explicitly explains that re-pairing will be required, stops the active session, revokes local trust and removes topology references. Peer-side removal is best effort and never a precondition for local revocation.

Troubleshooting displays actionable health first, with expandable technical detail and an opt-in diagnostic export preview. Reuse diagnostic calculations where their measurement semantics hold. Exclude key content, clipboard content, private keys and pairing secrets. Show what identifiers and addresses will be exported and allow redaction. Logs have rotation and a retention limit.

## Failure and recovery behavior

| Situation | Visible behavior | Recovery and safety requirement |
| --- | --- | --- |
| Peer offline or network change | “Waiting for [computer]”; last-seen detail in expanded row | Keep input local. Retry with bounded backoff. Address repair must preserve pinned identity. |
| Runtime unreachable | “Sharing unavailable”; Retry and Troubleshoot | Treat authority as unknown, not locally confirmed. Reject new remote routing; agent supervision establishes safe local state. |
| Permission missing or revoked | Name the specific permission and affected process | Open the relevant OS settings when supported; recheck on return. Require deliberate resume after recovery. |
| Pairing timeout, decline or mismatch | Separate messages with Retry or Cancel | Delete ephemeral requests. Never silently trust a replacement identity. |
| Certificate changed | “Computer identity changed” | Stop authentication. Require explicit forget and verified re-pairing. |
| Layout stale after hotplug | “Display arrangement needs review” | Disable affected crossing edges; release remote state. Preserve the draft for repair. |
| Command times out | “Could not confirm this change” | Read a fresh snapshot using the request ID before retrying. Do not invert a toggle blindly. |
| Safety latch trips | “Sharing stopped for safety” with details | Keep local input available; require runtime restart and preflight. A Resume button cannot clear a latch. |
| Sleep, lock or session switch | Paused state, no repeated toast | Release held keys and buttons and invalidate remote authority. Re-enumerate on wake; require the approved resume policy. |
| Config unreadable or newer than app | Recovery screen with backup and version guidance | Preserve the file. No identity regeneration or default overwrite. |
| Update interrupted | Show previous version or repair state | Restore a compatible binary/config pair and remain paused until health is known. |

Notifications are limited to pairing requests and sustained failures that require action. Coalesce repeated failures. No toast for ordinary edge crossings or brief reconnects.

## Visual direction and accessibility

Use Windows and macOS system fonts, neutral backgrounds, restrained separators, and one accent for actionable controls. Light and dark appearances follow the system. Native material effects are optional and must have opaque fallbacks. Remove ambient decorations, large slogans, dashboard cards and oversized step navigation from daily operation.

Use a 4-pixel spacing base, 16-pixel outer padding, 14-pixel default body type and a clearly stronger status line. Targets should be at least 32 logical pixels high, preferably 40 for primary actions. Status always includes text and an icon, never color alone. Motion lasts at most 150 ms and is disabled with reduced motion.

Acceptance includes full keyboard operation, visible focus, Narrator and VoiceOver labels, high contrast, reduced motion, 200% text scaling, and mixed display scaling. Announce meaningful state transitions without reading every telemetry update. Restore focus to the invoking tray entry or control after dismissal. Pairing comparison strings must be read unambiguously by screen readers. No drag-only actions or hover-only recovery controls.

## Architecture and keep or rebuild decisions

Proposed process structure is a per-user native shell plus a supervised `kvm-runtime` agent. The shell owns tray, windows, login registration and update orchestration. The agent owns capture, injection, trust, configuration, topology, pairing and live state. The renderer owns presentation and drafts only. No elevated system service is proposed for normal desktop sharing.

Move setup business logic out of `SetupService` into testable Rust services behind authenticated local IPC. Extract incrementally so existing invariants remain testable. Keep `kvm-daemon` as reusable machinery; clearly retire or rename the skeleton binary in release tooling. Consolidate credential access through the existing platform and security modules after an audit of their actual use. Preserve identities during migration.

Keep and revalidate the Rust protocol, security, network, router, input and platform crates. Keep config migration, bounded queues, generation gates, failsafe machinery and relevant tests. Refactor `kvm-runtime/src/active.rs` into explicit owner-loop responsibilities as needed. Rebuild `App.tsx`, the polling orchestration, setup command façade and shell lifecycle. Retain React/Tauri initially because this avoids replacing the native input system and desktop shell technology simultaneously. A fully native widget remains a fallback if measured accessibility, focus or memory requirements cannot be met.

The shell supervises one agent per signed application identity and user session. Window close does not stop it. Shell failure must cause a bounded agent safety transition through a lease, while agent failure causes the shell to show unavailable and restart paused. The lease is native and independent of renderer responsiveness. OS login launches the shell; it adopts only a compatible authenticated agent. Duplicate launches and stale endpoint files cannot create competing capture owners.

### Full backend rewrite versus selective overhaul

| Choice | Benefits | Costs and failure risks |
| --- | --- | --- |
| Rewrite backend and UI | Can establish one ownership model and a smaller initial contract without legacy setup paths. Useful if existing invariants cannot be isolated or licensed dependencies become unsuitable. | Recreates unsafe native hooks, injection ordering, transport security, hotplug and failsafe behavior. Loses the value of accumulated tests unless ported and independently checked. Longest period without a trustworthy deliverable. A cleaner module tree does not prove safer input. |
| Selective backend overhaul with new shell and UI | Preserves tested mechanisms while fixing state ownership and delivery. Enables measured comparison against the remediation baseline and incremental migration. | Temporary adapters and old/new contracts add complexity. Existing composition may resist extraction. Requires disciplined deletion of compatibility code and integration tests across boundaries. |

Recommend selective overhaul. This is still a ground-up product redesign. Authorize a bounded backend replacement only if the first extraction phase demonstrates unresolved authority conflicts or measured performance failures that cannot be repaired locally. Compare evidence and scope before expanding to a full rewrite; do not promise an unsupported schedule advantage in weeks.

## Lifecycle and input safety

Define states independently for agent health, sharing intent, capture readiness, authenticated connection, active input owner and safety latch. Derive user-facing status from these fields. One “running” boolean is insufficient.

Pause and Quit must close routing admission, invalidate outstanding authority, release tracked injected keys and buttons, stop suppression and acknowledge completion. Release must happen on both local and remote failure paths. A disconnected remote machine needs its own bounded watchdog; the source cannot guarantee remote cleanup over a severed link. Late packets from an earlier generation must not reassert ownership.

Preserve native emergency handling independently of IPC, webview and tray. Test panic, queue saturation, hook loss, unplug, dropped key-up, app crash and remote restart while modifiers are held. Keep panic latch semantics. A forced process termination is a last recovery step and must never be described as equivalent to acknowledged cleanup.

For lock and secure-desktop transitions, pause ordinary desktop sharing. Do not promise control of Windows elevation prompts or macOS login screens. Probe session and display readiness before restarting capture. Failsafe and permission failures require explicit recovery; ordinary transient network loss may reconnect only under the approved sharing intent policy.

## Contract and data migration

Introduce a versioned control handshake with application version, supported schema range, capabilities and agent instance ID. Snapshots carry a monotonic revision and observation time. Events carry revision and instance ID; gaps or restart trigger a full refresh. UI subscriptions stop when hidden, while the native shell retains only health and menu state subscriptions.

Commands carry request IDs and expected config revisions. Return accepted, completed or failed states with structured reasons such as permission denied, unsupported, conflict, busy and safety latched. Bound every queue and payload. Retried commands must be idempotent. Never mark a control complete on the existing enqueue acknowledgment alone.

Generate TypeScript DTOs from the selected Rust schema or validate shared fixtures in CI. Cover actual serialized enum spelling and nullability. Keep local control versioning separate from the peer wire protocol and persisted config version. Preserve peer transport compatibility unless a separately approved security change requires a negotiated break.

Migration sequence: stop and acknowledge the legacy runtime; back up setup, TOML and credential references; validate all sources; produce one new authoritative revision; atomically commit; start paused; verify identity and topology preservation. Preserve a journal for interruption recovery. Import legacy runtime status only as historical diagnostics, never as live authority. Do not copy plaintext private material into renderer-accessible data.

During transition, the old setup interface calls the new owner through an adapter. There must never be two writers. Remove file-based stop/status authority only after deployed migration and rollback tests pass. Future-version config remains untouched. Downgrade either restores a compatible backup explicitly or refuses with useful guidance.

## Security and delivery

Audit local IPC endpoint ownership, same-user authorization, Windows pipe ACLs, Unix socket permissions, endpoint impersonation and payload limits before adding mutation commands. A local port or filesystem location alone is not authentication. Validate hostile names and bundles as data. Keep CSP restrictive and Tauri commands narrowly scoped; no arbitrary shell execution or production preview fallback.

Review pairing under active LAN attack. The comments in `nearby.rs` are not proof that initial trust resists identity substitution. Bind confirmation to both identities, roles, nonces and expiration; rate-limit requests; test replay and parallel sessions. Require explicit sign-off on the enrollment design before a public release. Retain certificate pinning and revocation for subsequent sessions.

Package the exact runtime with the shell; disable developer executable overrides in production. Establish one stable application identifier and signed helper identity before permission testing. Produce signed Windows installers and signed, notarized macOS artifacts. Validate Windows WebView availability and installation behavior offline. Verify ARM64 and x64 support rather than inferring support from CI host names.

Add release CI for locked dependencies, artifact provenance, checksums, license notices, signatures and clean-machine installation tests. Keep signing credentials outside builds from untrusted forks. Verify installed permissions, firewall behavior, login registration and helper paths on physical machines.

Updates are proposed as user-approved initially. Verify signed metadata and payloads, reject unexpected downgrades, download without interrupting sharing, then pause and await cleanup before replacement. Update shell and runtime as a compatible set. Preserve a rollback version and migration backup. Failed health checks return to a compatible version paused. Define signing-key rotation and recovery before enabling automatic updates.

Uninstall stops sharing, removes login registration, app-owned helpers and firewall rules, and offers explicit removal of settings and trust. Explain any OS permission entries that require manual removal. Test both retain-settings and erase-data paths. Never remove unrelated credentials, rules or user files. Reinstallation must not silently restore sharing intent.

## Phases, dependencies and acceptance gates

All targets below are proposed gates, not measured current results. Record hardware, OS version, build and test procedure with each measurement.

1. **Baseline and contracts.** Inventory all executable, config and credential owners; reproduce a two-host session; capture latency, CPU and memory baselines; settle state and lifecycle contracts. Gate: every mutation has one named owner, every visible state has an authoritative source, and signed-app identity strategy is agreed. Existing Rust and panel tests pass or failures are documented before change.
2. **Agent extraction and safety.** Depends on phase 1. Move setup services behind versioned IPC, add completion semantics, supervision and migration adapters. Gate: 100 repeated start/pause/quit cycles produce no duplicate capture owner or held injected state; dropped connections, shell death, agent death, lock and sleep recover locally within an approved watchdog bound, provisionally one second. Verify this on both receiving platforms, including peer link loss. Corrupt, old and future config fixtures preserve trust or stop without overwriting it.
3. **Tray shell and widget.** Depends on phase 2 contracts. Implement native menu, placement, focus, compact state views and settings navigation. Gate: 100 open/close cycles leave sharing unchanged; second launch opens the existing instance; webview failure leaves native Pause and Quit functional; keyboard and screen-reader checks pass on both OSes.
4. **Setup and recovery.** Depends on phases 2 and 3 and pairing security sign-off. Implement resumable onboarding, permission guidance, verified enrollment and transactional arrangement. Gate: eight first-time testers, at least four per OS, with seven completing pairing and arrangement without help within five minutes excluding downloads and OS restarts. Every failure row above has an integration scenario and clear recovery. No UI enables an unsupported runtime command.
5. **Performance and installed lifecycle.** Depends on working end-to-end flows. Gate: warm widget open p95 below 150 ms; hidden idle app plus agent averages below 1% of one CPU core over ten minutes without sharing traffic; total steady-state private memory provisionally below 120 MB. Report macOS and Windows memory measures separately. No frontend polling while hidden. Input latency p95 and p99 regress by no more than 10% against the same-hardware baseline; measure end-to-end externally where clocks are not aligned. Revisit proposed resource limits with baseline evidence before treating them as release promises.
6. **Release rehearsal.** Depends on all preceding gates. Gate: clean install, upgrade, interrupted upgrade, rollback and both uninstall modes pass on the supported OS/architecture matrix; signatures and notarization verify; 24-hour two-host soak has no stuck input or unbounded memory growth; at least 100 sleep/wake and disconnect/reconnect transitions pass. Release remains blocked by unresolved safety or enrollment authentication defects.

Avoid adding extensive UI snapshot tests that merely reproduce markup. Prioritize state-machine, serialization, migration, native failure-injection and installed-artifact tests. Use manual assistive-technology and physical input validation where simulation cannot establish correctness.

## Risks and unanswered sign-off questions

The largest risk is moving setup ownership while the old panel still writes state. Enforce one writer before shipping adapters. Stable signed helper identity may affect macOS permissions and requires an early installed-build experiment. A tray-only app can become undiscoverable; setup must show where it lives, and relaunch must reveal it. A safety lease that is too short can interrupt input under load; choose its bound from fault tests without coupling it to renderer health. Tauri may miss memory or accessibility targets; budget a native-widget evaluation only if measurements justify it.

The consolidated plan needs explicit decisions on:

- Does the first release remain two-host and LAN-only, with clipboard and audio excluded?
- Should ordinary network reconnection resume previously requested sharing automatically, and should wake or unlock always require Resume?
- Is Quit defined as stopping sharing and exiting both processes, as proposed, or is an independently persistent background agent required?
- Are login startup and automatic sharing opt-in defaults acceptable?
- Which Windows/macOS versions and CPU architectures form the supported release matrix?
- Which authenticated enrollment design and threat model will receive security review, and what happens to legacy trust records that lack equivalent verification?
- Who owns signing identities, update hosting, key rotation, release incident response and notarization access?
- Are the provisional one-second safety recovery bound and CPU, memory and latency regression gates acceptable after baseline measurement?
- Should uninstall retain settings by default, and what diagnostic retention period is acceptable?

Recommendation: approve the compact utility direction and selective backend overhaul only after the consolidated plan resolves lifecycle, enrollment and supported-platform choices. Keep release blocked on evidence from installed native builds, rather than treating a redesigned widget as proof that background input handling is ready.
