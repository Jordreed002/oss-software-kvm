# Software KVM utility overhaul recommendation

Status: proposed for user sign-off. Prepared 2026-11-17 after comparing independent Codex, Astra and Opus proposals. Base `code-review-remediation` at `9edb5ed`; planning branch `overhaul/widget-app-planning`. This document governs the recommendation where independent proposals disagree. Implementation has not begun.

## Recommended product

Rebuild Software KVM as a small Windows notification-area and macOS menu-bar utility. A compact anchored widget replaces the large daily console. Separate setup, display arrangement, settings and troubleshooting windows open only when needed. Retain and revalidate the Rust input mechanisms while substantially rebuilding the application shell, state/control contract and ownership of setup/configuration.

The visible experience should answer where input is going, whether sharing is ready, and how to pause safely. The default UI should contain no charts, protocol terminology or network-address forms. Advanced detail stays available in troubleshooting.

This is a full product and frontend redesign with a substantial application-backend refactor. A complete input-engine rewrite is a separate expansion of scope, justified only if baseline and extraction work demonstrates a specific unrepairable deficiency. All three independent plans favor selective replacement.

## First release scope and defaults

- Windows 11 and macOS, two paired computers on one LAN, multiple displays per computer, existing keyboard mapping, pointer handoff and optional plain-text clipboard.
- Native tray/menu-bar entry and an anchored widget around 360 logical pixels wide. Grow or scroll for accessibility; dimensions are design starting points rather than clipping constraints.
- Focused, resizable setup/settings windows. Optional pinned desktop widget follows the initial utility release.
- Launch at login is opt-in. New installations begin with clipboard off. Existing trust and settings migrate, but capture starts paused after migration.
- Window close dismisses the window. Explicit Quit stops sharing and exits the native shell and agent after cleanup is confirmed.
- Pause sharing gates input and clipboard and reconciles held input. Resume restores the configured features only after preflight and runtime confirmation. A failsafe latch requires explicit recovery, not an ordinary Resume.
- Ordinary transient peer reconnection can honor an already-active sharing intent after authentication and authority validation. Wake, unlock, agent restart, permission recovery and safety faults require deliberate Resume initially.
- No new WAN, video/audio, privileged system service, login-screen control, multi-peer UI, or per-device suppression promise. Preserve existing lower-level capabilities without advertising unvalidated product controls.

## Everyday experience

The native icon distinguishes paused, sharing and attention by shape as well as accessible text. Its menu offers Open controls, Pause or Resume when supported, Settings, Troubleshoot and Quit. Native Pause/Quit remain available if the renderer fails.

The widget shows a concise status sentence, actual input destination, peer name, a small workspace sketch if useful, and one primary Pause/Resume action. “Connected” and “Controlling MacBook” represent different facts. Display “Starting” or “Could not confirm this change” while state remains pending or unknown. Never show a successful toggle merely because a command entered a queue. Do not show input-transfer or clipboard actions until supported and validated.

Esc and outside activation dismiss the widget without changing routing. Keyboard activation works. Restore focus appropriately to the invoking control or previous application and verify remote-authority behavior on hardware. Clamp placement to a usable work area after monitor removal or DPI changes. A second launch opens the existing instance.

Use quiet neutral surfaces, a restrained accent, clear typography, crisp icons and short transitions. Support light/dark themes, high contrast and reduced motion from the first component set. Avoid a miniature version of the old dashboard. Approve concrete visual variants during phase zero before building the new production views.

## Setup and settings

First launch opens resumable onboarding: identify this computer, permissions, discover and verify the peer, arrange displays, then test and enable. Explain Windows firewall and elevated-window limitations and macOS permissions in user terms. Permission state must refer to the installed capture executable.

Nearby machines are untrusted candidates. Both users confirm an authenticated enrollment comparison. Timeout, mismatch, decline, identity change and blocked discovery each have explicit recovery. Keep manual public-bundle exchange as an advanced fallback with equivalent trust checks. Enrollment design must pass a threat review before public release; do not invent a UI-only security protocol.

Arrangement supports simple left/right setup plus multiple displays. Reuse tested geometry where suitable; add keyboard and numeric alternatives to dragging. Apply works on a draft: pause, validate inventories, synchronize and confirm a revision, commit, then offer Resume. Failure preserves the previous committed map.

Settings groups computers/displays, keyboard/clipboard, permissions, startup and About. Troubleshooting shows the actionable blocker before technical detail. Export presents a redaction preview and excludes input payloads, private keys and pairing secrets. Forget immediately revokes local trust and stops the active session; remote-side forgetting is best effort.

## Process and ownership architecture

Retain Tauri 2, React, TypeScript, Vite and the Rust workspace initially. Two primary processes remain:

1. The native Tauri shell owns tray/menu-bar behavior, windows, the local API client, login integration and update orchestration. React owns presentation and uncommitted drafts.
2. The existing `kvm-runtime` evolves into a per-user background agent with optional active capture. It owns identity, pairing/discovery, configuration, committed topology, runtime lifecycle and authoritative state. The local control endpoint exists while sharing is off.

Extract setup and nearby-pairing services from the current Tauri backend into testable Rust modules, adding a crate only where ownership/dependency boundaries warrant one. Do not add a third persistent coordinator. Preserve the actual runtime entry point and retire the lifecycle-skeleton binary from release tooling.

The agent supervises its input sessions, not the renderer. The shell adopts only a compatible, authenticated agent instance for the same user session. Duplicate launches cannot create competing capture owners. A runtime lock or a PID alone proves neither identity nor health.

Loss of a webview leaves the native shell and sharing intact. Loss of the native shell triggers a bounded agent pause through a native health lease; this is independent of React rendering and must be tuned against load/fault measurements. The agent remains available in idle recovery state. If the lease cannot avoid false trips or fails its safety gate, revisit supervision design before shipping. An agent restart starts paused and cannot clear a persisted safety condition by accident.

## Local contract and safety

Use the existing bounded local transport as the starting point for a versioned app API. Add schema negotiation, capabilities, authenticated instance identity, monotonic revisions and state freshness. Keep local API, peer wire, general configuration and runtime-profile versions independent. General configuration is already v3 at the base; choose any next schema version only after a concrete schema delta exists.

Commands carry correlation IDs and expected revisions. Responses distinguish accepted, applied, rejected and unconfirmed. Retried operations are idempotent or explicitly rejected. Events carry instance identity and revision; gaps, stale state or restarts force snapshot resynchronization. Generate or validate TypeScript serialization against Rust DTOs in CI.

Provide status, pause/resume, failsafe, identity/enrollment, peer/layout settings, diagnostics and lifecycle commands deliberately. Existing protocol variants do not prove implementations exist. Unsupported controls remain absent or clearly unavailable. Until live transactions are safe, settings use stop/edit/validate/restart. Old frontend commands can adapt to the new owner temporarily; two writers must never coexist.

Preserve UI-independent emergency recovery, held-key/button accounting, bounded queues, exact-session/generation gates and local fallback. The shutdown sequence closes remote admission, invalidates authority, reconciles held state, stops suppression, and confirms termination. Remote cleanup under a severed link relies on the destination's own watchdog. Force-killing a process cannot be described as proof that cleanup occurred.

Sleep, screen lock and session switch pause sharing before capture resumes elsewhere. Do not promise control over secure desktops or elevation prompts. Permissions, inventories, authenticated peer health and authority must be revalidated before explicit Resume.

## Trust, diagnostics and migration

Harden local IPC before expanding mutations. Validate same-user endpoint ownership, restrictive Unix directories/socket permissions, Windows pipe ACLs and first-instance policy, both server identity and client authorization, bounded payloads and connection limits. Tests include endpoint impersonation, unauthorized user access and stale endpoint recovery. Same-user malicious software remains a threat-model decision; a SID suffix alone is not a security boundary.

Integrate existing OS credential-store adapters into identity persistence. Migration preserves host/peer identities and trust, journals progress, validates new storage by read-back, and commits atomically. Retain a rollback-compatible protected credential reference until the supported rollback path is proven. Define when the old secret file and sensitive backups are removed; do not delete the only rollback copy prematurely or leave redundant secrets indefinitely.

Consolidate setup state, runtime profile and general configuration into one authoritative owner, without conflating their schemas. Stop the legacy runtime before migration. Future-version configuration is preserved and produces guidance. Interrupted writes restore the last working configuration; no silent identity regeneration.

Release diagnostics use local authenticated IPC. Disable the unauthenticated LAN TCP diagnostics listener in release builds. Keep developer diagnostics explicitly opt-in. Remote diagnostic collection is deferred until a separately reviewed bounded authenticated transport and compatibility policy exists; moving it onto the peer session would require explicit protocol work and input-path isolation.

Review existing enrollment against active LAN attacks, including identity substitution, replay, parallel sessions, rate limits and authentication-string entropy. Preserve approved peer identities unless specific evidence requires re-pairing. The current input core and historical tests are valuable evidence, not blanket proof of safety or security.

## Implementation sequence and gates

| Phase | Deliverable | Dependencies and completion gate |
| --- | --- | --- |
| 0. Baseline and experience | Current-behavior inventory, physical baseline, state/lifecycle contract, two visual variants and chosen design, installed-shell/permission spike | Confirm supported OS/CPU matrix, signed helper identity feasibility, tray positioning/focus and recovery paths. Every existing action has a destination or explicit deferral. Define numeric performance and recovery budgets from named-machine measurements. |
| 1. Single owner and local API | Idle-capable agent, extracted setup/pairing services, capabilities/events/completion semantics, legacy adapter | Phase 0 contracts. Headless two-agent pairing and map sync work without open webviews. Status works with capture stopped. One config writer. Delayed/duplicate commands and event gaps produce explicit safe state. |
| 2. Tray shell and daily widget | Native menu, single instance, placement, lifecycle supervision, all everyday status states, light/dark accessible components | Phase 1 contract. 100 open/dismiss cycles leave sharing unchanged; webview failure leaves native Pause/Quit usable. Keyboard, Narrator/VoiceOver, high contrast, text scaling and mixed DPI pass. |
| 3. Setup, settings and security migration | New onboarding, transactional arrangement, mapping/clipboard controls, trust migration, IPC hardening and local diagnostics | Phase 1 ownership plus phase 2 shell. Clean and existing paired installs work; enrollment review passes; unauthorized clients rejected; interrupted migrations preserve identity; no unsupported controls; release LAN diagnostic listener absent. |
| 4. Lifecycle and physical acceptance | Both-direction input validation, shell lease, lock/sleep/user switch, disconnects, crash/relaunch, permission loss | Prior phases. At least 100 combined start/pause/quit and fault transitions on each receiving OS have no stuck input or duplicate capture owner. Cleanup bounds meet phase 0 decisions under load. Twenty-four-hour two-host soak has no unbounded growth or stuck input. |
| 5. Installed release | Compatible host/agent packages, signed/manual release, optional user-approved signed updater, login/uninstall/rollback | Phase 4 plus signing resources. Clean install, paired upgrade, interrupted update, rollback, offline prerequisites and both retain/erase uninstall paths pass across approved OS/CPU matrix. Both binaries/config remain compatible; update waits for confirmed cleanup. |

Build the early native-shell prototype in phase zero so major platform and permission risks become visible before bulk extraction. Production UI work can proceed against phase-one contracts once stable. Keep the legacy frontend as an internal fallback during migration; remove it only after parity and acceptance, with an explicit compatibility retirement checkpoint.

Each implementation phase should produce a reviewable change with verification evidence. Reassess scope after the extraction gate before authorizing an input-engine replacement or a framework switch. Calendar estimates follow the first spike rather than an assumed rewrite duration.

## Verification and resource targets

Run the existing workspace formatting, clippy and tests with and without diagnostics, panel type-check/tests/build and the separately excluded Tauri Rust checks. Add meaningful contract, state-machine, serialization, migration and lifecycle tests. UI fixtures cover ordinary and failure states but cannot certify native input behavior.

Record performance with UI hidden and visible on the same host pair, build mode, topology and network. Proposed warm-widget p95 opening target is 150 ms. Establish CPU, memory, end-to-end input latency and recovery bounds from measured baselines in phase zero; all become signed-off release gates before implementation cutover. Report host, agent and webview memory separately and use platform-appropriate measurements. Avoid interpreting cross-host timestamps without clock alignment. Local codec benches supplement external input-latency measurements rather than replace them.

Physical validation includes held modifiers/buttons during pause/quit, peer/link loss, local agent crash, shell crash versus webview crash, lost IPC events, sleep/wake, lock/unlock, changed LAN, dock/undock, revoked permissions and mixed versions. Test setup with people unfamiliar with the product when available; do not invent a fixed tester cohort or crash-free percentage without a measurement denominator.

## Packaging and operations

Recommend a per-user Windows installer and a signed/notarized macOS app with a bundled compatible agent. Fix production executable discovery to packaged paths and disable developer overrides. Choose stable app/helper identifiers before permission continuity testing. Validate WebView prerequisites and offline behavior. Signing budget, account access and supported architectures are phase-zero inputs, not assumptions.

Start with signed manual releases. User-approved in-app updates follow only when signature checks, compatible-pair replacement, failed-health rollback and signing-key recovery are tested. Do not install while input is active. Uninstall stops sharing, removes app-owned startup/helper/firewall registrations and offers explicit deletion of trust/settings. Preserve unrelated files and credentials. Explain any OS permission records requiring manual cleanup.

No telemetry upload is proposed. Local logs rotate with a documented retention period. Redacted support bundles are user initiated. Release CI builds from locked inputs, verifies signatures, records checksums/provenance and includes licenses. Credentials for signing are unavailable to untrusted fork builds.

## Approval requested

Approve this recommendation as the implementation direction with these defaults: compact tray/menu-bar home; focused setup/settings; agent-owned durable state; selective core refactoring; explicit Quit stops sharing; opt-in startup; optional plain-text clipboard; two-host LAN scope; Windows/macOS parity; user-approved updates after installed lifecycle validation.

Visual variants, measured budgets and installed helper behavior return for phase-zero review before production UI implementation. A full engine rewrite, independently persistent invisible sharing, pinned widget, new platforms and multi-peer scope remain separate decisions.

Before phase zero closes, supply or confirm the supported OS/CPU matrix, final product/application identifiers, available Windows/macOS test machines, and signing ownership/budget. These do not prevent approving the product direction or beginning the baseline/design spike.

## Supporting material

`plan-comparison.md` records adopted strengths, objections and resolutions. `codex-plan.md`, `astra-plan.md` and `opus-plan.md` preserve the independent proposals. `current-capability-inventory.md` maps existing behavior to overhaul requirements. File paths in those documents are relative to this repository.

Available Tauri mechanisms are documented in the official [tray guide](https://v2.tauri.app/learn/system-tray/), [window event API](https://v2.tauri.app/reference/javascript/api/namespacewindow/), [autostart plugin](https://v2.tauri.app/plugin/autostart/), and [updater plugin](https://v2.tauri.app/plugin/updater/). Their availability does not replace installed-platform validation.
