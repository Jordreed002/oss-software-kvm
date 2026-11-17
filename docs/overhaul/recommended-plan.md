# Software KVM utility overhaul recommendation

Status: proposed for user sign-off. Prepared 2026-11-17 after comparing independent Codex, Astra and Opus proposals. Base `code-review-remediation` at `9edb5ed`; planning branch `overhaul/widget-app-planning`. This document governs the recommendation where independent proposals disagree. Implementation has not begun.

Scope revised by the user: rebuild the Rust application from the ground up, with selective reuse allowed. Performance is a primary architectural and release requirement. This direction supersedes the selective backend overhaul recommended in the original independent proposals. `rust-rebuild-strategy.md` defines the revised backend work and performance gates.

## Recommended product

Rebuild Software KVM as a small Windows notification-area and macOS menu-bar utility with a newly designed Rust backend. A compact anchored widget replaces the large daily console. Separate setup, display arrangement, settings and troubleshooting windows open only when needed. Design fresh Rust process, module, concurrency, state and protocol boundaries. Existing code is reference material and a source of individually reviewed reusable parts.

The visible experience should answer where input is going, whether sharing is ready, and how to pause safely. The default UI should contain no charts, protocol terminology or network-address forms. Advanced detail stays available in troubleshooting.

This is a full product, frontend and Rust implementation rebuild. The original plans favored selective replacement; the user's subsequent scope decision takes precedence. No existing Rust crate or input subsystem is presumed to survive intact. Preserve required behavior and safety properties, and retain code only through an explicit reuse decision backed by tests and measurements. Performance governs architectural choices from the first design phase.

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

Use Tauri 2, React, TypeScript and Vite as the proposed presentation stack, subject to the installed-shell performance spike. Rebuild the Rust workspace structure and native shell integration around two primary processes:

1. The native Tauri shell owns tray/menu-bar behavior, windows, the local API client, login integration and update orchestration. React owns presentation and uncommitted drafts.
2. A newly implemented per-user Rust agent owns identity, pairing/discovery, configuration, committed topology, runtime lifecycle and authoritative state. It supports an idle state with no active capture. The local control endpoint exists while sharing is off. The current runtime supplies behavioral reference and comparison measurements rather than the default implementation.

Design explicit Rust services and ownership boundaries before implementation. Build the new agent alongside the legacy implementation so tests and measurements can compare them. Reuse selected parsing, geometry, mapping, native bindings or other components only after reviewing their contracts, safety and performance. Do not carry over the current large orchestration modules by default. Do not add a third persistent coordinator or ship the old lifecycle-skeleton binary.

The agent supervises its input sessions, not the renderer. The shell adopts only a compatible, authenticated agent instance for the same user session. Duplicate launches cannot create competing capture owners. A runtime lock or a PID alone proves neither identity nor health.

Loss of a webview leaves the native shell and sharing intact. Loss of the native shell triggers a bounded agent pause through a native health lease; this is independent of React rendering and must be tuned against load/fault measurements. The agent remains available in idle recovery state. If the lease cannot avoid false trips or fails its safety gate, revisit supervision design before shipping. An agent restart starts paused and cannot clear a persisted safety condition by accident.

## Local contract and safety

Design a versioned app API with bounded local transport, schema negotiation, capabilities, authenticated instance identity, monotonic revisions and state freshness. Evaluate existing transport code for selective reuse rather than inheriting it. Keep local API, peer wire, general configuration and runtime-profile versions independent. General configuration is already v3 at the base; choose any next schema version only after a concrete schema delta exists. Legacy peer compatibility must be explicitly selected and tested; it must not force a poor new architecture or unsafe silent downgrade.

Commands carry correlation IDs and expected revisions. Responses distinguish accepted, applied, rejected and unconfirmed. Retried operations are idempotent or explicitly rejected. Events carry instance identity and revision; gaps, stale state or restarts force snapshot resynchronization. Generate or validate TypeScript serialization against Rust DTOs in CI.

Provide status, pause/resume, failsafe, identity/enrollment, peer/layout settings, diagnostics and lifecycle commands deliberately. Existing protocol variants do not prove implementations exist. Unsupported controls remain absent or clearly unavailable. Until live transactions are safe, settings use stop/edit/validate/restart. Old frontend commands can adapt to the new owner temporarily; two writers must never coexist.

Preserve UI-independent emergency recovery, held-key/button accounting, bounded queues, exact-session/generation gates and local fallback. The shutdown sequence closes remote admission, invalidates authority, reconciles held state, stops suppression, and confirms termination. Remote cleanup under a severed link relies on the destination's own watchdog. Force-killing a process cannot be described as proof that cleanup occurred.

Sleep, screen lock and session switch pause sharing before capture resumes elsewhere. Do not promise control over secure desktops or elevation prompts. Permissions, inventories, authenticated peer health and authority must be revalidated before explicit Resume.

## Trust, diagnostics and migration

Harden local IPC before expanding mutations. Validate same-user endpoint ownership, restrictive Unix directories/socket permissions, Windows pipe ACLs and first-instance policy, both server identity and client authorization, bounded payloads and connection limits. Tests include endpoint impersonation, unauthorized user access and stale endpoint recovery. Same-user malicious software remains a threat-model decision; a SID suffix alone is not a security boundary.

Implement identity persistence through reviewed OS credential-store adapters; existing adapters are candidates for reuse. Migration preserves host/peer identities and trust where the new security model permits, journals progress, validates new storage by read-back, and commits atomically. If a legacy enrollment cannot meet the new trust requirements, require explained verified re-pairing. Retain a rollback-compatible protected credential reference until the supported rollback path is proven. Define when the old secret file and sensitive backups are removed; do not delete the only rollback copy prematurely or leave redundant secrets indefinitely.

Consolidate setup state, runtime profile and general configuration into one authoritative owner, without conflating their schemas. Stop the legacy runtime before migration. Future-version configuration is preserved and produces guidance. Interrupted writes restore the last working configuration; no silent identity regeneration.

Release diagnostics use local authenticated IPC. Disable the unauthenticated LAN TCP diagnostics listener in release builds. Keep developer diagnostics explicitly opt-in. Remote diagnostic collection is deferred until a separately reviewed bounded authenticated transport and compatibility policy exists; moving it onto the peer session would require explicit protocol work and input-path isolation.

Review existing enrollment against active LAN attacks, including identity substitution, replay, parallel sessions, rate limits and authentication-string entropy. Preserve approved peer identities unless specific evidence requires re-pairing. The current input core and historical tests are valuable evidence, not blanket proof of safety or security.

## Implementation sequence and gates

| Phase | Deliverable | Dependencies and completion gate |
| --- | --- | --- |
| 0. Baseline, new architecture and experience | Current-behavior inventory, physical performance baseline, new Rust architecture and reuse policy, two visual variants, installed-shell/permission spike | Confirm supported OS/CPU matrix and signed helper feasibility. Every existing behavior has a destination or approved deferral. Set numeric tail-latency, smoothness, CPU, allocation, memory, wakeup and safety budgets on named machines before backend design is accepted. |
| 1. New Rust foundation and fast path | New domain/state model, native adapters, bounded event path, authenticated transport and session ownership | Phase 0 contracts. A minimal two-host capture-to-injection slice passes ordered-state and emergency-release tests in both directions and meets initial latency/smoothness budgets. Review unsafe/native boundaries and record every reused component. |
| 2. New agent and control plane | Idle-capable agent, identity/enrollment, topology, configuration, versioned local API and confirmed command outcomes | Phase 1 safety model. Pair and synchronize headlessly; one writer; no IPC, pairing, config or diagnostics workload violates input-path budgets. Legacy imports work through an isolated adapter. |
| 3. Tray shell and new daily UI | Native menu, single instance, widget, supervision, setup/settings, accessible light/dark components | Phase 2 contracts; design can proceed earlier against fixtures. Webview failure leaves native Pause/Quit usable. One hundred open/dismiss cycles leave sharing unchanged. Keyboard, assistive technology, DPI and visible/hidden performance gates pass. |
| 4. Security and migration acceptance | Reviewed enrollment, settings transactions, credential migration, endpoint hardening and local diagnostics | New core and control plane. Unauthorized clients rejected; interrupted migration preserves identity or requests explained re-pairing; release LAN diagnostics absent; no unsupported controls. |
| 5. Lifecycle and physical acceptance | Held input, lock/sleep/user switch, disconnect/crash/relaunch and permission loss | Prior phases. One hundred combined lifecycle/fault transitions per receiving OS produce no stuck input or duplicate owner. Twenty-four-hour soak has no unbounded growth. Full performance matrix passes under load with UI visible and hidden. |
| 6. Installed release and cutover | Compatible packages, signing, manual release, startup/uninstall/rollback and later user-approved updater | Phase 5 plus signing resources. Clean install, paired upgrade, interrupted update, rollback and uninstall pass on approved OS/CPU matrix. Legacy capture is stopped before new capture starts. Retire old runtime after parity and performance acceptance. |

Build the early native-shell and capture-to-injection prototypes before expanding feature work. Keep the legacy implementation available as a reference and rollback build, with exclusive capture ownership. Implement new Rust modules alongside it and compare against both the legacy baseline and absolute new performance budgets. Keep legacy compatibility isolated and retire it at an explicit checkpoint after parity and acceptance.

Each implementation phase should produce a reviewable change with correctness and performance evidence. The Rust/input-engine rebuild is already in scope. Framework changes remain evidence-driven choices. Re-estimate delivery after the first end-to-end slice; the former selective-refactor schedule no longer applies.

## Verification and resource targets

Keep the legacy suites as behavioral evidence and regression references. Build independent contract, state-machine, serialization, property, migration, native lifecycle and fault-injection tests for the new Rust implementation. Passing old tests alone does not validate new architecture. Run formatting, clippy, tests, frontend checks and separate desktop-backend checks as applicable to both implementations during transition. UI fixtures cannot certify native input behavior.

Performance is a first-class design constraint for every Rust subsystem and UI feature. Record p50, p95, p99 and, with sufficient samples, p99.9 input latency, jitter, smoothness, queue age, CPU, memory, allocations, wakeups and energy. Measure both directions with UI hidden and visible on the same host pair, build mode, topology and network. Proposed warm-widget p95 opening target is 150 ms. Set numeric input-path and resource budgets in phase zero before committing to the new architecture; baseline parity alone is insufficient if the legacy baseline misses those budgets. Report host, agent and webview resources separately. Avoid cross-host latency claims without aligned clocks or external measurement. Codec microbenchmarks supplement physical input-latency and smoothness tests. See `rust-rebuild-strategy.md` for required hot-path design rules and benchmark matrix.

Physical validation includes held modifiers/buttons during pause/quit, peer/link loss, local agent crash, shell crash versus webview crash, lost IPC events, sleep/wake, lock/unlock, changed LAN, dock/undock, revoked permissions and mixed versions. Test setup with people unfamiliar with the product when available; do not invent a fixed tester cohort or crash-free percentage without a measurement denominator.

## Packaging and operations

Recommend a per-user Windows installer and a signed/notarized macOS app with a bundled compatible agent. Fix production executable discovery to packaged paths and disable developer overrides. Choose stable app/helper identifiers before permission continuity testing. Validate WebView prerequisites and offline behavior. Signing budget, account access and supported architectures are phase-zero inputs, not assumptions.

Start with signed manual releases. User-approved in-app updates follow only when signature checks, compatible-pair replacement, failed-health rollback and signing-key recovery are tested. Do not install while input is active. Uninstall stops sharing, removes app-owned startup/helper/firewall registrations and offers explicit deletion of trust/settings. Preserve unrelated files and credentials. Explain any OS permission records requiring manual cleanup.

No telemetry upload is proposed. Local logs rotate with a documented retention period. Redacted support bundles are user initiated. Release CI builds from locked inputs, verifies signatures, records checksums/provenance and includes licenses. Credentials for signing are unavailable to untrusted fork builds.

## Approval requested

The user has requested a ground-up Rust rebuild with selective reuse and performance as a primary requirement. The revised implementation proposal combines that requirement with compact tray/menu-bar home, focused setup/settings, agent-owned durable state, explicit Quit stopping sharing, opt-in startup, optional plain-text clipboard, two-host LAN scope, Windows/macOS parity and user-approved updates after installed lifecycle validation.

Visual variants, new Rust architecture, measured performance budgets and installed helper behavior return for phase-zero review before full implementation. Independently persistent invisible sharing, pinned widget, new platforms and multi-peer scope remain separate decisions. The requested Rust rebuild does not depend on proving the old architecture irreparable.

Before phase zero closes, supply or confirm the supported OS/CPU matrix, final product/application identifiers, available Windows/macOS test machines, and signing ownership/budget. These do not prevent approving the product direction or beginning the baseline/design spike.

## Supporting material

`rust-rebuild-strategy.md` defines the user's revised Rust and performance scope. `plan-comparison.md` records the earlier comparison and the subsequent scope override. `codex-plan.md`, `astra-plan.md` and `opus-plan.md` preserve the original independent proposals, which predate the rebuild instruction. `current-capability-inventory.md` maps existing behavior to overhaul requirements. File paths in those documents are relative to this repository.

Available Tauri mechanisms are documented in the official [tray guide](https://v2.tauri.app/learn/system-tray/), [window event API](https://v2.tauri.app/reference/javascript/api/namespacewindow/), [autostart plugin](https://v2.tauri.app/plugin/autostart/), and [updater plugin](https://v2.tauri.app/plugin/updater/). Their availability does not replace installed-platform validation.
