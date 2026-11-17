# Application overhaul plan comparison

Prepared by the coordinating Codex agent on 2026-11-17. All three proposals were independently written against `9edb5ed` before comparison. This is a qualitative design assessment, not measured software performance or a vote by the three models. The consolidated recommendation is in `recommended-plan.md`.

## Subsequent user scope decision

The user subsequently requested a ground-up rebuild of the Rust application, allowing selective reuse, and made performance a primary requirement. This overrides the selective backend overhaul recommended by all three original proposals. The comparison below records the original assessment; its recommendations to retain or evolve existing Rust subsystems no longer define implementation scope. The updated `recommended-plan.md` and `rust-rebuild-strategy.md` govern the new work. The models have not re-reviewed the revised scope.

## Strengths and weaknesses

| Proposal | Strongest contribution | Weakness or unresolved assumption | Consolidated decision |
| --- | --- | --- | --- |
| Codex | Incremental delivery, current-capability inventory, command completion semantics, explicit quit, and measured baselines before resource promises | Keeping setup orchestration in the resident native host leaves two durable authorities and requires both native shells for pairing/map sync. It underweights enrollment review and removal of the LAN diagnostics listener. | Adopt its staged delivery and capability discipline. Move durable setup ownership into the existing runtime process as Astra and Opus propose. |
| Astra | Clear state dimensions, one writer, authenticated IPC, enrollment threat review, interrupted migration, peer-side cleanup, and installed-build validation | Its shell-health lease adds a new safety mechanism with potential false trips. Clipboard exclusion removes existing capability without user direction. Numeric latency/resource bounds and a fixed tester cohort are provisional. Return-input action still needs backend support. | Adopt its safety and migration model. Prototype the native lease under load; preserve clipboard as validated optional plain-text functionality. Make measured budgets a phase-zero output. Do not show an unsupported transfer action. |
| Opus | Most concrete extraction of setup/pairing into an idle-capable agent, packaging work, native secret-store integration, and removal of unauthenticated LAN diagnostics | “The backend is fine” overstates source evidence. Reusing the existing verification flow is not a substitute for enrollment review. Force-kill cannot guarantee input release. Its plan both promises unchanged peer wire and proposes a new authenticated peer diagnostic request. Changing config “to v3” overlooks the current general config schema already being v3. Default-on startup, invisible sharing after Quit, and tight unmeasured budgets need correction. | Adopt agent ownership and release/security work. Keep existing algorithms subject to validation. Distinguish general config, runtime-profile, IPC, and peer-wire versions. Local diagnostics first; remote diagnostics require separately negotiated support. Reject invisible sharing after Quit and false cleanup guarantees. |

## Architectural disagreement resolved

Codex initially kept orchestration in the resident Tauri host. Astra and Opus place trust, setup, pairing and configuration in a background agent. Choose the latter because a window-independent process should own the state needed to keep the pair coherent while sharing is paused. The existing runtime becomes that agent with an optional active input session. This is still two primary processes, native shell and runtime agent, not a new third resident coordinator.

The native shell owns tray, windows, login integration and update orchestration. The agent owns durable configuration, identity, enrollment, topology and runtime lifecycle. React owns presentation and uncommitted drafts. A temporary adapter preserves the legacy UI, but the legacy backend loses write authority before the agent gains it.

Agent presence does not imply capture is active. Its local control endpoint remains available while sharing is stopped. It can continue serving status and pairing without installing input capture.

## Defaults and scope disagreements

| Topic | Alternatives in the independent plans | Recommendation and reason |
| --- | --- | --- |
| Everyday surface | Anchored popover, optional pinned widget, large settings/dashboard | Tray/menu-bar popover as home; focused resizable setup/settings; pinned widget later. This delivers the requested small utility without squeezing display arrangement into a tiny panel. |
| Quit | Stop both processes, remembered choice, or persistent background sharing | Explicit Quit stops sharing and both processes after confirmed cleanup. Closing a task window only dismisses it. Avoid a second meaning for Quit. |
| Shell crash | Agent continues, restarts, or pauses through a lease | Webview crash leaves routing unaffected. Loss of the native shell triggers bounded agent pause through a tested native health lease; agent remains idle for recovery. Peer cleanup remains independently enforced. |
| Restart | Automatic restart, manual restart, or restart paused | Restart/adopt a validated compatible agent paused. Never auto-clear a failsafe latch or mistake lock/PID presence for health. |
| Clipboard | Exclude first release, always show toggle, or preserve optional preference | Preserve plain-text scope, default off for new installs. Keep existing preference during migration but start paused. Implement the missing mutation path before enabling controls; Pause sharing gates both input and clipboard. |
| Startup | Checked by default or opt-in | Launch at login off until chosen. Launching the app does not silently restore capture. Network reconnection may follow an existing active sharing intent; wake, unlock and fault recovery require explicit Resume initially. |
| Input switching | Always-present Return input here / Switch to peer | Show current destination and automatic handoff. Native Pause and the existing emergency chord provide recovery. Add deliberate transfer only after an authoritative tested command exists. |
| UI technology | Keep Tauri/React, native rewrite fallback | Keep Tauri/React first. Revisit only if the installed shell spike fails focus, accessibility, resource or platform behavior requirements. |
| Visual style | Custom bundled font and palette versus platform materials/fonts | Calm neutral surfaces, readable platform text and one accent. Native accessibility and high-contrast support take priority. Material effects optional; avoid expensive decoration. |
| Updates | Automatic on quit versus user-approved | Signed manual installer first; user-approved signed in-app update after replacement and rollback tests. No automatic installation during sharing. |
| Diagnostics | Existing LAN endpoint versus authenticated peer request | Local IPC diagnostics in release. Disable unauthenticated LAN diagnostics. Defer remote collection until a bounded authenticated transport is explicitly designed and versioned. |

## Findings checked during consolidation

The coordinator inspected `setup.rs`, `lib.rs`, `control.rs`, `nearby.rs`, Tauri configuration/capabilities, `kvm-runtime/src/main.rs`, `active.rs`, `kvm-daemon/src/control_service.rs`, `kvm-protocol/src/control.rs`, and network IPC/diagnostics modules.

Confirmed that the current mutation acknowledgement is queue admission, not completion; topology/device/clipboard mutations return `Internal`; stop uses a file and a blocking wait; IPC is composed by the active runtime; and the diagnostics listener binds to the configured LAN IP with an intentionally unauthenticated protocol.

Windows pipe creation rejects remote clients but has no explicit DACL or first-instance policy in the inspected constructor. That warrants authorization and endpoint-impersonation testing; it does not prove exploitability for every local principal. Merely checking process ID or adding a user suffix is insufficient authentication. Verify both server identity and client authorization under the approved local threat model.

The current pairing comparison code hashes a request ID and both bundles. This confirms the existing comparison mechanism, not resistance to all active enrollment attacks. Review transcript binding, role/nonce handling, low-entropy comparison attacks, retry limits and legacy trust before public release. Retain verified trust during migration unless specific evidence requires re-enrollment.

## What is intentionally not decided by the models

Signing account ownership, product identifier, supported OS minimums/CPU architectures, and hardware availability need user or project-owner input before release scope is finalized. The models cannot promise those resources. Precise latency, memory, CPU and recovery thresholds need named-machine baselines and fault measurements. No application code or native behavior was tested during this planning exercise.

## Source proposals

- `codex-plan.md`: coordinating Codex independent proposal.
- `astra-plan.md`: requested `codex/gpt-6-astra` independent proposal.
- `opus-plan.md`: requested `claudeAgent/claude-opus-5-5` independent proposal.
- `current-capability-inventory.md`: coordinator's source-based inventory used to check parity and scope.
