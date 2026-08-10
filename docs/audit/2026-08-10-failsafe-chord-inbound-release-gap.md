# Audit: §25 Stuck-Key Recovery — failsafe chord does not release inbound keys

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 37
**Spec ref:** `.spec/implementation.md` §25 (Stuck Key Recovery)
**Severity:** High — safety-critical. Leaves peer-injected modifiers logically
held in the exact scenario the codebase's own F-02 comment warns about.

## What the spec requires (§25)

Track pressed keys/buttons and, on **failsafe triggers** (plus disconnect, route
change, shutdown), send the corresponding release events. *"Never leave remote
Ctrl, Shift, Alt, Command or mouse buttons logically held down."*

§25 lists "failsafe triggers" as one cleanup condition. There are **two** runtime
entry points into the failsafe, and they are wired inconsistently.

## The two failsafe paths

### (a) Native-capture discontinuation — WIRED (both directions)

When capture is lost, `PeerSessionSupervisor::native_capture_discontinued_with_workspace`
calls `trigger_capture_emergency` (`supervisor.rs:1355`), which is the complete
reconciler (`session.rs:858-867`):

```text
core.trigger_emergency     → queues outbound cleanup
release_all_inbound        → injects inbound releases   ✅
drain_remote_cleanup       → sends outbound releases
combine_cleanup_results    → neither error masks the other
```

Its own comment (`session.rs:860-863`) states *why* inbound is released: to avoid
**F-02** — "the user regains control of the machine with the peer's injected
modifiers still physically held."

### (b) Emergency chord — GAP (outbound only)

When the user physically presses the escape chord, `DaemonCore::prepare_captured`
(`core.rs:842`) calls `activate_failsafe` (`core.rs:1771`), which queues
**outbound-only** cleanup (`queue_remote_cleanup(|_,_,_| true)`, `core.rs:1777`).
Control returns as `CaptureDecision::Local` with `failsafe_activated`.

The coordinator's `route_captured` `Local`/`Inert` branch (`session.rs:790-797`)
then does **only** `drain_remote_cleanup(now_ns)` — it never calls
`release_all_inbound`. The supervisor's `route_capture_with_workspace`
(`supervisor.rs:1280-1312`) sees `outcome.failsafe_activated()` and does only
`workspace.cancel_handoff_for_failsafe(...)` (`supervisor.rs:1298`) — it too
never releases inbound.

So on the chord path, `inbound_pressed` (peer-injected keys held at our host) is
left untouched. This is the precise F-02 scenario — yet path (a)'s fix for F-02
(`trigger_capture_emergency`) is not on path (b).

## When it bites

`inbound_pressed` is non-empty only while **we are the destination**
(`active_host == local_host`) and a peer is actively injecting modifiers here
(e.g. the peer holds `Ctrl` on its keyboard, injected into us). If the local user
then presses the escape chord to regain control, `Ctrl` stays logically held
locally. In the more common forwarding state (`active_host == remote`)
`inbound_pressed` is typically empty, so the gap is latent — which is why it has
not been caught by the existing failsafe tests (those exercise the outbound
drain and routing suspension, not a peer-injected-modifier destination state).

## Why this is a §25 violation, not just a nicety

§25's invariant is absolute: "Never leave … modifiers logically held down" on a
failsafe trigger. Path (b) is a failsafe trigger that does leave them held. The
codebase already treats F-02 as a correctness bug worth a named fix and an
explicit comment — path (b) simply was not given the same fix.

## Web verification

Stuck modifier keys across disconnect / failsafe / mode-switch are one of the
most-reported classes of bug in software KVM and remote-desktop tools: Synergy
users report modifiers "sticking" on screen switches; Sunshine issue #791 is
literally "stuck key persisted across disconnect/reconnect"; RDP has a long
history of the Windows key remaining held after focus loss. Every one of these
is the same root cause §25 targets: an input sink stops being authoritative
while a modifier is down and nobody synthesizes the release. So the gap is real
against both the spec and field experience — not a theoretical completeness nit.

## Other §25 triggers (verified conformant)

For completeness, the other three §25 conditions were traced and are WIRED:

- **Peer disconnect** — `disconnect` / `session_fatal_cleanup` (`session.rs:1613`,
  `:1640`) call `release_all_inbound` + `drain_remote_cleanup`. (In `disconnect`
  the outbound drain result is deliberately discarded once the transport is
  invalidated — settled by terminal invalidation, not skipped.)
- **Route change** — outbound is drained on every route-changing op
  (`update_workspace` `core.rs:1512`, `prepare_route_policy_update`
  `core.rs:1284`, pointer handoff `session.rs:725`/`:762`, `gate_local_devices`
  `session.rs:935`, config host removal `core.rs:1161`). Inbound is correctly
  *not* released — the session persists and the peer owns its injected keys.
- **Daemon shutdown** — `PeerManager::shutdown` → `coordinator.shutdown`
  (`session.rs:1057`) does `release_all_inbound` + `drain_remote_cleanup`, errors
  combined, session retained on failure.

Error paths across these combine both directions (`combine_cleanup_results`) and
retain the session for retry via `CleanupIncomplete` — no silent release-skip.

(Note: the spec-named `PressedState::take_release_payloads` is not called in
production; the coordinator reads `pressed_keys()`/`pressed_buttons()` directly
in `inbound_releases` and clears via `apply`. Functionally equivalent — same
deterministic order, modifiers-last — but worth recording.)

## Recommendation (cycle 38 IMPROVE target)

In `route_captured`'s `Local`/`Inert` branch, when `outcome.failsafe_activated()`,
also call `release_all_inbound(now_ns)` and `combine_cleanup_results` with the
outbound drain — exactly mirroring `trigger_capture_emergency` (`session.rs:858`).
This puts the "failsafe releases both directions" logic in the one coordinator
method both failsafe paths share, and adds a test that holds an inbound modifier,
fires the chord, and asserts `inbound_pressed` is emptied.

## Non-goals

Did not modify code this cycle (AUDIT). The fix lands in cycle 38. Did not change
the disconnect / route-change / shutdown paths (verified conformant).
