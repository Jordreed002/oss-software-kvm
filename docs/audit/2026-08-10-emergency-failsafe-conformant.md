# Audit: §24 Emergency Failsafe — CONFORMANT (safety-critical)

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 27
**Spec ref:** `.spec/implementation.md` §24 (Emergency Failsafe)
**Severity:** N/A — conformance confirmation of the system's "kill switch". Cycle
14 already verified the suspend-duration half (`routing_suspend_seconds`); this
cycle verifies the other half — the chord detection, local precedence, and full
action set.

## What the spec requires

Reserve a physical shortcut, default **Ctrl+Alt+Shift+Backspace**, that:

- is **never forwarded**, **never remapped**, **always detected locally**; and on
  activation: release all capture/suppression, clear pressed remote keys, reset
  active host, disable KVM routing temporarily. Configurable later.

## Implementation evidence

### The chord — exactly the spec default, configurable

`kvm-config/src/model.rs`:

- `FailsafeSettings::default()` (`:362`) sets `shortcut =
  [Control, Alt, Shift, Backspace]` and `routing_suspend_seconds = 10` —
  precisely the §24 default chord.
- `shortcut` is a `Vec<ShortcutKey>` where `ShortcutKey = Control | Alt | Shift |
  Meta | Backspace | Escape | Physical{usage_page, usage}` — so the chord is
  fully **configurable** (spec's "make the shortcut configurable later"),
  including raw HID usages for non-standard keys.
- `Debug` redacts the shortcut (`[REDACTED]`) so logs cannot leak the kill chord.

### Detected locally, before routing, never forwarded

`kvm-daemon/src/core.rs`, inside `prepare_captured` (`:831`, **before**
`route_for` at `:854`):

```text
if self.failsafe_matches() && !self.drain_failsafe_keys {
    self.drain_failsafe_keys = true;
    return Ok(match self.activate_failsafe(now_ns) { … CaptureDecision::Local … });
}
```

- `failsafe_matches()` (`:1786`) requires **every** chord key pressed
  (`shortcut.iter().all(shortcut_key_pressed)`) against the daemon's tracked
  physical pressed-key state — so the chord is matched on raw physical state,
  not on a translated/semantic output (never remapped).
- On match it returns `CaptureDecision::Local(Gated)` — the triggering event is
  **not forwarded**; `activate_failsafe` runs.
- `drain_failsafe_keys` then keeps every subsequent chord-key event **local**
  (`:843-852`, forced `Local/Gated`) until **all** chord keys are released
  (`any_failsafe_key_pressed` goes false). This is the subtle correctness detail:
  the key-up events of the chord are also consumed locally, so the remote host
  never observes a partial chord or ends up with stuck modifier keys.

Because this runs in `prepare_captured` on every captured physical event, the
chord is **always detected locally** at the daemon's lowest input-handling layer,
independent of routing/translation — exactly §24's requirement and the
established best practice for a kill chord (handle it before anything else).

### The full §24 action set — `activate_failsafe` (`:1767`)

```text
suspended_until_ns   = now + routing_suspend_seconds * 1e9   # disable routing temporarily
workspace.active_host = workspace.local_host                  # reset active host
handoff_pending = false                                       # cancel any in-flight handoff
queue_remote_cleanup(|_,_,_| true)                            # clear pressed remote keys (release all)
publish(now_ns)                                               # surface the state change
```

- **disable KVM routing temporarily** → `suspended_until_ns`; the routing gate
  (verified in cycle 14, `core.rs` ~`:2098`) honors this until it elapses.
- **reset active host** → `active_host = local_host`.
- **clear pressed remote keys** → `queue_remote_cleanup` for **all** pending
  remote effects queues release events for every key/button the remote still
  holds (the §25 stuck-key cleanup path, reused here).
- **release all capture/suppression** → the platform layer: the supervisor /
  capture session exposes `trigger_capture_emergency` (`session.rs:800` →
  `core.trigger_emergency`, `supervisor.rs:1355`), which is the same
  `activate_failsafe` reached by the chord. The runtime warns the operator to
  keep the shortcut available when whole-host capture starts
  (`kvm-runtime/src/main.rs:39`).

A programmatic `trigger_emergency(now_ns)` (`:1739`) also exists, so the
failsafe can be activated by the platform/supervisor without the chord (e.g. a
forced escape from another layer) — reusing the identical action path.

## Web verification (current best practice)

Ctrl+Alt+Backspace is the long-standing X11 "Zap" / kill-server chord (well
documented across distro guides); adding **Shift** (as this spec does) is a
common hardening to avoid accidental triggers. The principle that such a chord
must be handled at the lowest input layer — before forwarding, remapping, or
application-level processing — is the consensus best practice and is exactly what
`prepare_captured`'s pre-routing check implements.

## Non-goals

Did not modify code. §24 is conformant and well-engineered. The only thing not
exercised here is live OS-level end-to-end delivery of the chord through the
platform capture backends (the daemon-side detection and action logic, which is
what §24 prescribes, is fully verified).
