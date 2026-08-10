# Audit: §15 Local Suppression + §16 Injected-Event Detection — CONFORMANT

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 23
**Spec ref:** `.spec/implementation.md` §15 (Local Suppression), §16 (Injected Event Detection)
**Severity:** N/A — conformance confirmation. These are the two most safety-critical
software-KVM properties (a remotely-routed event must not also fire locally; an
injected event must not be re-captured and re-forwarded). Both are implemented
and gated correctly on both platforms.

## What the spec requires

- **§15** — a remotely routed physical event must not also execute locally; the
  capture→routing decision must be able to `suppress` the local copy when the
  event is bound for the remote host. Suppression is implemented independently
  per platform, and global disable of all input is to be avoided unless
  absolutely necessary (i.e. per-device selective suppression is the ideal).
- **§16** — every backend must classify each event `Physical | InjectedByKvm |
  Unknown`, and KVM-generated events must never enter remote-routing logic
  (prevents the Mac→Windows→Mac forwarding loop).

## Implementation evidence

### §15 suppression — present on BOTH platforms, symmetric, opt-in

Both backends expose a non-default `*WholeHostAlpha*` capture mode that performs
real suppression, and a default observation mode that does not. This matches the
milestone-02 boundary: capture/suppression is gated behind an explicit alpha
opt-in, never enabled in the observation-only default.

- **Windows** (`crates/kvm-windows/src/native.rs`)
  - `new_whole_host_alpha(host_id)` installs two global low-level hooks:
    `SetWindowsHookExW(WH_KEYBOARD_LL, …)` (`:1677`) and
    `SetWindowsHookExW(WH_MOUSE_LL, …)` (`:1691`).
  - The hook procs return `LRESULT(1)` to swallow a proven physical event
    (`:1522`, `:1622`) — i.e. they do **not** call `CallNextHookEx`, which is
    the documented Win32 mechanism to suppress at the low-level hook layer.
    Non-suppressed paths forward via `CallNextHookEx` (`:1524`, `:1625`).
  - Suppression is decided by `whole_host_should_suppress(classification,
    disposition)` (`:375`) and only honors a proven-translated `SuppressLocal`;
    injected/untrusted/unknown/panicking/untranslatable paths always remain
    local (`:805-806`). `suppressed_events` is tallied (`:378`).
  - Inactive/teardown state never suppresses (`:1467-1469`) — safe fail-open.
- **macOS** (`crates/kvm-macos/src/native.rs`)
  - `new_whole_host_alpha` Quartz event-tap backend; the tap callback computes
    `suppress` (`:1359`) and, when set and active, does not pass the event along
    (`:1371`), tallying `suppressed_events` (`:1509`).
  - `suppression_scope()` maps mode→scope: `IoHidObservation`→`None`,
    `WholeHostAlpha`→`WholeHostAlpha` (`:527-530`).
- **Selective / per-device suppression:** reported `NotImplemented`
  (`kvm-windows/src/native.rs:1286`, `kvm-macos/src/native.rs:541`) on both
  platforms — the `WholeHostAlpha` aggregate scope is the current ceiling. This
  is consistent with the spec's "avoid global disable … unless absolutely
  necessary" guidance being a goal rather than a day-one requirement, and is
  honestly advertised through `WindowsCapabilities` /
  `selective_suppression_supported()` rather than silently claimed.

### §16 injected-event detection — classification present on BOTH platforms

- **Windows:** `classify_low_level`/`classify_raw_input` produce a `Physical |
  Injected | Unknown` classification using the `LLKHF_INJECTED` /
  `LOW_LEVEL_KEY_INJECTED` / `LOW_LEVEL_MOUSE_INJECTED` flags
  (`kvm-windows/src/capture.rs`, consumed at `native.rs:67-72`). Only a
  proven-physical, translated event can be suppressed; injected events fail-open
  to local and never enter remote routing.
- **macOS:** the KVM injection path tags its synthesized events
  (`KVM_EVENT_TAG`, `native.rs:33`) so the capture side can distinguish
  self-injected from physical — the §16 "InjectedByKvm" classification.
- This is exactly the §16 three-way classification and "KVM-generated events
  never enter remote-routing" rule, closing the Mac⇄Windows feedback loop.

## Web verification (current best practice)

`WH_KEYBOARD_LL` / `WH_MOUSE_LL` global hooks that omit `CallNextHookEx` to
swallow the event are the canonical Win32 system-wide suppression mechanism
(Microsoft Q&A "How to suppress keys using HookCallback"; widely-used
keyboard-blocker/barrier-style implementations). The `LLKHF_INJECTED` flag is
the standard signal that an event was synthesized rather than physical, and is
the recommended basis for loop-prevention in KVM-class software. The codebase's
approach matches industry practice.

## Why this is a finding (not just "looks fine")

§15/§16 are the two properties whose failure makes a software KVM unusable or
dangerous (double input, or an infinite Mac⇄Windows forwarding loop). Several
prior cycles confirmed individual subsystems (stuck-key §25, clipboard §27,
topology §12, peer state §22, workspace epoch §11/§14). This cycle formally
records that the **suppression and loop-detection** core also holds — on both
platforms, symmetrically, behind an explicit opt-in, with honest capability
reporting. No code change required.

## Non-goals

Did not modify code. The only genuine §15 limitation — per-device **selective**
suppression being `NotImplemented` on both platforms — is a known future
capability, not a regression; it is advertised through the capabilities surface
and is out of scope for this cycle.
