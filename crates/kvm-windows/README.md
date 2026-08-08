# Windows backend

This crate is the native Windows boundary for Software KVM. Its first
feasibility milestone implements:

- Raw Input enumeration of physical keyboard and mouse collections;
- observation-only Raw Input capture on a dedicated message thread;
- explicitly opted-in aggregate whole-host alpha capture and synchronous
  suppression with low-level keyboard and mouse hooks;
- stable application `DeviceId` derivation from Raw Input device-interface
  paths, with VID/PID extraction when the path contains USB identifiers;
- tagged `SendInput` injection for the canonical keyboard and pointer subset;
- basic GDI monitor enumeration; and
- a non-destructive runtime capability probe.

Capture translates keyboard make/break records, relative pointer motion, five
mouse buttons, and both wheel axes into shared `InputEvent` values. A bounded
1,024-event queue uses non-blocking insertion between the Windows message loop
and callback dispatcher; overflow, translation omissions, callback panics, and
ignored suppression requests are exposed through `capture_statistics()`.
Motion and scroll events may be dropped under queue pressure. A key or button
transition is never silently dropped: failure to admit one marks a capture
discontinuity, terminates that capture generation, increments
`capture_discontinuities`, and is returned by `stop_capture()` so the daemon can
release tracked pressed state before any restart. A compound mouse packet can be
partially admitted only with that explicit terminal discontinuity.
Startup uses a five-second, two-way readiness/acknowledgement handshake. A
timed-out owner drops the acknowledgement channel, forcing the eventual native
startup path to unregister before it can enter its message loop. Shutdown first
posts to the hidden window, falls back to `PostThreadMessageW(WM_QUIT)`, and
waits at most two seconds for each worker before returning a retryable error.
Join handles are joined only after a completion signal, so a failed Windows
message post or blocked callback cannot strand daemon shutdown indefinitely.

Raw Input registration is process-global for each top-level collection. A
process-wide generation claim therefore permits only one keyboard/mouse capture
owner. Timed-out starts retain their claim until their native thread completes
real unregister cleanup. Generation-checked release prevents stale cleanup from
unregistering or clearing ownership for a newer session. If native unregister
fails, ownership remains held rather than allowing an unsafe replacement.

`WindowsInputBackend::new` remains observation-only. Every callback result is
observed, but `SuppressLocal` is ignored and counted, so local input is never
blocked. The explicit `WindowsInputBackend::new_whole_host_alpha` constructor
instead installs low-level keyboard and mouse hooks. Its callback runs
synchronously on the hook thread, and `SuppressLocal` is honored only for
translated physical events. Callback panic, unknown messages, failed
translation, third-party injection, and KVM-tagged injection always fail open.

Low-level hooks do not carry Raw Input device identity. Whole-host alpha
therefore enumerates and emits exactly two deterministic, host-scoped aggregate
devices: one keyboard and one pointer. Raw Input remains the physical inventory
and observation mechanism in the default mode. `probe_capabilities` reports
`SuppressionScope::WholeHostAlpha`; per-device suppression remains explicitly
`NotImplemented`.

Whole-host hook ownership is process-global. Teardown deactivates callback state
before unhooking and joins the hook thread with a bounded wait. Callback state is
freed only after both native hooks are successfully removed. A partial unhook
failure leaves an inert ownership sentinel in place so another instance cannot
race an orphaned hook.

## Event classification

The Raw Input thread queries `GetCurrentInputMessageSource` for each `WM_INPUT`,
but does not currently classify any untagged event as `Physical`. Windows also
reports UIAccess-process injection as `IMO_HARDWARE`, and a non-null Raw Input
device handle proves attribution, not physical origin. Both handle-backed and
handle-less input therefore fail closed to `Unknown`, which the daemon keeps
local. The 32-bit KVM marker written to `SendInput.dwExtraInfo` is classified
`InjectedByKvm` if observed in the Raw Input extra-information field. Whether a
specific Windows build surfaces `SendInput` as Raw Input and preserves that
marker still requires physical validation. Whole-host alpha instead treats the
exact KVM marker as `InjectedByKvm`, any untagged low-level injected flag
(including lower-integrity injection) as `Unknown`, and only
untagged/non-injected hook records as `Physical`. Injected and unknown events
can never suppress locally.

Absolute Raw Input pointer coordinates are not emitted as relative motion.
Supporting absolute devices requires device-local prior-position state and
virtual-desktop metrics; treating their coordinates as deltas would be unsafe.

## Identity limitations

Raw Input device-interface paths are normally durable across process restarts,
but Windows can assign a new path after driver reinstall, re-pairing, or a USB
topology change. If Windows supplies an empty path, enumeration falls back to a
session-local native handle. That fallback is not stable across restarts and is
labelled as such in the derived identity input. The resulting SHA-256-based ID
is for local configuration matching only; it is not a security credential.

## Permissions and testing

Windows has no global `SendInput` permission that can be queried without
actually injecting input. UIPI can reject injection into a higher-integrity
target, so the probe reports injection as target-dependent. Enumeration,
capture startup/stop, origin classification, injection-tag observation, queue
pressure, monitor DPI behavior, hot-plug/reconnects, and UIPI boundaries require
testing on a real Windows 11 host. Whole-host alpha additionally requires
physical validation of hook installation/removal, hook timeout behavior under a
slow callback, secure-desktop and elevated-window boundaries, injected-flag/tag
preservation, repeat/held-state behavior, five-button mice, both wheel axes,
absolute/high-rate pointer behavior, sleep/resume, and emergency local recovery.
Per-device suppression still requires a separately proven Raw Input-to-hook
correlation mechanism.
