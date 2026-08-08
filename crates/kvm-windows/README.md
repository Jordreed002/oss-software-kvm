# Windows backend

This crate is the native Windows boundary for Software KVM. Its first
feasibility milestone implements:

- Raw Input enumeration of physical keyboard and mouse collections;
- observation-only Raw Input capture on a dedicated message thread;
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

Capture is intentionally observation-only. Every callback result is observed,
but `SuppressLocal` is ignored and counted, so local input is never blocked.
Raw Input carries a device handle, while Windows low-level keyboard and mouse
hooks can suppress an event but do not carry that same identity. A later
feasibility test must prove safe correlation and emergency recovery before
per-device suppression can be reported as supported.

## Event classification

The capture thread queries `GetCurrentInputMessageSource` for each `WM_INPUT`,
but does not currently classify any untagged event as `Physical`. Windows also
reports UIAccess-process injection as `IMO_HARDWARE`, and a non-null Raw Input
device handle proves attribution, not physical origin. Both handle-backed and
handle-less input therefore fail closed to `Unknown`, which the daemon keeps
local. The 32-bit KVM marker written to `SendInput.dwExtraInfo` is classified
`InjectedByKvm` if observed in the Raw Input extra-information field. Whether a
specific Windows build surfaces `SendInput` as Raw Input and preserves that
marker still requires physical validation. Forwarding must remain disabled
until physical-origin proof is implemented and validated.

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
testing on a real Windows 11 host. The critical unresolved risk remains reliable
correlation between Raw Input device identity and a suppressible low-level-hook
event.
