# macOS physical validation checklist

The IOHID capture implementation is observation-only. It does not suppress
events locally, even when the daemon callback returns `SuppressLocal`.
Selective suppression remains blocked on proving a reliable correlation
between an IOHID device identity and the corresponding suppressible Quartz
event.

Run the following checks on every supported macOS release and hardware family:

- Grant Input Monitoring, restart the daemon if macOS requests it, and verify
  permission preflight plus IOHID manager startup.
- Enumerate the built-in MacBook keyboard and trackpad, an external USB or
  Bluetooth keyboard, and external mice with and without extra buttons.
- Confirm stable `DeviceId` values after daemon restart, sleep/wake, reconnect,
  and reboot. Record devices that expose neither serial nor stable location.
- Capture key down/up for letters, both modifier sides, backspace, enter,
  arrows, and common shortcut chords without missing releases.
- Capture relative X/Y motion, left/right/middle/back/forward buttons, vertical
  wheel, and horizontal AC Pan values at high event rates.
- Confirm X/Y, wheel, and AC Pan elements are marked relative. Absolute values
  on all four usages are intentionally ignored rather than treated as deltas.
- Attach virtual HID software and joystick/game-controller collections. Verify
  virtual or weakly attributed elements are classified `Unknown`, and unrelated
  button collections never produce pointer-button events.
- Test the built-in trackpad separately. Some Apple trackpads expose contact
  data or absolute X/Y axes rather than generic-desktop relative X/Y values.
  Absolute axes are intentionally ignored until prior-state normalization is
  designed; do not claim pointer or gesture support on such hardware.
- Inject every supported event through `MacOutputBackend` and confirm that
  Quartz-tagged KVM events never appear in the IOHID callback or get forwarded.
- Saturate the bounded queue with motion/scroll and verify only the
  `dropped_events` counter increases while local input remains unaffected.
- Saturate the queue, then generate a key or button transition. Verify capture
  terminates, `transition_discontinuities` and terminal health are observable,
  and `stop_capture` returns the discontinuity error. Never resume routing from
  that session because key/button state is no longer trustworthy.
- Force delivery-worker disconnection and verify capture terminates with
  `DeliveryDisconnected` health and an explicit stop error rather than counting
  unbounded drops.
- Return `SuppressLocal` from the callback and verify the request is counted but
  macOS continues to receive the event locally.
- Start/stop capture repeatedly, including during device removal, sleep/wake,
  permission revocation, daemon shutdown, and a panicking delivery callback.
- Block the user callback indefinitely. Verify `stop_capture` returns its
  bounded timeout, the session remains available for a later stop retry, and
  dropping the backend returns without leaking or double-releasing its retained
  CFRunLoop reference. This requires Instruments/leak diagnostics on real macOS.

Task 18 is not complete until physical testing proves device-attributed Quartz
suppression, emergency recovery, and immediate release after daemon/network
failure. This layer must not be used to claim those guarantees.

## Explicit whole-host alpha mode

`MacInputBackend::new_whole_host_alpha` is a separate, explicit mode. It uses
an active `CGSessionEventTap` and can suppress translated physical input after
the synchronous daemon callback returns `SuppressLocal`. It deliberately
publishes only two stable, host-scoped aggregate devices: one keyboard and one
pointer. It does not provide or claim per-device suppression; built-in and
external devices of the same role are indistinguishable in this mode.

Both Input Monitoring and Accessibility must be granted before the event tap
is installed. The ordinary `MacInputBackend::new` constructor remains the
non-suppressing IOHID observation backend.

Before enabling this mode in a usable runtime, record all of the following on
each supported macOS version and hardware family:

- Confirm the two IDs returned by `enumerate_devices` exactly match every
  whole-host callback event and remain stable across restart, sleep/wake, and
  reboot.
- Verify ordinary hardware events report the HID-system source state. Events
  from private or combined-session sources must remain `Unknown` and local.
- Inject every supported key, repeated key-down, pointer movement/drag, button,
  and scroll record through `MacOutputBackend`. Confirm the exact KVM marker is
  retained at the session tap, every injected record stays local, and no record
  is retransmitted.
- Route key press/autorepeat/release, left/right modifiers, Fn,
  common shortcuts, pointer drag, five buttons, extra buttons, smooth trackpad
  scrolling, and both wheel axes. Verify local delivery occurs only when the
  callback returns `AllowLocal` and remote enqueue is not proven.
- Confirm Caps Lock remains local and is counted as untranslated. Quartz
  exposes its toggle state rather than a trustworthy physical down/up pair, so
  whole-host alpha must not invent a remotely held Caps Lock transition.
- Exercise two keyboards and two pointing devices. Record the whole-host
  limitation when the same modifier/button is held concurrently; do not infer
  per-device correctness from aggregate results.
- Force a callback delay long enough for Quartz to disable the tap. Local input
  must resume immediately, lifecycle must become `Faulted`, the runtime must
  gate routing and release remote held state, and the disabled generation must
  never re-enable itself. Only a clean stop followed by a new start may recover.
- Repeat the terminal check for user-input disable, permission revocation,
  invalidated Mach port, callback panic, secure-input fields, fast user
  switching, lock/unlock, and sleep/wake.
- Stop during held keys/buttons and race stop against active callbacks. Callback
  authority must become inert before the tap is disabled or removed; no event
  after stop begins may be suppressed.
- Block the daemon callback, request stop, and verify the bounded timeout keeps
  an inert process-global owner for retry without freeing callback context.
- Kill the daemon abruptly and confirm macOS removes the tap and restores local
  input without requiring logout or reboot.
- Run at least 100 start/stop cycles and a sustained high-rate trackpad test,
  recording callback latency, tap-disable count, untranslated records, and any
  terminal lifecycle transitions.

Login-window control and per-device policies remain outside this alpha scope.
The foreground alpha now polls `capture_lifecycle`, gates before teardown on
`Faulted`, and starts exact held-input cleanup. Whole-host suppression is not
accepted for normal startup until the remaining physical checks above pass.
