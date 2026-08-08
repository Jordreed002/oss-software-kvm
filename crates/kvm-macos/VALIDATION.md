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
