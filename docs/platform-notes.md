# Platform notes

## Feasibility gate: device-aware suppression

Per-device remote routes require both stable physical identity and suppression of the matching
local event. This is the first native feasibility gate because the operating systems expose those
properties through different APIs.

On Windows, Raw Input supplies device identity and high-frequency events, while low-level hooks
can suppress input but do not necessarily expose the same device identity. The production backend
must demonstrate reliable correlation, injection tagging, and recovery before per-device routing
is considered supported. The current backend observes Raw Input without suppression and treats
ambiguous/null-device records as unknown. `SendInput` is also subject to integrity-level
restrictions.

On macOS, IOHID supplies device discovery and identity while Quartz event taps provide observation
and suppression. The backend must demonstrate attribution for the built-in keyboard and trackpad,
external devices, KVM-injected event filtering, and immediate recovery when permissions or peer
health change. The current backend observes IOHID values without suppression and deliberately
ignores absolute pointer axes rather than misreporting them as relative movement.

If user-space APIs cannot meet the invariant reliably, implementation stops at this gate. A helper
or filter driver is an architectural decision requiring explicit review; it is not introduced
silently.

## Permissions

macOS requires clear Input Monitoring and Accessibility onboarding. Windows injection into a
higher-integrity process may fail under UIPI. Login-screen control is outside version-one scope.

## Cross-platform modifier roles

Shortcut modifiers are remapped on the destination so shortcuts keep their meaning across a
macOS↔Windows pair. The persisted `keyboard.modifier_role_mapping` selects the mode;
`functional` is the default:

| Source → Destination | `functional` (default) | `positional` (legacy) | `identity` |
|---|---|---|---|
| Mac Cmd → Windows | Ctrl | Alt | Windows key unchanged |
| Mac Option → Windows | Alt | Windows key | Alt |
| Mac Ctrl → Windows | Windows key | Ctrl | Ctrl |
| Windows Ctrl → Mac | Cmd | Ctrl | Ctrl |
| Windows Alt → Mac | Option | Option | Cmd |
| Windows Win → Mac | Ctrl | Cmd | Win |

Both directions are bijective per mode (proven by test), so simultaneous holds — e.g. Mac
Cmd+Ctrl held together — always map to two distinct destination keys and releases can never
collide. Shift is never remapped. Physical-mode text entry remains layout-dependent: HID usage
IDs are transported verbatim, so a non-QWERTY source layout onto a QWERTY destination types
destination-layout glyphs; the semantic layer (protocol v4) covers shortcut intents only.
