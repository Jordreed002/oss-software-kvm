# Software KVM — Product & Technical Specification

## 1. Product Summary

Build a cross-platform software KVM for macOS and Windows that allows a user to control both systems seamlessly using any connected keyboard, mouse, or trackpad.

The primary use case is a desk setup where:

* A Windows PC has multiple monitors.
* A MacBook has its own built-in display, keyboard, and trackpad.
* The Windows PC has an external Logitech keyboard and mouse connected.
* The user wants all input devices to work across both systems without physically switching devices, moving hardware, or using Logitech Easy-Switch.

The software should make the MacBook display behave like an additional logical display in the overall workspace.

The user should be able to move a pointer across Windows monitors and onto the MacBook display, with keyboard focus following the active display.

The software must support input originating from either machine.

---

# 2. Primary Goal

Create a reliable, low-latency, bidirectional software KVM that makes two physical computers feel like one multi-display workstation.

Example workspace:

```text
┌────────────┬────────────┬────────────┐
│ Windows #1 │ Windows #2 │ Windows #3 │
│            │            │            │
└────────────┴──────┬─────┴────────────┘
                    │
              logical boundary
                    │
              ┌─────▼──────┐
              │  MacBook   │
              │   macOS    │
              └────────────┘
```

Available input devices may include:

```text
Windows host
├── Logitech keyboard
└── Logitech MX Master mouse

Mac host
├── Built-in MacBook keyboard
└── Built-in MacBook trackpad
```

All four devices should be capable of controlling either machine.

---

# 3. Supported Platforms

Initial release:

* Windows 11
* macOS

Architecture must allow Linux support later without restructuring the shared core.

Do not implement Linux in the initial release.

---

# 4. Technology Stack

## Core

Use Rust.

Create a Cargo workspace containing shared core functionality and platform-specific crates.

Suggested structure:

```text
kvm/
├── Cargo.toml
│
├── crates/
│   ├── kvm-core/
│   ├── kvm-protocol/
│   ├── kvm-network/
│   ├── kvm-config/
│   │
│   ├── kvm-windows/
│   ├── kvm-macos/
│   │
│   └── kvm-daemon/
│
└── apps/
    └── control-panel/
```

## Control Panel

Use:

* Tauri
* React
* TypeScript

The control panel must be separate from the KVM daemon.

The daemon must continue operating if the UI:

* crashes,
* closes,
* restarts,
* or is never opened.

---

# 5. Core Architecture

Run one KVM daemon on each machine.

```text
WINDOWS                               MACOS

┌──────────────────┐             ┌──────────────────┐
│ Windows KVM      │             │ macOS KVM        │
│ daemon           │◄───────────►│ daemon           │
│                  │   network   │                  │
│ input capture    │             │ input capture    │
│ input injection  │             │ input injection  │
│ display topology │             │ display topology │
└──────────────────┘             └──────────────────┘
```

The daemon is responsible for:

* physical input capture,
* device identification,
* local input suppression,
* remote input injection,
* display topology,
* active-host state,
* keyboard routing,
* mouse routing,
* network communication,
* peer discovery,
* pairing,
* reconnect behaviour,
* clipboard synchronisation,
* failsafe behaviour.

---

# 6. KVM State Model

The primary KVM state should remain simple.

```rust
enum Host {
    Windows,
    Mac,
}

struct KvmState {
    active_host: Host,
}
```

The active host is primarily determined by pointer position.

Each physical device may optionally override this behaviour.

```rust
enum DeviceRoute {
    FollowActiveHost,
    Windows,
    Mac,
    Local,
}
```

Default behaviour:

```text
MX Master              → FollowActiveHost
Logitech Keyboard      → FollowActiveHost
MacBook Trackpad       → FollowActiveHost
MacBook Keyboard       → FollowActiveHost
```

---

# 7. Input Device Requirements

Each input device must have a stable internal identity where practical.

Represent devices using a shared structure similar to:

```rust
struct InputDevice {
    id: DeviceId,
    host: HostId,
    name: String,
    vendor_id: Option<u16>,
    product_id: Option<u16>,
    kind: DeviceKind,
    capabilities: DeviceCapabilities,
}
```

Possible device kinds:

```rust
enum DeviceKind {
    Keyboard,
    Mouse,
    Trackpad,
    Other,
}
```

The system must support multiple keyboards and pointing devices simultaneously.

Input must not be treated purely as:

```text
keyboard
mouse
```

when the platform can provide physical device identity.

---

# 8. Windows Input Backend

Use native Windows APIs.

Investigate/use as appropriate:

* Raw Input
* SendInput
* low-level keyboard hooks
* low-level mouse hooks
* Windows display APIs
* Windows clipboard APIs

Raw Input should be the primary mechanism for:

* physical device enumeration,
* distinguishing different keyboards,
* distinguishing different mice,
* receiving high-frequency mouse data.

Injected events must not be retransmitted.

The Windows backend must distinguish:

```text
physical input
vs
KVM-injected input
```

to avoid input loops.

---

# 9. macOS Input Backend

Use native macOS APIs through Rust FFI or a very thin Swift/Objective-C bridge where necessary.

Investigate/use as appropriate:

* IOHIDManager
* IOHIDDevice
* Quartz Event Services
* CGEvent
* CGEventTap
* CoreGraphics display APIs
* macOS clipboard APIs

macOS implementation must support:

* built-in MacBook keyboard,
* built-in MacBook trackpad,
* externally connected input devices,
* input monitoring permissions,
* accessibility permissions.

Avoid moving business logic into Swift.

Platform-specific native code should only expose functionality that the Rust platform crate needs.

---

# 10. Input Event Model

Create a platform-neutral input representation.

Example:

```rust
struct InputEvent {
    source_host: HostId,
    source_device: DeviceId,
    timestamp: u64,
    sequence: u64,
    payload: InputPayload,
}
```

Example payloads:

```rust
enum InputPayload {
    KeyDown(Key),
    KeyUp(Key),

    MouseMove {
        dx: f64,
        dy: f64,
    },

    MouseButton {
        button: MouseButton,
        pressed: bool,
    },

    Scroll {
        vertical: f64,
        horizontal: f64,
    },
}
```

Mouse movement should primarily use relative movement.

Do not rely on remote machines having matching screen resolutions.

---

# 11. Pointer Behaviour

The system should behave as though all displays belong to one logical workspace.

Example:

```text
┌──────────┬──────────┬──────────┐
│ Win #1   │ Win #2   │ Win #3   │
└──────────┴─────┬────┴──────────┘
                 │
           ┌─────┴─────┐
           │ MacBook   │
           └───────────┘
```

When the pointer reaches a configured machine boundary:

1. Detect the display edge.
2. Determine the adjacent display.
3. Change the active host if necessary.
4. Suppress local mouse handling where required.
5. Transfer pointer position logically.
6. Forward subsequent movement to the destination host.

Transition should feel continuous.

---

# 12. Display Model

Displays must be represented independently of hosts.

Example:

```rust
struct Display {
    id: DisplayId,
    host: HostId,

    bounds: Rect,

    logical_width: f64,
    logical_height: f64,

    scale_factor: f64,

    refresh_rate: Option<f64>,

    primary: bool,
}
```

Refresh rate should be collected for informational purposes but should not affect KVM routing.

Important factors are:

* logical dimensions,
* physical dimensions where available,
* scale factor,
* DPI scaling,
* display position.

---

# 13. Mixed DPI and Resolution Handling

The user may have:

* three Windows monitors,
* different resolutions,
* different scaling percentages,
* different refresh rates,
* a Retina MacBook display.

Pointer transition must therefore use logical and normalised coordinates.

Example:

```text
source_y_normalised =
    pointer_y / source_display_height
```

Destination:

```text
destination_y =
    source_y_normalised * destination_display_height
```

Do not assume pixel coordinates map directly between displays.

---

# 14. Workspace Layout Editor

The control panel must include a visual display layout editor.

Example:

```text
┌─────────┐ ┌───────────┐ ┌─────────┐
│ PC #1   │ │ PC #2     │ │ PC #3   │
└─────────┘ └───────────┘ └─────────┘
                  │
             ┌─────────┐
             │ MacBook │
             └─────────┘
```

The user must be able to drag displays into their physical desk arrangement.

The resulting layout defines which display edges connect.

Examples:

```text
PC monitor 2 bottom
→ MacBook top
```

while:

```text
PC monitor 1 bottom
→ no transition
```

unless explicitly configured.

---

# 15. Shared Logical Pointer

The system should conceptually maintain one logical pointer state.

```rust
struct LogicalPointer {
    display: DisplayId,
    x: f64,
    y: f64,
}
```

Any pointing device configured as `FollowActiveHost` can continue controlling the active logical pointer.

Example workflow:

1. User moves MX Master from Windows onto Mac.
2. Pointer is now on Mac.
3. User stops touching MX Master.
4. User uses MacBook trackpad.
5. Same active pointer continues moving.
6. User moves pointer back onto Windows.
7. Logitech keyboard automatically follows Windows again.

No manual device switching should be necessary.

---

# 16. Keyboard Behaviour

By default, keyboards should follow the active host.

Example:

```text
Pointer on Windows
→ Logitech keyboard types into Windows
→ MacBook keyboard types into Windows

Pointer on Mac
→ Logitech keyboard types into Mac
→ MacBook keyboard types into Mac
```

Individual devices may be pinned to a specific host.

---

# 17. Modifier Mapping

Support platform-specific keyboard semantics.

At minimum provide two modes.

## Physical mode

Example:

```text
Ctrl → Control
Win  → Command
Alt  → Option
```

## Semantic mode

Translate common commands based on their intent.

Examples:

```text
Copy
Windows: Ctrl+C
Mac:     Command+C

Paste
Windows: Ctrl+V
Mac:     Command+V

Undo
Windows: Ctrl+Z
Mac:     Command+Z

Application switch
Windows: Alt+Tab
Mac:     Command+Tab
```

Semantic shortcut mapping should be configurable.

Do not attempt to semantically translate every keyboard combination.

---

# 18. Mouse Requirements

Must support:

* relative pointer movement,
* left click,
* right click,
* middle click,
* vertical scroll,
* horizontal scroll,
* extra mouse buttons where identifiable.

The Logitech MX Master should support:

* main scroll wheel,
* horizontal thumb wheel,
* back/forward buttons.

Do not depend on Logitech Options+ behaviour.

KVM behaviour should operate independently of Logitech proprietary software where possible.

---

# 19. MacBook Trackpad Requirements

Initial trackpad support:

* pointer movement,
* primary click,
* secondary click,
* vertical two-finger scroll,
* horizontal two-finger scroll.

Later support:

* multi-finger gestures,
* gesture-to-semantic-action translation,
* pinch,
* workspace navigation gestures.

Do not block the initial implementation on advanced gesture support.

---

# 20. Gesture Translation

Future architecture should allow gestures to map to semantic actions.

Example:

```text
3-finger swipe up
```

Could map to:

```text
macOS
→ Mission Control

Windows
→ Task View
```

Represent semantic actions separately from raw input events if this feature is implemented.

---

# 21. Networking

Initial networking requirements:

* local-network operation,
* persistent connection,
* very low latency,
* encrypted communication,
* automatic reconnection.

Suggested initial implementation:

```text
mDNS
→ peer discovery

persistent TCP connection
→ event transport

TLS
→ encryption
```

QUIC may be evaluated later.

Do not introduce QUIC purely for perceived performance unless profiling demonstrates that TCP is inadequate.

---

# 22. Network Protocol

Do not serialise arbitrary internal Rust structs directly as the public wire protocol.

Create a versioned protocol.

Example message types:

```text
HELLO
AUTH
DEVICE_LIST
DEVICE_ADDED
DEVICE_REMOVED

DISPLAY_LIST
DISPLAY_UPDATED

KEY_DOWN
KEY_UP

MOUSE_MOVE
MOUSE_BUTTON
SCROLL

POINTER_ENTER_DISPLAY
POINTER_LEAVE_DISPLAY

CLIPBOARD_UPDATE

PING
PONG

RELEASE_INPUT
```

Every connection should negotiate a protocol version.

Example:

```text
KVM Protocol v1
```

---

# 23. Input Ordering

Keyboard and button input must preserve ordering.

Example:

```text
Ctrl down
C down
C up
Ctrl up
```

must never arrive out of order.

Mouse movement may potentially be optimised or coalesced later if required.

Do not sacrifice keyboard/button event ordering for latency.

---

# 24. Loop Prevention

Remote input injection must never be captured and forwarded back to the source.

Required concept:

```text
physical input
→ eligible for routing

KVM injected input
→ never forward
```

Use platform-specific injected-event metadata and/or event tagging.

The protocol should also include origin information:

```rust
source_host
source_device
```

to assist loop prevention and diagnostics.

---

# 25. Local Input Suppression

When a device event is routed remotely, the local machine must not also process the same event.

Required behaviour:

```text
event captured
      ↓
determine destination
      ↓

LOCAL
→ allow/process locally

REMOTE
→ suppress local event
→ forward remote event
```

This must work reliably for keyboard presses and mouse actions.

---

# 26. Failsafe Behaviour

Failsafe reliability is mandatory.

The application must never permanently strand keyboard or mouse input.

## Network failure

If the remote host disconnects:

```text
remote host unavailable
→ immediately stop remote routing
→ restore local control
```

## Daemon crash

The OS should naturally regain physical input if the daemon exits unexpectedly.

Avoid designs where recovery requires daemon cleanup.

## Emergency shortcut

Provide an emergency shortcut that can never be forwarded.

Example default:

```text
Ctrl + Alt + Shift + Backspace
```

Behaviour:

```text
release all captured input
reset active host to local
disable remote routing temporarily
```

Shortcut must be configurable.

---

# 27. Connection Health

Implement heartbeats.

Example:

```text
PING
PONG
```

Track:

* round-trip latency,
* connection state,
* last received packet,
* peer daemon status.

Possible states:

```rust
enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Degraded,
}
```

---

# 28. Pairing

The initial pairing process should not require manual IP entry.

Suggested flow:

1. Both applications discover each other via mDNS.
2. User selects a peer.
3. Both machines display a confirmation code.
4. User confirms pairing.
5. Long-term machine credentials are stored securely.

Future connections should happen automatically.

---

# 29. Security

Requirements:

* encrypted connections,
* authenticated peers,
* no unauthenticated remote input,
* paired device allowlist,
* secure credential storage,
* explicit approval when pairing a new machine.

The daemon should bind to the local network interface only by default.

Do not expose remote input control publicly over the internet in the initial release.

---

# 30. Clipboard

Initial clipboard support:

* plain text.

Later:

* images,
* files,
* rich clipboard types.

Clipboard synchronisation should avoid update loops.

Example:

```text
Mac clipboard update
→ Windows clipboard

Windows receives update
→ must not immediately retransmit identical update
```

---

# 31. Configuration

Persist configuration locally.

Example configuration areas:

```text
paired_hosts
display_layout
device_routes
keyboard_mapping
failsafe_shortcut
clipboard_enabled
startup_enabled
network_settings
```

Use a versioned configuration format to support future migrations.

---

# 32. Daemon Lifecycle

The daemon should:

* start automatically with the operating system,
* reconnect automatically,
* operate without the control panel,
* remain lightweight,
* log failures,
* expose status through local IPC.

The control panel should communicate with the daemon via local IPC rather than directly managing input hooks.

---

# 33. Control Panel

The UI should primarily configure and monitor the daemon.

Main screens:

## Workspace

Shows:

* both computers,
* all displays,
* physical layout,
* active display.

Supports drag-and-drop display positioning.

## Devices

Example:

```text
MX Master 3
● Follow active host
○ Windows
○ Mac
○ Local

Logitech Keyboard
● Follow active host
○ Windows
○ Mac
○ Local

MacBook Keyboard
● Follow active host
○ Windows
○ Mac
○ Local

MacBook Trackpad
● Follow active host
○ Windows
○ Mac
○ Local
```

## Connection

Show:

* peer status,
* ping,
* protocol version,
* connection state,
* last reconnect.

## Settings

Configure:

* startup,
* clipboard,
* modifier mapping,
* emergency shortcut,
* discovery.

---

# 34. UI Scope

The UI is not the priority.

Do not spend significant development time on visual polish before the KVM functionality is reliable.

Priority:

```text
input reliability
>
latency
>
reconnection
>
correct routing
>
configuration
>
visual polish
```

---

# 35. Logging

Use structured logging.

Important events:

```text
daemon started
peer discovered
peer connected
peer disconnected
input device added
input device removed
display configuration changed
active host changed
input routing changed
input capture error
input injection error
network timeout
failsafe triggered
```

Do not log every mouse movement by default.

Allow verbose/debug logging to inspect raw events when required.

---

# 36. Metrics / Diagnostics

Expose basic diagnostics:

* connection latency,
* event rate,
* dropped events,
* reconnect count,
* active host,
* active display,
* connected input devices.

Useful development metric:

```text
input_capture_timestamp
→ remote_injection_timestamp
```

This allows measurement of end-to-end KVM input latency.

---

# 37. Performance Targets

Target normal LAN input latency:

```text
< 10 ms end-to-end
```

Ideal wired LAN target:

```text
1–5 ms
```

These are engineering goals rather than hard protocol guarantees.

The daemon must not visibly impact:

* CPU usage,
* battery usage,
* foreground application responsiveness.

Idle CPU should remain close to zero.

---

# 38. Non-Goals for Initial Release

Do not initially implement:

* video/display streaming,
* remote desktop,
* audio forwarding,
* internet/WAN remote control,
* Linux,
* mobile platforms,
* advanced Mac trackpad gestures,
* USB device forwarding,
* game controller forwarding,
* drag-and-drop file transfer,
* remote login-screen management,
* cloud accounts.

This product controls input.

It does not stream displays.

---

# 39. Development Order

Build production architecture from the start.

Do not create a disposable prototype.

## Phase 1 — Foundation

Implement:

* Cargo workspace,
* shared types,
* daemon architecture,
* platform abstraction traits,
* logging,
* configuration.

Suggested interfaces:

```rust
trait InputBackend {
    fn enumerate_devices(&self) -> Vec<InputDevice>;
    fn start_capture(&mut self) -> Result<()>;
}

trait OutputBackend {
    fn inject(&self, event: &InputEvent) -> Result<()>;
}

trait DisplayBackend {
    fn displays(&self) -> Result<Vec<Display>>;
}
```

---

## Phase 2 — Networking

Implement:

* discovery,
* pairing,
* authentication,
* persistent encrypted connection,
* protocol framing,
* heartbeat,
* reconnection.

---

## Phase 3 — Keyboard

Implement bidirectional:

```text
Windows keyboard → Mac
Mac keyboard → Windows
```

Requirements:

* key down/up,
* modifier keys,
* suppression,
* injected-event filtering,
* emergency shortcut.

---

## Phase 4 — Pointer

Implement:

```text
Windows mouse → Mac
Mac trackpad/mouse → Windows
```

Support:

* movement,
* clicking,
* scrolling.

---

## Phase 5 — Logical Workspace

Implement:

* display enumeration,
* logical workspace,
* cross-display transition,
* DPI conversion,
* active host,
* active display.

---

## Phase 6 — Follow Active Host

Implement:

```text
pointer on Windows
→ keyboards route to Windows

pointer on Mac
→ keyboards route to Mac
```

This is the primary feature required to solve the target desk setup.

---

## Phase 7 — Device Routing

Implement per-device overrides:

```text
FollowActiveHost
Windows
Mac
Local
```

---

## Phase 8 — Logitech and Trackpad Support

Improve:

* high-resolution scrolling,
* horizontal scroll,
* extra mouse buttons,
* Mac trackpad scrolling.

---

## Phase 9 — Clipboard

Implement text clipboard synchronisation.

---

## Phase 10 — Control Panel

Implement:

* workspace editor,
* device list,
* route configuration,
* status,
* diagnostics,
* settings.

---

# 40. Definition of Initial Success

The software can be considered functionally successful when the following workflow works reliably for daily use:

1. Windows and Mac start.
2. KVM daemons start automatically.
3. They reconnect without user intervention.
4. User moves the MX Master across the three Windows monitors.
5. User moves the pointer through the configured boundary onto the MacBook.
6. Pointer appears naturally on macOS.
7. Logitech keyboard immediately types into macOS.
8. User switches to the MacBook trackpad.
9. Trackpad continues controlling the same Mac pointer.
10. User moves the Mac trackpad back across the boundary onto Windows.
11. Windows receives pointer control.
12. Logitech keyboard and MacBook keyboard now type into Windows.
13. No manual input switching occurs.
14. No duplicated input occurs.
15. Clipboard text works across systems.
16. Disconnecting either machine immediately restores safe local input.

---

# 41. Core Product Principle

The user should not need to think about which physical machine owns a keyboard or mouse.

The software should make:

```text
Windows PC
+
MacBook
```

behave like:

```text
one workstation
with four displays
and multiple interchangeable input devices
```

The physical machine boundary should become effectively invisible during normal desktop use.
