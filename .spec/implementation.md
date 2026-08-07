# Software KVM — Codex Implementation Specification

## Objective

Build a production-quality, bidirectional software KVM for Windows 11 and macOS.

The software must make a Windows workstation and MacBook behave like one multi-display workspace.

Target physical setup:

```text
Windows PC
├── Monitor 1
├── Monitor 2
├── Monitor 3
├── Logitech mechanical keyboard
└── Logitech MX Master mouse

MacBook Pro
├── Built-in Retina display
├── Built-in keyboard
└── Built-in trackpad
```

All input devices must be capable of controlling either host.

The normal user experience must require no manual KVM switching.

Pointer position determines the active host.

---

# 1. Engineering Principles

Follow these principles throughout implementation.

## 1.1 Production architecture immediately

Do not create a throwaway proof of concept.

Each implementation milestone must contribute directly to the final architecture.

Temporary debug binaries and test harnesses are allowed, but shared core logic must not be duplicated into them.

## 1.2 Native daemon owns KVM functionality

KVM functionality must run in a Rust daemon.

The graphical application is only a configuration and monitoring client.

Closing or crashing the UI must not interrupt KVM operation.

## 1.3 Platform-neutral core

Platform-specific APIs must be isolated behind interfaces.

The following must not directly depend on Win32 or Apple APIs:

* routing
* network protocol
* topology
* pairing
* peer state
* clipboard protocol
* configuration
* diagnostics

## 1.4 Input has highest priority

Priority order:

```text
input correctness
>
failsafe behaviour
>
input latency
>
connection reliability
>
display transitions
>
clipboard
>
audio
>
UI polish
```

Never allow clipboard, audio, logging, discovery, or UI work to block the input-processing path.

---

# 2. Repository Structure

Create a Cargo workspace.

```text
software-kvm/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── rustfmt.toml
├── clippy.toml
│
├── crates/
│   ├── kvm-types/
│   │   └── shared domain types
│   │
│   ├── kvm-protocol/
│   │   └── wire protocol and framing
│   │
│   ├── kvm-router/
│   │   └── device and host routing
│   │
│   ├── kvm-topology/
│   │   └── display workspace model
│   │
│   ├── kvm-network/
│   │   └── discovery, transport and peers
│   │
│   ├── kvm-security/
│   │   └── pairing and identity
│   │
│   ├── kvm-config/
│   │   └── persistent configuration
│   │
│   ├── kvm-clipboard/
│   │   └── clipboard synchronisation
│   │
│   ├── kvm-audio/
│   │   └── optional audio transport
│   │
│   ├── kvm-windows/
│   │   └── Windows native backend
│   │
│   ├── kvm-macos/
│   │   └── macOS native backend
│   │
│   └── kvm-daemon/
│       └── production daemon
│
├── apps/
│   └── control-panel/
│       ├── Tauri
│       ├── React
│       └── TypeScript
│
├── tools/
│   ├── input-monitor/
│   ├── protocol-inspector/
│   └── latency-test/
│
└── docs/
    ├── architecture.md
    ├── protocol.md
    ├── security.md
    └── platform-notes.md
```

---

# 3. Rust Dependencies

Use maintained crates and verify current stable releases before pinning versions.

Expected categories:

```text
async runtime
→ tokio

serialization
→ serde

error handling
→ thiserror / anyhow where appropriate

logging
→ tracing
→ tracing-subscriber

IDs
→ uuid

TLS
→ rustls ecosystem

Windows APIs
→ windows crate

macOS
→ native FFI / appropriate maintained Rust Apple bindings

local IPC
→ platform-appropriate socket / named pipe abstraction
```

Do not introduce a dependency for functionality that is trivial to implement internally.

Do not expose third-party crate types across public domain interfaces unless there is a strong reason.

---

# 4. Core IDs

Create strongly typed identifiers.

Do not pass raw strings everywhere.

```rust
pub struct HostId(Uuid);

pub struct DeviceId(Uuid);

pub struct DisplayId(Uuid);

pub struct PeerId(Uuid);
```

These should implement the usual:

```rust
Clone
Copy where appropriate
Debug
Eq
Hash
Serialize
Deserialize
```

---

# 5. Host Model

```rust
pub struct Host {
    pub id: HostId,
    pub name: String,
    pub platform: Platform,
}

pub enum Platform {
    Windows,
    MacOS,
}
```

Do not hard-code exactly two hosts into protocol types.

The initial product supports two connected systems, but shared models should naturally tolerate more than two later.

---

# 6. Input Device Model

```rust
pub struct InputDevice {
    pub id: DeviceId,
    pub host_id: HostId,

    pub name: String,

    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,

    pub kind: DeviceKind,

    pub capabilities: DeviceCapabilities,
}
```

```rust
pub enum DeviceKind {
    Keyboard,
    Mouse,
    Trackpad,
    Other,
}
```

```rust
pub struct DeviceCapabilities {
    pub pointer: bool,
    pub keyboard: bool,
    pub vertical_scroll: bool,
    pub horizontal_scroll: bool,
    pub extra_buttons: bool,
}
```

Device IDs should remain stable across daemon restarts where sufficient hardware identity is available.

---

# 7. Input Event Model

All native input must be converted into a shared representation immediately.

```rust
pub struct InputEvent {
    pub sequence: u64,

    pub timestamp_ns: u64,

    pub source_host: HostId,
    pub source_device: DeviceId,

    pub payload: InputPayload,
}
```

```rust
pub enum InputPayload {
    Key {
        code: KeyCode,
        state: KeyState,
    },

    PointerMove {
        dx: f64,
        dy: f64,
    },

    PointerButton {
        button: PointerButton,
        state: ButtonState,
    },

    Scroll {
        horizontal: f64,
        vertical: f64,
    },
}
```

Do not use Windows VK codes or macOS key codes as the canonical `KeyCode`.

Create a platform-independent physical key representation.

Native backends perform translation.

---

# 8. Routing Model

```rust
pub enum DeviceRoute {
    FollowActiveHost,
    Local,
    Host(HostId),
}
```

```rust
pub struct RoutingTable {
    routes: HashMap<DeviceId, DeviceRoute>,
}
```

Default route for supported keyboard/mouse/trackpad devices:

```text
FollowActiveHost
```

Routing decision:

```rust
pub enum Destination {
    Local,
    Remote(HostId),
}
```

Router API:

```rust
pub trait InputRouter {
    fn destination(
        &self,
        event: &InputEvent,
        state: &WorkspaceState,
    ) -> Destination;
}
```

---

# 9. Workspace State

```rust
pub struct WorkspaceState {
    pub local_host: HostId,

    pub active_host: HostId,
    pub active_display: DisplayId,

    pub pointer: LogicalPointer,
}
```

```rust
pub struct LogicalPointer {
    pub display_id: DisplayId,
    pub x: f64,
    pub y: f64,
}
```

The pointer is a logical workspace pointer.

It must not be tied to the physical device that last moved it.

---

# 10. Display Model

```rust
pub struct Display {
    pub id: DisplayId,
    pub host_id: HostId,

    pub name: String,

    pub logical_size: Size,
    pub physical_size: Option<Size>,

    pub scale_factor: f64,

    pub refresh_rate: Option<f64>,

    pub native_bounds: Rect,

    pub primary: bool,
}
```

Refresh rate is metadata only.

Do not couple pointer movement timing to monitor refresh rate.

---

# 11. Workspace Topology

Represent all displays in one logical 2D coordinate system.

```rust
pub struct WorkspaceTopology {
    pub displays: HashMap<DisplayId, WorkspaceDisplay>,
}
```

```rust
pub struct WorkspaceDisplay {
    pub display: Display,
    pub workspace_bounds: Rect,
}
```

Provide:

```rust
fn display_at(point: Point) -> Option<DisplayId>;

fn adjacent_display(
    display: DisplayId,
    edge: Edge,
    position: f64,
) -> Option<DisplayId>;
```

`position` should represent normalised edge position:

```text
0.0 → start of edge
1.0 → end of edge
```

This prevents mismatched resolutions and DPI from producing pointer jumps.

---

# 12. Pointer Transition Algorithm

When local pointer movement reaches an edge:

```text
1. Determine active display.

2. Determine exit edge.

3. Ask WorkspaceTopology for adjacent display.

4. If none:
   clamp pointer normally.

5. If adjacent display belongs to same host:
   allow native transition.

6. If adjacent display belongs to remote host:
   calculate normalised edge position.

7. Send PointerEnter message.

8. Change active_host.

9. Change active_display.

10. Begin remote routing.

11. Keep subsequent pointer movement relative.
```

Reverse the process when entering a local display from the peer.

---

# 13. Windows Backend

Create:

```text
kvm-windows/
├── input/
├── injection/
├── displays/
├── clipboard/
├── audio/
├── startup/
└── permissions/
```

Use Windows Raw Input for physical input capture and device identification. Windows exposes raw keyboard, mouse and HID input as well as device enumeration and device information APIs.

Injection should initially use the Windows input synthesis APIs; `SendInput` supports synthesising keyboard, mouse movement and button input. Be aware that Windows integrity levels/UIPI can restrict injection into higher-integrity applications.

Implement:

```rust
pub struct WindowsInputBackend;
pub struct WindowsOutputBackend;
pub struct WindowsDisplayBackend;
```

Required first-pass Windows events:

```text
keyboard make
keyboard break

relative mouse movement

left button
right button
middle button

XBUTTON1
XBUTTON2

vertical wheel
horizontal wheel
```

Raw Windows mouse input exposes both wheel directions and additional X buttons, which should be preserved by the platform-neutral event model.

---

# 14. macOS Backend

Create:

```text
kvm-macos/
├── input/
├── injection/
├── displays/
├── clipboard/
├── audio/
├── permissions/
└── startup/
```

Use Apple's HID and Core Graphics event facilities as appropriate.

`IOHIDManager` provides HID device discovery/management, while `CGEvent` represents low-level input events and Quartz events can be posted into the event stream.

Implement:

```rust
pub struct MacInputBackend;
pub struct MacOutputBackend;
pub struct MacDisplayBackend;
```

Use a thin Swift or Objective-C bridge only where direct Rust integration becomes significantly worse.

The bridge must not own:

```text
routing
topology
networking
protocol
configuration
```

Those remain Rust.

---

# 15. Local Suppression

A remotely routed physical event must not also execute locally.

Required flow:

```text
physical input
      │
      ▼
capture
      │
      ▼
routing decision
   ┌───────┴────────┐
   ▼                ▼
 local            remote
   │                │
allow             suppress
                    │
                    ▼
                 network
```

Implement suppression independently per platform.

Do not globally disable all input merely because one device is remote-routed unless absolutely necessary.

---

# 16. Injected Event Detection

Prevent forwarding loops.

Never allow:

```text
Mac
→ inject Windows
→ Windows captures injected event
→ forward Mac
→ Mac captures event
→ ...
```

Every backend must classify:

```text
Physical
InjectedByKvm
Unknown
```

KVM-generated events must never enter remote-routing logic.

---

# 17. Networking Architecture

Create separate logical channels.

```text
Connection
│
├── Control
├── Input
├── Clipboard
├── Diagnostics
└── Audio
```

Even if several channels initially share one TCP/TLS connection, preserve the conceptual separation in code.

Input events must never wait behind:

```text
clipboard payloads
audio payloads
diagnostic dumps
configuration sync
```

---

# 18. Protocol Framing

Create an explicitly versioned wire protocol.

```rust
pub const PROTOCOL_VERSION: u16 = 1;
```

```rust
pub struct FrameHeader {
    pub protocol_version: u16,
    pub message_type: MessageType,
    pub payload_length: u32,
}
```

Possible messages:

```rust
pub enum ProtocolMessage {
    Hello(Hello),
    Authenticate(Authenticate),

    DeviceSnapshot(DeviceSnapshot),
    DeviceAdded(DeviceAdded),
    DeviceRemoved(DeviceRemoved),

    DisplaySnapshot(DisplaySnapshot),
    DisplayUpdated(DisplayUpdated),

    Input(InputEvent),

    PointerEnter(PointerEnter),
    PointerLeave(PointerLeave),

    Clipboard(ClipboardMessage),

    Ping(Ping),
    Pong(Pong),

    ReleaseInput(ReleaseInput),
}
```

Do not directly expose internal structs through automatic binary serialisation without protocol boundaries.

Protocol structs may resemble internal structs but must remain independently versionable.

---

# 19. Event Ordering

Input packets require monotonically increasing sequence numbers.

The receiver must preserve keyboard/button ordering.

Example:

```text
1021 Ctrl DOWN
1022 C DOWN
1023 C UP
1024 Ctrl UP
```

must remain in that order.

Mouse movement may eventually support coalescing.

Keyboard and mouse button events must not be coalesced.

---

# 20. Discovery

Implement LAN discovery using mDNS.

Expose something conceptually similar to:

```rust
pub struct DiscoveredPeer {
    pub name: String,
    pub address: SocketAddr,
    pub host_id: HostId,
}
```

Discovery must not imply trust.

A discovered host is not allowed to inject input until explicitly paired.

---

# 21. Pairing

Initial pairing workflow:

```text
discover
↓
select machine
↓
exchange ephemeral pairing information
↓
display matching verification code
↓
user approves both
↓
persist peer identity
```

Subsequent connections authenticate automatically.

Reject unpaired input connections.

---

# 22. Connection State

```rust
pub enum PeerState {
    Disconnected,
    Discovering,
    Connecting,
    Authenticating,
    Connected,
    Degraded,
}
```

Maintain heartbeat timestamps:

```rust
last_sent_ping
last_received_packet
last_received_pong
round_trip_time
```

---

# 23. Failure Recovery

This is a critical subsystem.

If peer health exceeds the failure threshold:

```text
stop remote routing
↓
release local suppression
↓
mark active host local
↓
restore local pointer
```

Input recovery must not depend on the UI.

---

# 24. Emergency Failsafe

Reserve a physical shortcut.

Initial default:

```text
Ctrl + Alt + Shift + Backspace
```

This shortcut must:

```text
never be forwarded
never be remapped
always be detected locally
```

Action:

```text
release all capture/suppression
clear pressed remote keys
reset active host
disable KVM routing temporarily
```

Make the shortcut configurable later.

---

# 25. Stuck Key Recovery

Track pressed keyboard and pointer buttons.

```rust
pub struct PressedState {
    keys: HashSet<KeyCode>,
    buttons: HashSet<PointerButton>,
}
```

When:

```text
peer disconnects
route changes
failsafe triggers
daemon shuts down
```

send corresponding release events where required.

Never leave remote Ctrl, Shift, Alt, Command or mouse buttons logically held down.

---

# 26. Keyboard Translation

Create:

```text
kvm-core/
keyboard/
├── physical.rs
├── platform.rs
└── semantic.rs
```

Support two modes.

## Physical

Translate the same physical key to the equivalent physical destination key.

## Semantic

Support an explicit small set of actions:

```rust
pub enum SemanticCommand {
    Copy,
    Paste,
    Cut,
    Undo,
    Redo,
    SelectAll,
    AppSwitch,
}
```

Do not automatically reinterpret arbitrary keyboard combinations.

---

# 27. Clipboard

Implement text clipboard first.

```rust
pub struct ClipboardUpdate {
    pub id: Uuid,
    pub origin: HostId,
    pub content: ClipboardContent,
}
```

```rust
pub enum ClipboardContent {
    Text(String),
}
```

Use update IDs/hashes to stop rebroadcast loops.

Do not send clipboard contents unless clipboard synchronisation is enabled.

---

# 28. Audio Architecture

Audio is optional and must not block initial KVM completion.

Create:

```text
kvm-audio/
├── capture.rs
├── playback.rs
├── packet.rs
├── jitter.rs
└── codec/
```

Audio flow:

```text
source OS
   │
capture
   │
normalise format
   │
packetise
   │
network
   │
jitter buffer
   │
playback
   ▼
destination audio device
```

Initial format target:

```text
48 kHz
stereo
PCM
```

Windows system output capture should use WASAPI loopback, which Microsoft documents specifically for capturing the stream played by a render endpoint.

macOS should use current Core Audio capture facilities, including Core Audio taps where appropriate for outgoing audio capture.

Later codec:

```text
Opus
```

Provide:

```rust
pub enum AudioMode {
    Disabled,
    Pcm,
    Opus,
}
```

Opus may be used where lower bandwidth or additional tolerance to network conditions is desirable; its API includes a restricted-low-delay application mode.

Audio routing should support:

```text
Windows → Mac
Mac → Windows
Disabled
```

Do not automatically send both directions simultaneously without explicit configuration because of feedback risk.

---

# 29. Audio Device Selection

Allow independent source and destination selection.

Example:

```text
Source:
Windows Default Output

Destination:
MacBook Pro Speakers
```

or:

```text
Source:
Mac System Output

Destination:
Windows USB Headset
```

Do not tie audio destination to pointer focus initially.

Later optionally support:

```text
Audio follows active host
```

---

# 30. Audio Isolation

Audio transport must use an independent bounded queue.

If audio is late:

```text
drop / conceal audio packet
```

Never:

```text
delay keyboard or mouse event
```

The input path always wins.

---

# 31. Daemon IPC

Provide local IPC between daemon and control panel.

Commands:

```text
GetStatus
GetPeers
GetDevices
GetDisplays
GetTopology

SetDeviceRoute
SetTopology

EnableKvm
DisableKvm

EnableClipboard
DisableClipboard

SetAudioRoute

TriggerFailsafe
```

Events:

```text
PeerChanged
DeviceChanged
DisplayChanged
ActiveHostChanged
ActiveDisplayChanged
LatencyChanged
ErrorOccurred
```

---

# 32. Control Panel

Use Tauri + React + TypeScript.

Do not implement it until core KVM routing is operational.

Required pages:

```text
Workspace
Devices
Connections
Audio
Settings
Diagnostics
```

---

# 33. Workspace UI

Show all screens as draggable rectangles.

Example:

```text
┌─────────┐ ┌───────────┐ ┌─────────┐
│ Win #1  │ │ Win #2    │ │ Win #3  │
└─────────┘ └───────────┘ └─────────┘

               ┌──────────┐
               │ MacBook  │
               └──────────┘
```

Display:

```text
host
display name
resolution
scale
refresh rate
```

Allow drag/drop layout changes.

---

# 34. Device UI

Example:

```text
MX Master 3

Routing:
● Follow active host
○ Windows
○ MacBook
○ Local
```

Same configuration for:

```text
Logitech keyboard
MacBook keyboard
MacBook trackpad
```

---

# 35. Diagnostics

Expose:

```text
connection state
round-trip latency
input event rate
dropped packets
peer uptime
protocol version
active host
active display
last reconnect
audio buffer health
```

Do not enable raw-event logging by default.

---

# 36. Performance Instrumentation

Timestamp events at:

```text
physical capture
routing decision
network send
network receive
injection request
```

Create development-only tracing that can calculate:

```text
capture → injection latency
```

Do not perform disk I/O on the real-time input path.

---

# 37. Testing Strategy

Create unit tests for:

```text
routing
topology
normalised coordinate conversion
keyboard state tracking
sequence handling
protocol encode/decode
configuration migration
clipboard loop suppression
```

Create integration tests for:

```text
peer connection
authentication
reconnection
protocol version rejection
stuck-key cleanup
failsafe activation
```

Platform integration testing will require actual Windows and macOS machines.

---

# 38. Codex Task Sequence

Execute tasks in this order unless a task exposes a dependency requiring adjustment.

## Task 1 — Workspace

Create Cargo workspace and crate structure.

Acceptance:

```text
cargo build
```

succeeds for platform-neutral crates.

---

## Task 2 — Domain types

Implement:

```text
HostId
DeviceId
DisplayId
Host
InputDevice
Display
InputEvent
```

Add tests.

---

## Task 3 — Protocol

Create v1 framing and serialisation.

Implement round-trip tests for every message.

---

## Task 4 — Router

Implement:

```text
FollowActiveHost
Local
Host
```

with unit tests.

---

## Task 5 — Topology engine

Implement logical display arrangement and adjacency calculation.

Test mismatched sizes and DPI.

---

## Task 6 — Daemon skeleton

Create daemon lifecycle:

```text
startup
config
logging
shutdown
```

No platform input yet.

---

## Task 7 — Network connection

Implement persistent local-network peer connection.

Do not add discovery yet.

Use explicit addresses for development only.

---

## Task 8 — Heartbeats/reconnect

Implement:

```text
PING
PONG
RTT
disconnect detection
reconnect
```

---

## Task 9 — Windows device enumeration

Enumerate Windows keyboards/mice.

Expose results through daemon diagnostics.

Windows Raw Input provides both input-event access and APIs for enumerating/querying raw input devices.

---

## Task 10 — Windows input capture

Capture:

```text
keyboard
mouse movement
buttons
wheels
```

Convert to `InputEvent`.

Do not forward yet.

---

## Task 11 — macOS device enumeration

Enumerate relevant HID devices through the macOS backend.

---

## Task 12 — macOS input capture

Capture:

```text
keyboard
pointer
buttons
scroll
```

Convert to shared events.

---

## Task 13 — Windows injection

Receive protocol `InputEvent`.

Inject:

```text
keyboard
pointer movement
buttons
scroll
```

`SendInput` is the initial Windows injection mechanism.

---

## Task 14 — macOS injection

Receive protocol events and generate native Quartz events.

Apple's `CGEventPost` posts Quartz events into the macOS event stream.

---

## Task 15 — One-way keyboard test

Achieve:

```text
Windows Logitech keyboard
→ Mac
```

Acceptance:

```text
letters
modifiers
backspace
enter
arrows
common shortcuts
```

work correctly.

---

## Task 16 — Bidirectional keyboard

Achieve:

```text
Windows → Mac
Mac → Windows
```

Implement injected-event filtering.

---

## Task 17 — Pointer forwarding

Implement:

```text
Windows mouse → Mac
Mac trackpad → Windows
```

Movement only first.

Then:

```text
click
right click
middle click
scroll
```

---

## Task 18 — Local suppression

Prevent remote-routed input from executing locally.

This task must include emergency recovery testing.

---

## Task 19 — Failsafe

Implement permanent local escape sequence.

Test daemon/network failure while remote input is active.

---

## Task 20 — Display enumeration

Enumerate:

```text
Windows three-monitor topology
MacBook display
```

Synchronise display snapshots between hosts.

---

## Task 21 — Cross-host pointer boundary

Connect one Windows display edge to MacBook.

Acceptance:

```text
move MX Master across edge
→ pointer enters Mac

move back
→ pointer returns Windows
```

No hotkey.

---

## Task 22 — Full workspace topology

Support all Windows displays plus MacBook.

Handle different:

```text
resolutions
DPI
scaling
refresh rates
```

Refresh rate must not influence pointer mapping.

---

## Task 23 — FollowActiveHost keyboards

When pointer is on Mac:

```text
Logitech keyboard → Mac
MacBook keyboard → Mac
```

When pointer is on Windows:

```text
Logitech keyboard → Windows
MacBook keyboard → Windows
```

---

## Task 24 — Interchangeable pointer sources

Required behaviour:

```text
MX Master moves pointer onto Mac

user stops touching MX Master

user uses MacBook trackpad

same logical workspace continues
```

Then allow Mac trackpad to return pointer to Windows.

---

## Task 25 — Per-device routing

Add:

```text
FollowActiveHost
Local
specific host
```

---

## Task 26 — Logitech improvements

Verify:

```text
vertical wheel
horizontal thumb wheel
back
forward
middle button
```

---

## Task 27 — Trackpad improvements

Verify:

```text
pointer movement
primary click
secondary click
vertical scroll
horizontal scroll
```

Ignore advanced macOS gestures initially.

---

## Task 28 — Pairing/security

Replace development address configuration with:

```text
mDNS discovery
pairing
peer authentication
secure persistent credentials
```

---

## Task 29 — Clipboard

Implement bidirectional plain-text clipboard.

---

## Task 30 — Startup integration

Configure agents to start automatically.

Required:

```text
Windows login/startup
macOS login/startup
automatic reconnect
```

---

## Task 31 — Control-panel IPC

Expose daemon state through local IPC.

---

## Task 32 — Tauri control panel

Implement functional UI.

No visual polish beyond usability.

---

## Task 33 — Workspace editor

Implement drag/drop display topology.

Persist layout.

---

## Task 34 — Audio proof

Implement:

```text
Windows WASAPI capture
→ PCM transport
→ Mac playback
```

Keep audio completely independent of input processing.

---

## Task 35 — Bidirectional audio

Implement:

```text
Windows → Mac
Mac → Windows
```

with selectable destination devices.

---

## Task 36 — Audio resilience

Implement:

```text
bounded buffer
small jitter buffer
underrun handling
clock drift handling
device-change handling
```

---

## Task 37 — Opus mode

Add optional Opus transport.

Keep PCM as preferred LAN mode.

---

## Task 38 — Production hardening

Run long-duration testing.

Test:

```text
sleep/wake
Mac lid close/open
Windows lock/unlock
network cable disconnect
Wi-Fi reconnect
display unplug
display reconnect
keyboard disconnect
mouse disconnect
daemon restart
peer restart
rapid pointer boundary crossings
holding modifiers during transition
holding mouse buttons during transition
```

---

# 39. Initial Production Acceptance Test

Do not consider the core KVM ready until this workflow can be repeated reliably:

```text
Boot Windows.

Log into Windows.

Open MacBook.

Both agents connect automatically.

Use MX Master across all three Windows monitors.

Move MX Master onto MacBook display.

macOS gains pointer control seamlessly.

Type using Logitech keyboard.

Text appears on Mac.

Use MacBook keyboard.

Text continues appearing on Mac.

Use MacBook trackpad.

Pointer continues naturally.

Move Mac trackpad onto Windows display.

Windows becomes active.

Type on MacBook keyboard.

Text appears in Windows.

Move MX Master.

Windows pointer continues normally.

Move MX Master onto Mac again.

Repeat without manual switching.
```

No input duplication.

No stuck keys.

No manual Easy-Switch.

No application restart.

No perceptible transition delay.

---

# 40. Final Architecture

Target architecture:

```text
               SOFTWARE KVM WORKSPACE

 ┌──────────────── Windows PC ────────────────┐
 │                                            │
 │ Monitor 1   Monitor 2   Monitor 3          │
 │                                            │
 │ Logitech Keyboard                          │
 │ MX Master                                  │
 │                                            │
 │     ┌──────── Windows KVM Agent ────────┐  │
 │     │ capture                           │  │
 │     │ inject                            │  │
 │     │ display topology                  │  │
 │     │ clipboard                         │  │
 │     │ audio                             │  │
 │     └────────────────┬──────────────────┘  │
 └──────────────────────┼─────────────────────┘
                        │
                 encrypted LAN
                        │
 ┌──────────────────────┼─────────────────────┐
 │     ┌────────────────┴──────────────────┐  │
 │     │ macOS KVM Agent                  │  │
 │     │ capture                          │  │
 │     │ inject                           │  │
 │     │ display topology                 │  │
 │     │ clipboard                        │  │
 │     │ audio                            │  │
 │     └───────────────────────────────────┘  │
 │                                            │
 │ MacBook Display                            │
 │ MacBook Keyboard                           │
 │ MacBook Trackpad                           │
 │                                            │
 └──────────────── MacBook ───────────────────┘
```

The end result should behave like one workstation with:

```text
4 displays
2 keyboards
2 pointing devices
2 operating systems
1 logical workspace
```

The user should normally have no reason to think about which physical computer owns a particular keyboard or pointer device.
