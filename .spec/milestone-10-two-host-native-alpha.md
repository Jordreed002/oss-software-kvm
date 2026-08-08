# Milestone 10 — Two-Host Native Runtime Alpha

## Status

In progress. The P3 prerequisite is complete; the platform-neutral, Linux, and Windows GNU gates
are green. Reviewed whole-host alpha capture implementations now exist for Windows and macOS, and
the fail-closed runtime profile, native lifecycle bridge, manual selected-peer candidate seam, and
static Unix preparation boundary are implemented. Active listener/connector/session composition,
Windows secure-file preparation, durable native display/hotplug follow-ups, and the complete
physical two-host acceptance matrix remain open.

M10 deliberately freezes the runtime topology at exactly two manually provisioned hosts. It uses
the M08 selected-peer execution policy and any compatible M09 exact-generation internals already
landed, but it does not enable arbitrary third-peer routing, concurrent remote destinations, or
multi-peer release settlement. Those remain disabled regardless of how many paired records a
configuration file can represent.

Completion requires evidence from physical Windows and macOS machines. Cross-compilation,
simulated backends, and observation-only diagnostics cannot complete this milestone.

## Objective

Produce a manually launched, headless alpha in which one explicitly provisioned Windows host and
one explicitly provisioned macOS host can:

- establish their authenticated exact-generation session;
- publish current native input and display inventory;
- move pointer authority across a statically configured two-host display boundary;
- route whole-host keyboard, pointer, buttons, and supported scroll input to the active host;
- suppress an event on its source host only from the native synchronous callback and only after
  the exact selected-peer FIFO accepted that event;
- inject received input with a native loop-prevention tag;
- fail open to usable local input on startup, permission, readiness, callback, queue, transport,
  topology, hotplug, shutdown, and unexpected-process failure;
- release or quarantine previously routed held controls through the existing bounded daemon
  lifecycle before reopening remote routing.

This is an operator alpha, not a consumer release. Its purpose is to prove one real Windows/macOS
pair end to end without weakening the security and exact-generation work already completed.

## Release decision and fallback

The runtime may expose an `alpha` enable switch only after both native suppression paths pass the
physical acceptance matrix in this document. Before then, native backends remain observation-only
and the production runtime must refuse to enable routing.

Any unproved platform, permission state, event origin, display mapping, peer generation, inventory
state, or callback outcome means `AllowLocal`. A first key/button press is never suppressed unless
its exact remote Input frame entered the selected admitted FIFO. Once a lifecycle has been
suppressed remotely, ordinary queue or transport failure follows the existing bounded
release/quarantine rules; a loss of the native decision path itself activates the global alpha
escape, disables further suppression, and restores local input rather than leaving the machine
captured.

If Windows or macOS cannot meet the synchronous callback latency, loop exclusion, whole-host
suppression, failsafe, and teardown tests, M10 ships only the separate runtime skeleton and native
diagnostics. It must not claim an operational KVM and must not weaken classification or silently
enable asynchronous best-effort suppression.

## Alpha scope boundary — whole host, not physical device

The suppressible Windows low-level hooks and macOS Quartz event tap do not provide the durable
physical device identity exposed by Raw Input and IOHID. M10 therefore makes an explicit product
tradeoff: while remote authority is active, capture and suppression apply to the source host's
entire supported keyboard and pointer event stream.

- the alpha exposes one deterministic, host-scoped aggregate input source for routing policy;
- the aggregate source covers keyboard, relative pointer movement, supported buttons, and
  vertical/horizontal scroll;
- all supported local keyboards and pointing devices follow the same active-host decision;
- `Local` and per-physical-device route exceptions are disabled in alpha mode;
- physical Raw Input/IOHID inventory remains useful for diagnostics and hotplug safety, but it is
  not presented as suppression attribution;
- no timestamp-only, order-only, or proximity-only correlation between Raw Input/IOHID and the
  suppressible hook/tap is permitted;
- any relevant physical-device removal gates the whole aggregate source, releases all of its
  remote-held controls, and requires a fresh stable inventory plus explicit automatic rearm under
  the unchanged two-host policy;
- unsupported absolute devices, gestures, consumer controls, touch, pen, and ambiguous native
  records remain local.

The aggregate `DeviceId` must be stable for the host and domain-separated from physical hardware
IDs. It must not change after USB reconnect, reboot, docking, or keyboard replacement. Real
physical device IDs remain separately stable and private for inventory and diagnostics.

## Non-overlap and architecture boundary

M10 may modify native platform crates, platform-neutral runtime-facing APIs, diagnostics, and root
composition. It must preserve the M09 restriction on arbitrary multi-peer routing and must not
add UI, clipboard, audio, installer, or automatic pairing scope.

Add a separate `crates/kvm-runtime` package:

- `kvm-daemon` remains a platform-neutral library containing routing, exact-session, inventory,
  pointer, cleanup, and peer-manager state machines;
- `kvm-windows` and `kvm-macos` remain native adapters and must not construct network, security,
  persistence, or peer-manager state;
- `kvm-runtime` depends on `kvm-daemon` and uses target-specific dependencies on exactly one native
  backend per build;
- `kvm-runtime` owns concrete startup/shutdown composition, native callback bridging, clocks,
  task supervision, OS signal handling, and the production executable;
- no dependency cycle may be introduced by making `kvm-daemon` depend on either native crate;
- the old `kvm-daemon` binary, if retained temporarily, remains an inert diagnostic shell and
  cannot offer a second production composition path;
- there is exactly one `PeerManager`, one mutable routing authority, one native capture owner, and
  one selected-peer runtime per process.

The runtime API must be dependency-injected and testable with fake native backends, fake clocks,
bounded transports, and temporary configuration stores. Platform crates expose capabilities and
affine lifecycle owners; they do not expose cloneable suppression handles or raw native handles to
unrelated crates.

## Workstream A — Runtime profile and two-host admission

- add an explicit, versioned `two_host_native_alpha` runtime profile which is disabled by default;
- require exactly one local identity and exactly one configured selected peer;
- reject a third runtime peer, an ambiguous host-to-peer mapping, or a route targeting any host
  other than local or selected before native suppression starts;
- retain `FollowActiveHost` as the only effective aggregate input route;
- require the exact current admitted peer, negotiated compatible protocol, fresh inventory,
  compiled two-host workspace, healthy sender task, and workspace readiness before remote capture
  can return `SuppressLocal`;
- use the P3 exact admitted endpoint facade for every workspace and routing mutation; never recover
  authority from `HostId`, `PeerId`, a sender clone, or a stale generation token;
- keep replacement generations blocked or gated until old held-state cleanup has reached the
  guarantees of the selected two-host path;
- never infer authorization from discovery, IP address, hostname, native device identity, or a
  successful TLS connection alone;
- publish a coarse runtime state: `Starting`, `LocalOnly`, `PeerReady`, `Routing`, `Degraded`,
  `Stopping`, or `Faulted`, with no input payloads, stable IDs, credentials, routes, generations,
  or native handle values in ordinary diagnostics.

The alpha starts `LocalOnly`. `Routing` is an earned state and is revoked immediately when any
required readiness fact becomes stale.

## Workstream B — Synchronous whole-host capture and suppression

Replace the production use of observation-only asynchronous delivery with a separate explicitly
suppressible backend mode. Observation mode remains available to diagnostics and never suppresses.

### Shared callback contract

- invoke the routing decision synchronously from the OS hook/tap callback;
- perform only bounded canonical translation, loop classification, a nonblocking/try-only access
  to serialized routing authority, and an exact bounded FIFO enqueue;
- perform no socket I/O, TLS work, DNS, discovery, disk I/O, configuration write, allocation with
  attacker-controlled size, sleep, async wait, blocking mutex wait, or tracing of event payloads;
- return `SuppressLocal` only from an explicit daemon outcome whose exact remote frame was accepted
  by the current selected-peer FIFO;
- return `AllowLocal` for unknown, invalid, unsupported, stale, injected, unready, contended,
  queue-full-first-press, panicking, timed-out, or otherwise ambiguous events;
- preserve the daemon's exact held lifecycle for repeats and releases after a successful suppressed
  first press; queue failure enters its cleanup/quarantine path and cannot retarget the lifecycle;
- catch unwinds at every Rust/native boundary and default to the platform's pass-through result;
- positively bound callback duration and expose only coarse latency/timeout counters;
- make start/stop affine, idempotent at the runtime boundary, same-thread correct where required,
  and bounded; stop must disable suppression before waiting for worker teardown.

### Windows

- use `WH_KEYBOARD_LL` and `WH_MOUSE_LL` or another reviewed synchronous Win32 mechanism for the
  alpha capture source; Raw Input remains inventory/observation only;
- translate scan position, make/break, auto-repeat, relative movement, supported buttons, and
  wheels conservatively; track held keys so the first make is `Pressed`, later makes are
  `Repeated`, and break is `Released`;
- recognize `LLKHF_INJECTED`, `LLKHF_LOWER_IL_INJECTED`, mouse injected flags, and
  `dwExtraInfo`; KVM-tagged or OS-marked injected events never re-enter routing or activate the
  failsafe;
- return the documented nonzero hook result only for `SuppressLocal`; call the next hook for every
  allow-local, unsupported, and failure outcome;
- run the hook on an owned message-loop thread and detect hook removal, message-loop termination,
  desktop/session changes, secure-desktop transitions, and callback timeout as local-only faults;
- treat UIPI refusal, partial `SendInput`, and elevated-target limitations as injection failure and
  run exact remote cleanup; never elevate or install a driver for this alpha;
- keep process-global registration/hook ownership generation-bound so stale teardown cannot remove
  a replacement owner.

### macOS

- use a listen/suppress-capable Quartz event tap as the aggregate alpha capture source; IOHID
  remains physical inventory/observation and hotplug evidence;
- translate supported key, repeat, relative pointer, button, and scroll events without relying on
  timestamp correlation with IOHID;
- inspect `kCGEventSourceUserData` and other reviewed source metadata; events carrying
  `KVM_EVENT_TAG`, events proved synthetic, and tap-generated control notifications never re-enter
  routing or activate the failsafe;
- return `NULL` only for `SuppressLocal`; return the original event for allow-local and all failure
  paths;
- detect disabled taps, timeout disablement, permission revocation, run-loop exit, sleep/wake, and
  console-session change and immediately enter local-only state;
- require Accessibility and Input Monitoring before enabling the alpha, but make their absence or
  revocation a coarse local-only result, never a retry loop in the callback;
- retain/release Core Foundation objects on the correct threads and bound tap start/stop.

Because event-origin guarantees differ by OS, each native implementation must document the exact
evidence used to classify an event. Any alpha-only trust assumption about other same-user local
processes must be explicit in diagnostics and the physical report; it cannot be described as
cryptographic proof of physical origin.

## Workstream C — Loop tagging, injection, and emergency escape

- tag every Windows `SendInput` record with `KVM_INJECTION_TAG` and every macOS Quartz event with
  `KVM_EVENT_TAG` before posting it;
- verify on physical hosts that the synchronous capture API observes and excludes those exact
  tags for key, repeat, movement, every supported button, and both wheel axes;
- never accept a network-provided tag, classification, host ID, device ID, or timestamp as native
  trust evidence;
- keep a bounded receiver-side held ledger and synthesize releases after disconnect, degradation,
  injection failure, revocation, shutdown, and exact-session retirement;
- make partial batch injection explicit; never report a release applied until every covered native
  release succeeded and the held ledger committed removal;
- preserve scan-code/virtual-key location, left/right modifiers, extended keys, signed wheel
  values, and finite/range validation through both directions;
- reject unsupported keys/buttons without substituting another native input.

The configured emergency chord is evaluated from locally captured, non-KVM input before ordinary
remote suppression. When it completes:

1. the triggering event and remaining chord lifecycle are allowed locally;
2. a callback-safe atomic escape flag prevents every later event from being suppressed;
3. all aggregate capture is gated and the active host returns local;
4. remote-held cleanup is attempted through its exact selected generation;
5. routing remains suspended for the configured interval and requires complete readiness before
   automatic rearm.

Emergency escape must still work with the network task wedged, queues full, the peer gone, the
runtime control task busy, and native inventory changing. A second independent escape is process
termination: termination or crash must cause the OS to remove hooks/taps and restore local input.

## Workstream D — Native inventory, display identity, and hotplug

Wire real native snapshots and changes into the existing bounded inventory authorities before
starting suppressible capture.

### Input inventory

- publish a complete initial physical inventory and the aggregate alpha source at a checked local
  revision;
- translate native arrival/removal into exact-next local inventory changes, or publish a complete
  newer snapshot after any gap;
- preserve Windows device IDs across reboot with Container-ID-scoped collection identity where
  proven; never use a native `HANDLE` as durable policy identity;
- surface a coarse `unstable_identity` capability when Windows Container ID or durable macOS
  identity material is unavailable instead of silently claiming persistence;
- keep Raw Input paths, IORegistry paths, serials, container IDs, native handles, and unhashed
  identity material private and absent from normal diagnostics;
- on relevant arrival/removal, gate the aggregate source before mutating inventory, release all
  remote-held aggregate controls, quarantine still-physical state where knowable, commit the new
  inventory, then rearm only from a fresh quiescent state;
- handle unplug while held, receiver removal, handle reuse, duplicate same-model devices, sleep,
  wake, docking, and callback/listener loss without leaving remote input held;
- never rebuild a device-handle cache as the sole hotplug action.

### Display inventory

- enumerate all active displays before compiling the two-host workspace and publish checked native
  revisions on add/remove/mode/scale/layout changes;
- derive Windows `DisplayId` from durable private DisplayConfig target/device identity mapped to
  the GDI source, not from transient `\\.\DISPLAYn` alone;
- use a durable reviewed macOS display identity and define a coarse unstable fallback when a panel
  supplies insufficient identity material;
- define one shared coordinate contract: `logical_size` is normalized logical extent,
  `physical_size` is pixels, and the native bounds field must be renamed/documented or converted
  consistently rather than containing Windows physical pixels under a logical-coordinate claim;
- preserve mixed-DPI physical adjacency and use normalized logical edge position for cross-host
  pointer mapping;
- gate pointer handoff and return active authority local when a display revision invalidates the
  configured workspace; do not guess a replacement display by name, index, resolution, or primary
  flag;
- require explicit static placement for the alpha; native adjacency never creates a remote link by
  itself.

## Workstream E — Concrete runtime composition

The `kvm-runtime` startup order is normative:

1. parse the alpha command and load bounded configuration without starting native capture;
2. load the manually provisioned local identity, credential, paired peer, and trust pin;
3. acquire the single-process runtime lock;
4. probe permissions/capabilities and enter `LocalOnly` on any missing requirement;
5. enumerate native input/displays, validate stable identity capability, and compile the static
   two-host workspace;
6. start the secure listener/connector and admit the exact selected peer generation;
7. exchange and validate fresh device/display snapshots and establish workspace readiness;
8. start native injection ownership, then the suppressible capture owner in pass-through mode;
9. publish the callback routing handle and atomically enable alpha suppression only after all prior
   stages are current;
10. supervise transport, admission, inventory, topology, native lifecycle, callback health,
    heartbeat, failsafe, signals, and checked timers until shutdown.

Shutdown and terminal fault order is also normative:

1. atomically disable native suppression and gate new capture;
2. return active authority local and drain exact selected-generation remote cleanup while bounded;
3. stop/uninstall the native hook or event tap and prove the owner thread exited;
4. retire the admitted session and transport tasks;
5. release native injection, inventory, process lock, and redacted diagnostics resources.

Cleanup timeout never keeps native suppression enabled. An unacknowledged remote release may keep
future remote routing gated, but it cannot keep the operator's local keyboard or pointer seized.

All runtime tasks are owned by one supervisor tree. Detached tasks, leaked hook threads, cloned
senders, and a second independent daemon core are forbidden. A child panic, unexpected task exit,
or channel closure is a terminal local-only transition and appears in a coarse health snapshot.

## Workstream F — Manual provisioning alpha boundary

M10 does not implement pairing UI, certificate issuance UX, Keychain/Credential Manager storage,
automatic startup, or installer flows. The operator provisions both hosts out of band.

- provide documented commands and a schema for two explicit host IDs, peer IDs, bind/connect
  addresses, TLS certificate/key paths, exact peer certificate fingerprints, selected-peer
  mapping, static display placements/links, and the alpha enable flag;
- require mutual TLS, exporter-bound admission, the paired allowlist, exact host/peer match, and
  downgrade-safe protocol negotiation already implemented by earlier milestones;
- reject plaintext, trust-on-first-use, wildcard peers, hostname-only trust, discovery-derived
  trust, missing key-file protections, duplicate identities, nil IDs, and an extra runtime peer;
- require owner-only private-key/config permissions where the OS exposes them and refuse to print
  credentials, fingerprints, proofs, paths, or stable native identity material in ordinary logs;
- permit mDNS only as an address hint after explicit trust is loaded; an explicit address remains
  the supported recovery path;
- make the operator invoke the runtime manually in a foreground terminal for this alpha;
- display a clear startup warning that whole-host input is captured while routing is enabled and
  state the configured emergency chord without writing it to ordinary persistent logs.

The threat boundary assumes the manually provisioned local user account and machine are trusted.
It does not protect against an already-compromised local desktop session, kernel/driver attacks,
or a malicious Accessibility/UIAccess process. Remote peers, networks, discovery records, and old
connection generations remain untrusted and must satisfy all existing authentication checks.

## Safety invariants

1. M10 admits exactly one selected remote peer and never enables an arbitrary third-peer route.
2. Native suppression is whole-host and explicit; no code claims per-device suppression.
3. The OS callback itself makes the final synchronous pass/suppress decision.
4. Ambiguity, contention, stale state, or first-event enqueue failure returns `AllowLocal`.
5. `SuppressLocal` proves exact FIFO acceptance on the current admitted selected generation.
6. A held lifecycle never migrates between local/remote or connection generations.
7. KVM-tagged and proved synthetic events never re-enter routing or trigger the failsafe.
8. Emergency escape disables suppression without network, disk, discovery, or UI cooperation.
9. Hook/tap removal, runtime exit, panic, permission loss, or teardown restores local OS input.
10. Hotplug and display revision gate before inventory/topology mutation and cannot strand held
    remote input.
11. Physical and display identities are stable where claimed; degraded fallback is explicit.
12. Exactly one runtime, `PeerManager`, mutable routing core, capture owner, and selected session
    capability exist per process.
13. Startup enables suppression last; shutdown disables suppression first.
14. All native queues, callback work, inventories, held sets, tasks, retries, strings, files, and
    counters are positively bounded and checked.
15. Input payloads, credentials, stable IDs, native paths/handles, routes, and exact generations
    remain absent from normal Debug, errors, tracing, crash text, and committed evidence.

## Automated and adversarial acceptance

Deterministic tests must cover at least:

- alpha profile disabled by default and refusal of zero, duplicate, ambiguous, or more than one
  selected remote peer;
- third-host route rejection even when that peer is paired, discovered, connected, or admitted;
- startup failure at every numbered composition stage leaves capture pass-through and tears down
  all previously acquired owners in reverse order;
- callback allow-local for no session, stale/replaced generation, wrong peer, stale inventory,
  invalid workspace, handoff pending, queue full on first press, try-lock contention, unsupported
  event, non-finite value, injected flag/tag, panic, and checked-counter exhaustion;
- callback suppression only after the exact selected FIFO accepts the corresponding frame;
- press/repeat/release and button lifecycles preserve their exact latch under route, focus,
  generation, health, and inventory changes;
- Windows auto-repeat produces `Pressed`, `Repeated`..., `Released`, not duplicate fresh presses;
- unmatched repeat/release allocates no held state and remains local;
- KVM-tagged Windows and macOS injection is excluded for every supported event kind;
- forged remote classification/tag fields cannot bypass native origin handling;
- queue full/closed before first press fails open; failure after a suppressed press triggers bounded
  cleanup/quarantine and cannot retarget the lifecycle;
- callback panic, callback deadline breach, hook/tap disablement, run-loop/message-loop exit,
  permission revocation, injection failure, and runtime task loss atomically disable suppression;
- emergency chord succeeds with full queues, dead peer, blocked control task, and concurrent
  hotplug, and remains local through release;
- physical add/remove, removal while held, handle reuse, duplicate devices, revision gap, and
  reconnect produce deterministic inventory and whole-host cleanup;
- Windows Container-ID collection identities distinguish same-model devices and remain stable
  across supplied reboot fixtures; unstable fallback is reported;
- Windows display identity does not depend solely on `DISPLAYn`; reorder/dock fixtures preserve
  target identity or invalidate explicitly without misbinding;
- mixed-DPI geometry obeys the chosen logical/pixel contract and normalized edge mapping in both
  directions;
- display add/remove/mode/scale change gates handoff until a fresh compiled workspace exists;
- transport EOF, heartbeat degradation, revocation, stale terminal event, replacement generation,
  old release ack, and shutdown affect only the exact selected generation;
- simulated process termination drops every affine native owner and leaves a fresh runtime able to
  acquire capture immediately;
- maximum-plus-one inventory, display, held-control, queue, retry, path, and configuration inputs
  fail atomically;
- marker-based redaction tests cover event values, chord keys, IDs, native paths/handles, display
  identity, credentials, fingerprints, session/generation values, and backend errors.

Native callback tests must include a watchdog and assert a conservative platform-specific upper
latency bound without flaky wall-clock assumptions in ordinary unit tests. Integration stress
tests must saturate motion while preserving every admitted key/button transition or entering an
explicit discontinuity/local-only state.

## Physical-host acceptance

Run the same reviewed build on one physical Windows 11 host and one physical supported macOS host.
Commit only redacted reports under `docs/validation/windows/` and `docs/validation/macos/`; never
commit raw input traces, native paths, serials, credentials, or private topology details.

The operator matrix must prove both Windows-to-macOS and macOS-to-Windows operation:

- manual startup, exact peer admission, local-only startup failure, reconnect, clean shutdown, and
  immediate local input after process kill;
- ordinary typing, held-key auto-repeat, left/right modifiers, shortcut chords, key rollover,
  supported international/navigation/media keys, and release while crossing hosts;
- relative pointer motion, all supported buttons, drag while crossing, vertical and horizontal
  wheel, high-rate motion, and fractional accumulation;
- KVM-tagged loop exclusion under continuous bidirectional injection;
- emergency chord while idle, while a key/button is remotely held, during queue saturation, after
  network loss, and after the remote runtime is killed;
- unplug/replug each external input class, unplug while key/button held, receiver removal, alternate
  USB port, sleep/wake, console lock/unlock, and one post-fix reboot per host;
- built-in and external macOS input coexistence under the documented whole-host scope;
- display reorder, mode/scale change, mixed-DPI crossing, dock/undock where available, and stable
  display identity across restart;
- permission denial and live revocation on macOS; standard-user, elevated-target/UIPI, UAC secure
  desktop, session lock, and desktop switch behavior on Windows;
- network cable/Wi-Fi loss, peer restart, stale generation traffic, repeated reconnect, and
  heartbeat degradation without stuck or duplicated input;
- at least one sustained high-load run and repeated start/stop cycles with callback latency,
  queue drops, discontinuities, ignored/allowed events, injection failures, CPU, and recovery
  summarized coarsely.

Acceptance requires human confirmation that local input was always recoverable, no key/button
remained held on either host, no event looped between hosts, and no input appeared on both hosts
after a successful suppression decision. Every deferred or inconclusive safety row is a milestone
blocker, not a pass.

## Quality gates

Before physical testing:

```text
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff --check
```

Platform gates are mandatory:

- native Windows MSVC workspace check, tests, and strict Clippy on Windows 11;
- Windows GNU workspace check and strict Clippy where supported, with the MinGW C toolchain
  installed for transitive native dependencies;
- native Apple Silicon macOS workspace check, tests, and strict Clippy;
- x86_64 macOS check when that binary remains a supported deliverable;
- release-profile builds of `kvm-runtime` on both physical hosts;
- bounded sanitizer/Miri/model tests where supported for platform-neutral unsafe-adjacent state;
- independent native lifecycle/suppression, runtime composition, and security/privacy audits with
  no remaining blocker or high-severity finding.

A scoped native crate check against a stub daemon API is useful for Win32 binding compatibility but
does not satisfy the full Windows workspace gate. Cross-compilation does not substitute for native
hook/tap execution or physical acceptance.

## Workstream delivery order

1. freeze and gate the M09 P3 exact-session facade; keep third-peer execution disabled;
2. add `kvm-runtime` with fake-native startup/shutdown composition and no suppression;
3. define the aggregate whole-host source, alpha policy validation, and synchronous callback
   contract with deterministic fakes;
4. complete native inventory/hotplug and durable display identity/coordinate repairs;
5. implement Windows synchronous hook capture/suppression, repeat tracking, tagging, and teardown;
6. implement macOS synchronous event-tap capture/suppression, tagging, permissions, and teardown;
7. compose one manually provisioned selected peer end to end with suppression disabled by default;
8. pass automated/adversarial gates and independent audits;
9. enable the explicit alpha flag only for the reviewed physical acceptance run;
10. accept M10 only after every physical safety row passes on both hosts.

Each workstream lands with suppression disabled unless all prerequisites below it are complete. A
partially implemented native backend cannot be selected by the production runtime.

## Explicitly deferred

- arbitrary third-peer and concurrent multi-peer routing;
- completing M09 multi-FIFO release settlement solely to support more than two hosts;
- per-physical-device suppression or mixed `Local`/remote device policies;
- timing-based Raw Input/low-level-hook or IOHID/Quartz correlation;
- pairing UI, certificate issuance/recovery UI, automatic trust bootstrap, and trust-on-first-use;
- Windows Credential Manager and macOS Keychain production provisioning;
- background service/launch agent, auto-start, installer, updater, code signing/notarization, and
  consumer packaging;
- Tauri control panel and local management IPC beyond a minimal read-only health mechanism;
- clipboard, file transfer, audio, touch, pen, gestures, absolute pointing devices, advanced
  Logitech features, and gaming/raw-exclusive input;
- driver-level interception, kernel extensions, privileged helpers, elevation, and secure-desktop
  control;
- WAN traversal, relays, untrusted-network discovery, mobile hosts, Linux runtime, and more than
  one selected peer;
- unattended daily-driver claims, performance promises, or general release support.
