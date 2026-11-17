# Overhaul plan: a tray / menu-bar KVM utility with a small widget

**Author:** Opus design sub-agent. Written without reading any other overhaul proposal.
**Base:** branch `overhaul/widget-app-planning` at `9edb5ed` (from `code-review-remediation`).
**Status:** Planning only. No code changed. Nothing in this document is approved yet.

> **How claims are marked.** **[V]** means I checked it in the code at `9edb5ed` and cite the path.
> **[P]** means it is proposed behaviour. **[A]** means an assumption that needs a spike or sign-off.
> Line numbers are approximate and drift as the code changes.

---

## 0. Summary

The backend is not the problem. The input path, protocol, TLS/UDP transport, routing, failsafe and
native backends are large, tested and audited (`crates/`, about 80k lines, and `docs/audit/*conformant*.md`).
The current product feels like an engineering console for three reasons:

1. **Ownership is in the wrong process.** The Tauri webview app owns identity creation, LAN
   discovery, nearby pairing, display-map sync, config writing and runtime start/stop
   (`apps/control-panel/src-tauri/src/setup.rs`, `nearby.rs`). The UI says "Keep both setup
   consoles open" (`setup.rs` `start_runtime`). A tray utility cannot depend on a window staying open.
2. **The control contract is split.** Start/stop uses a file named `runtime.control` that the
   runtime checks every 250 ms. Status comes from the `runtime.status` file plus §31 IPC, but the
   panel only calls `GetStatus` (`control.rs`). Diagnostics use an unauthenticated LAN TCP port.
   Pairing uses a UDP protocol the panel owns.
3. **There is nothing to ship.** `bundle.active` is `false`. The runtime binary is found from an
   env var, a sibling file or `../../../target/release` (`setup.rs` `runtime_binary`). CI has no
   release workflow. There is no signing, updater, login item or uninstaller.

**Recommended path: a selective overhaul, not a full backend rewrite.** Keep the core crates. Turn
`kvm-runtime` into a long-lived, per-user, headless **agent**. Move setup, pairing, discovery and
config ownership out of the Tauri process and into that agent. Grow §31 into a single versioned
local **Control API v2** with event subscription. Then build a new, thin tray/menu-bar app around
a compact popover widget, a short onboarding window and a small settings window. Finish with
packaging, signing, update and uninstall.

---

## 1. Verified current state (grounding)

### 1.1 Processes and runtime ownership

| Fact | Evidence |
|---|---|
| **[V]** The Tauri app opens one 1180×790 resizable window titled "Software KVM · Link Console". There is no tray. | `apps/control-panel/src-tauri/tauri.conf.json` |
| **[V]** The Tauri app spawns `kvm-runtime run-managed <runtime.toml> <runtime.control>` as a child. stdout and stderr go to `runtime.log`. `SOFTWARE_KVM_DATA_DIR` is set. | `setup.rs` `start_runtime` (~L1385–1447) |
| **[V]** Stop writes `stop\n` to `runtime.control`. The runtime checks that file every 250 ms (`managed_stop_requested`). The app then busy-waits up to 15 s with `thread::sleep` inside a sync Tauri command. | `setup.rs` `stop_runtime`; `crates/kvm-runtime/src/main.rs` |
| **[V]** "One runtime only" is enforced by an exclusive `fs2` lock on `runtime.lock`. The app checks the lock to adopt a runtime it did not spawn. | `kvm-runtime/src/main.rs` `acquire_managed_lock`; `setup.rs` `runtime_lock_held` |
| **[V]** The app does not kill or stop the child on exit. There is no `Drop`, `RunEvent` or `on_window_event` handler. The runtime outlives the UI and can only be stopped through the control file. | grep of `src-tauri/src` |
| **[V]** The `kvm-daemon` binary is a lifecycle skeleton that uses random host IDs. The real entry point is `kvm-runtime`. | `crates/kvm-daemon/src/main.rs` |
| **[V]** The runtime installs a panic failsafe hook. A failsafe chord (Ctrl+Alt+Shift+Backspace) lives in the daemon, not the UI. | `kvm-runtime/src/main.rs`; `README.md` diagram |

### 1.2 IPC and network surfaces

| Surface | Evidence | Notes |
|---|---|---|
| **[V]** §31 local control: a Unix socket at `$TMPDIR/software-kvm-control.sock` (mode 0600 after bind), or the named pipe `\\.\pipe\software-kvm-control` with `reject_remote_clients(true)` | `crates/kvm-network/src/local_ipc.rs` | The Windows pipe uses the **default DACL** and does **not** set `first_pipe_instance`. That allows pipe-name squatting and lets other local principals connect. The module doc notes the Unix bind→chmod umask window. |
| **[V]** §31 vocabulary: `GetStatus/Peers/Devices/Displays/Topology`, `SetDeviceRoute`, `SetTopology`, `Enable/DisableKvm`, `Enable/DisableClipboard`, `SetAudioRoute`, `TriggerFailsafe` | `crates/kvm-protocol/src/control.rs` | The runtime drains only `TriggerFailsafe/EnableKvm/DisableKvm` (`kvm-runtime/src/active.rs` ~L520–570). Everything else answers `Internal` (`control_service.rs`). |
| **[V]** The service binds inside the active runtime only (`active.rs` ~L481) | `active.rs` | When KVM is stopped, nothing answers. That is why the UI has an `Unreachable` state (`control.rs`). |
| **[V]** Diagnostics are served as one JSON pull over TCP 24801. The doc calls the channel "deliberately unauthenticated", and it binds on the LAN listen address. | `crates/kvm-network/src/diagnostics.rs`; `active.rs` ~L1696 | It is read-only and redacted, but anyone on the LAN can still fingerprint it. |
| **[V]** Nearby discovery and pairing run on UDP 24801 (`software-kvm-presence/1`, `software-kvm-pairing/1`) with a 2-minute pairing expiry and a verification code. Signed display-map sync and the diagnostics relay also run here. | `apps/control-panel/src-tauri/src/nearby.rs` | They live in the **UI process**. |
| **[V]** TLS 1.3 mTLS on TCP 24800 and authenticated UDP pointer datagrams on 24802 | `README.md`, `docs/transport-v*.md` | Keep unchanged. |

### 1.3 Pairing, identity, config, secrets

- **[V]** The UI writes three overlapping stores into one app-data directory (`%LOCALAPPDATA%\…\runtime` on
  Windows, with icacls ACL hardening): `setup-state.json` (UI state, peer bundle, layout),
  `runtime.toml` (profile v2, string-formatted in `build_profile`) and `config.toml` (`kvm-config`).
  See `setup.rs` constants ~L45–54.
- **[V]** The TLS private key is written to a file, `local-key.pk8`, with restrictive permissions
  (`setup.rs` `secure_write`, `build_profile`). **This contradicts `docs/security.md`**, which says
  secret key material is stored in Keychain or Credential Manager and "never in the ordinary
  configuration file". Keychain and Credential Manager stores already exist but the app does not use them
  (`crates/kvm-macos/src/keychain.rs`, `crates/kvm-windows/src/credential_store.rs`,
  `crates/kvm-security/src/credential_store.rs`).
- **[V]** The pairing bundle is version 3 and the credential format is version 2. Legacy credential
  reset and migration code already exists (`setup.rs` `reset_legacy_credentials`, `migrate_legacy_windows_setup`).
- **[V]** The model is two hosts. The profile has exactly one `[selected_peer]`. Topology and routing
  are `selected_only`.

### 1.4 Permissions

- **[V]** On macOS, `probe_permissions()` checks `AXIsProcessTrusted` and `CGPreflightListenEventAccess`
  (`crates/kvm-macos/src/native.rs` ~L1372). The runtime's `diagnose-native` reports them. The UI
  only shows a hint after a `native_capture` fault (`App.tsx` ~L337). There is no proactive
  permission onboarding.
- **[V]** `Info.plist` declares `NSLocalNetworkUsageDescription` and Bonjour services.
- **[V]** On Windows, `docs/platform-notes.md` documents the UIPI limit on injection into elevated windows.
- **[V]** I found no handling of sleep/wake, session lock or fast user switching in either
  `crates/` or `src-tauri` (grep for `WTSRegisterSessionNotification`, `WM_POWERBROADCAST` and
  `WillSleep` returned nothing). **[A]** Some of this may be handled indirectly through hot-plug
  or session teardown. A spike needs to confirm.

### 1.5 Frontend

- **[V]** React 19, Vite 6, `lucide-react`, Manrope and Newsreader web fonts. `App.tsx` is a 4-step
  wizard ("This computer, Pair, Arrange, Ready") plus a diagnostics dashboard
  (`DiagnosticsDashboard.tsx`, `DashChart.tsx`, `components/diagnostics/*`).
- **[V]** The UI polls and does not subscribe: `setup_status` every 400 ms while running and 1200 ms
  otherwise (`App.tsx` ~L43), `DaemonStatusCard` every 2 s, plus a diagnostics poll loop.
- **[V]** `bridge.ts` has a browser preview mock. It contains a hard-coded `"Jordan’s Mac"`
  suggested name, which should be removed.
- **[V]** The capability is `core:default` on window `main`. The CSP is strict
  (`default-src 'self'`; `connect-src ipc:`). No shell or fs plugins are present.

### 1.6 Release

- **[V]** `bundle.active: false`. The identifier is `dev.software-kvm.control-panel`. Version is 0.1.0. No tags
  (`CHANGELOG.md`). `.github/workflows/ci.yml` only builds, lints and tests the app.

---

## 2. Product principles

1. **Invisible when working.** The default surface is a tray or menu-bar icon. Most days the user
   never opens a window.
2. **The input path never depends on UI.** UI crashes, hangs, updates and quits never strand
   input. The agent fails open (it releases keys and routes locally) whatever the UI does.
3. **One glance answers three questions:** Am I connected? Which computer has my keyboard? Is
   anything wrong?
4. **Every error has a next action.** No "coarse_error" dead ends. Every fault state links to one
   recovery action.
5. **Trust is explicit and reversible.** Pairing always shows a verification code on both machines.
   Forgetting a peer is one action and removes its keys.
6. **Native first, not web-app-in-a-frame.** System fonts, system materials, platform tray
   conventions, platform login-item and permission flows.
7. **Small footprint.** No resident webview when hidden (target); event-driven updates; zero
   measurable effect on input latency.
8. **Honest scope.** v1 pairs exactly two hosts on one LAN. The UI must not suggest multi-peer
   or WAN support.

---

## 3. Surfaces and flows (all [P])

### 3.1 Tray / menu-bar icon

A monochrome template icon (macOS) or a theme-aware glyph (Windows). **State is shown by glyph
shape, not by colour alone:**

| State | Glyph | Tooltip / accessible name |
|---|---|---|
| Not set up | outline link, dotted | "Software KVM: not set up" |
| Off (KVM disabled by user) | link with slash | "Off" |
| Waiting for peer | link, pulsing (static if reduced motion) | "Looking for *Peer*…" |
| Connected, input here | solid link, left node filled | "Connected · input on this computer" |
| Connected, controlling peer | solid link, right node filled | "Controlling *Peer*" |
| Degraded (high RTT or loss) | solid link + small dot badge | "Connected · unstable" |
| Needs attention (permission, fault, version mismatch) | link + "!" badge | specific reason |
| Pairing request | link + "?" badge | "*Name* wants to pair" |

- **Left click** (Windows) or **click** (macOS) toggles the widget popover.
- **Right click** (Windows) or **Option-click** (macOS) opens a native menu: Turn KVM off/on ·
  Switch input to *Peer* / this computer · Settings… · Pause clipboard sync · Quit.
- **[A]** A global hotkey for "toggle KVM" is optional. It must not collide with the failsafe chord.

### 3.2 Widget popover (about 340 × 420 logical px, fixed size)

```
┌──────────────────────────────────────┐
│ ● Connected                    ⚙   │  status pill + settings
│                                      │
│  [ Studio PC ]  ⇄  [ MacBook Air ]   │  two hosts, arrow shows active
│     this one         4 ms · good     │  RTT + quality word
│                                      │
│  KVM                         [ ON ]  │  EnableKvm / DisableKvm
│  Clipboard sync              [ ON ]  │  Enable/DisableClipboard
│                                      │
│  ▸ Arrange displays                  │  opens layout sheet
│                                      │
│  Emergency release: Ctrl+Alt+⇧+⌫     │  always visible footer
└──────────────────────────────────────┘
```

- It anchors to the tray icon: bottom-right flyout on Windows 11 (respects taskbar position), and
  below the menu-bar item on macOS. It closes on blur or Esc.
- **State variants** use the same frame with the body replaced:
  - *Not set up*: a "Set up Software KVM" button that opens onboarding.
  - *Agent not running*: "Background service stopped" plus a **Start** button. That button lets the app
    relaunch the agent.
  - *Peer offline*: the last-seen time, the peer's last address, "Troubleshoot" (opens the
    Connection pane), and **Forget**.
  - *Permission missing* (macOS): the missing permission is named, with **Open System Settings**
    and a re-check that happens automatically when the permission changes.
  - *Version mismatch*: "Update *Peer* to vX.Y". KVM stays disabled.
  - *Incoming pairing*: name, platform and the 6-digit code, with **Codes match** and **Decline**.
  - *Fault*: a one-line cause, a **Retry** button and "Copy details" (a redacted diagnostic bundle).

### 3.3 Onboarding window (about 480 × 560, opened once or from "Set up")

There are 4 steps, which trims the current 4-step wizard and adds permissions:

1. **Name this computer.** Pre-filled from the hostname. The address is chosen automatically. The
   network interface picker moves to Advanced.
2. **Permissions** (macOS only; skipped on Windows). Accessibility and Input Monitoring each get a
   live tick. The agent's change notifications or a 1 s probe (only while this step is visible)
   update the ticks.
3. **Pair.** Nearby computers are listed live. Picking one shows the same verification code on both
   screens, and both sides confirm. The fallback is the pairing card (copy/paste, the existing
   `import_peer_bundle`). A QR code is optional, see the sign-off questions.
4. **Arrange.** Reuse `DisplayLayoutEditor` (it already has tests). Wait for the peer's signed ack
   ("Waiting for *Peer* to confirm…" with a 60 s timeout and **Retry**). The peer only needs its
   **agent** running, not its window. This is the main ownership fix.

The last screen reads "You're set". It offers a "Start at login" checkbox, checked by default, and
**Done**. Done enables KVM and closes the window.

### 3.4 Settings window (about 640 × 480, sidebar panes)

- **General:** start at login, turn KVM on at launch, theme follows the system.
- **Connection:** peer card (name, platform, fingerprint short form, last seen), re-pair, forget,
  network interface, ports (read-only), and the firewall status hint.
- **Displays:** the layout editor.
- **Keyboard:** modifier role mapping (`keyboard.modifier_role_mapping`, see
  `docs/platform-notes.md`) and a failsafe chord display. Changing the chord needs sign-off.
- **Clipboard:** on/off, plus the size limit display.
- **Diagnostics** (collapsed behind "Advanced"): the existing `DiagnosticsDashboard`, `DashChart`
  and tables, moved here unchanged at first. Adds "Export redacted report".
- **About and updates:** version, channel, check now, licences.

### 3.5 Notifications (OS-native)

Notifications fire only when the user needs to act, or once per state change:

- An incoming pairing request.
- The peer was lost for more than 10 s while KVM is on.
- A permission was revoked.
- An update is ready, which applies on the next quit or restart.

Notifications never fire for routine handoffs.

### 3.6 Failure and recovery matrix

| Failure | Detection (owner) | User-visible | Automatic recovery | Manual action |
|---|---|---|---|---|
| UI crash or hang | OS | Icon disappears | Agent keeps running. The single-instance UI relaunches at next login or on user launch and re-subscribes over IPC | Relaunch the app |
| Agent crash | UI loses its IPC subscription | "Background service stopped" | Hooks and taps die with the process (OS-owned). The peer sees the session drop and releases its injected state (existing session teardown). The UI restarts the agent with backoff, at most 3 tries in 60 s | Start |
| Agent wedged (IPC times out but the process is alive) | UI health probe, 3× 750 ms | "Not responding" | None automatic. Avoid killing it mid-injection | **Force stop** (kill + release), which needs confirmation |
| Peer unreachable | Agent peer manager | Peer offline card | Existing reconnect jitter (`product-improvement-phase` memory) | Troubleshoot or forget |
| Network change (Wi-Fi switch, dock) | Agent (`repair_lan_binding` logic moved into the agent) | Brief "Reconnecting" | Re-bind on interface change | Pick an interface |
| Display hot-plug | Existing hot-plug modules | "Displays changed. Review layout" if an edge became invalid | Keep the edge if still valid | Arrange |
| Permission revoked (macOS) | Agent probe | "!" badge, permission card | Capture fails open, KVM gates off | Open System Settings |
| UIPI blocked (Windows elevated window) | Injection error counter | Transient hint "Can't control admin windows" | None | Docs link |
| Protocol mismatch | Handshake | Version-mismatch card | KVM stays disabled | Update the peer |
| Sleep, lock or user switch | **[P]** Agent subscribes to OS notifications | "Paused (locked)" | Release held keys, gate off, resume after unlock | n/a |
| Corrupt config | Agent load (`kvm-config` `.bak` fallback already exists in `store.rs`) | "Settings restored from backup" | `.bak` restore | Reset |
| Credentials missing from the keystore | Agent | "Pairing lost. Re-pair" | None | Re-pair |

---

## 4. Visual direction (all [P])

- **Type:** the system font stack (`Segoe UI Variable` / `-apple-system, SF Pro`). Drop the
  Newsreader serif and the Manrope web fonts. That saves bytes, matches the OS and handles text scaling.
- **Material:** Windows 11 Mica or Acrylic on the flyout and settings, macOS `NSVisualEffectView`
  popover vibrancy (Tauri `windowEffects` / `window-vibrancy`), with an opaque fallback when
  transparency is off or the high-contrast theme is active.
- **Geometry:** 8 px radius on Windows, 10 px on macOS, a 4 px spacing grid, and 32 px row height (Windows) or 28 px (macOS).
- **Colour:** neutral surfaces from system tokens and one accent (the OS accent colour where readable).
  Semantic success, warning and danger colours always come with an icon and text. The theme follows
  the system light/dark setting, and `forced-colors` is honoured.
- **Motion:** at most 150 ms ease-out for popover and state changes. `prefers-reduced-motion` turns
  off the pulse and transitions.
- **Iconography:** keep `lucide-react` (it tree-shakes) for in-app icons. Draw custom SVG/ICNS
  tray glyphs as template images.
- **Tone:** plain words ("Controlling MacBook Air"), with no protocol jargon outside Diagnostics.

---

## 5. Architecture

### 5.1 Full backend rewrite vs selective overhaul

| | Full backend rewrite | **Selective overhaul (recommended)** |
|---|---|---|
| Scope | Re-implement daemon, runtime, network and native layers around a new process model | Keep the core crates. Re-home the setup/pairing/lifecycle ownership. Rebuild the app shell and UI |
| What it fixes | Everything, in theory | The real problems: ownership, contract, packaging and UX |
| What it puts at risk | Fail-open invariants, audited conformance (`docs/audit/*-conformant.md`), the tuned latency work (protocol v3/v4, pacing, folding) and native hook edge cases found the hard way | Moving `setup.rs` (2.7k lines) and `nearby.rs` (2k lines) without behaviour drift |
| Effort | Months. The physical hardware acceptance (milestone 10) would have to be redone | Roughly 6 phases. Physical acceptance is re-run, not re-earned |
| Why not | The backend has no defect that a rewrite fixes and a refactor can't | n/a |

A rewrite is only justified if a spike shows that hosting the runtime as a persistent agent is
structurally impossible with `kvm-runtime`'s current `execute_with_shutdown` shape. I see no sign
of that: the runtime already takes a shutdown `watch` channel and runs a `ControlPlane` on its tick.

### 5.2 Target process model [P]

```
┌─────────── per-user session ───────────┐
│  Software KVM.app / .exe  (Tauri, UI)  │   no input path; can crash freely
│     tray + popover + windows           │
│        │  Control API v2 (local IPC,   │
│        │  request/response + events)   │
│        ▼                               │
│  kvm-agent (headless, long-lived)      │   owns: identity, keys(OS store),
│   ├ setup/pairing/discovery service    │   config, discovery, pairing,
│   ├ runtime supervisor ── active KVM   │   workspace sync, KVM lifecycle,
│   │   (existing kvm-runtime::active)   │   failsafe, diagnostics
│   └ control service (§31 → v2)         │
└────────────────────────────────────────┘
        ⇅ mTLS 24800 / UDP 24802 / UDP discovery  (unchanged on the wire)
```

- **The agent runs whenever the user is logged in**, not only while KVM is on. It idles with no capture
  installed until the user enables KVM. This fixes the `Unreachable` gap and the "keep both
  consoles open" requirement.
- **Launching:** the UI app is the login item. On start it connects to the agent. If no agent
  answers, it spawns the bundled `kvm-agent` detached. The existing `runtime.lock` keeps it to one
  agent per user. The agent outlives a UI quit only when the user chose "Keep KVM running"; see §6.
  - **[A] macOS TCC spike:** a child spawned by the .app has the app as its *responsible process*, so
    Accessibility and Input Monitoring are attributed to "Software KVM.app". That is the desired UX
    (one entry in System Settings). If the spike shows the attribution breaks when the parent exits,
    fall back to registering the agent as a `SMAppService` LaunchAgent with its own bundle
    identity. That shows a second TCC entry, so it needs sign-off.
  - **Windows:** the agent runs at medium integrity in the user session. There is no Windows service.
    Low-level hooks need a desktop session, and a SYSTEM service cannot hook the user's desktop.
- **Single instance:** use `tauri-plugin-single-instance` for the UI and the agent lock for the agent.

### 5.3 Keep, refactor, rebuild

| Area | Decision | Notes |
|---|---|---|
| `kvm-protocol`, `kvm-network` (TLS, UDP, queue, codec), `kvm-router`, `kvm-topology`, `kvm-input`, `kvm-clipboard`, `kvm-security`, `kvm-config`, `kvm-discovery` | **Keep** | Change only for the Control API v2 messages and config v3 |
| `kvm-daemon` (core, peer_manager, session, pointer_handoff, failsafe) | **Keep** | Delete the `main.rs` skeleton binary to avoid confusion |
| `kvm-windows`, `kvm-macos` | **Keep** | Add session lock, sleep and wake notifications; pipe DACL helper; permission-change observer |
| `kvm-runtime` | **Refactor** into `kvm-agent` | Split `main.rs` into an agent loop that holds an *optional* active runtime; `run-managed` becomes a compatibility path for one release |
| `src-tauri/setup.rs`, `nearby.rs` | **Move + refactor** into a new crate `kvm-setup` (platform-neutral), hosted by the agent | Move the existing tests with the code. Keep the signing, verification and bounds logic verbatim |
| `src-tauri/control.rs` | **Rebuild** as a thin v2 client plus a Tauri event bridge | |
| `kvm-diagnostics` (validation runner) | Keep | It stays a developer tool |
| React UI (`App.tsx`, wizard) | **Rebuild** | Reuse `DisplayLayoutEditor`, `lib/displayLayout.ts`, `lib/format.ts`, and the diagnostics components and their tests |
| `scripts/dev.ps1`, `dev.sh` | Update | Add launching the agent plus the UI |

### 5.4 Control API v2 (contract migration) [P]

The encoding stays the same: the `kvm-protocol` versioned `ControlFrame` with a 4-byte length prefix.
v2 adds:

- **A handshake:** `Hello { api_version, client_kind }` gets back `HelloAck { api_version, agent_version, features }`.
  A mismatch gets a typed error. The UI shows "Restart Software KVM to finish updating".
- **Subscriptions:** `Subscribe { topics }` produces a push stream of `StateChanged(AgentState)`,
  `PeerChanged`, `PairingEvent`, `PermissionChanged`, `DisplaysChanged`, `Fault`. The existing
  broadcast channel caps the stream at `CONTROL_EVENT_CHANNEL_CAPACITY`, and lag triggers a full resync.
  This replaces all three polling loops.
- **Setup and pairing commands** (moved from Tauri commands, same semantics):
  `CreateIdentity`, `ListNearby`, `RequestPairing`, `AcceptPairing`, `ConfirmPairing`,
  `DeclinePairing`, `ImportPairingCard`, `ExportPairingCard`, `ForgetPeer`, `SetLayout`,
  `RepairLanBinding`, `GetSetupState`.
- **Lifecycle:** `StartKvm` / `StopKvm`, which replace the `runtime.control` file. `EnableKvm` /
  `DisableKvm` stay as the gate while running. `Shutdown { release_input: true }` is used by the installer and uninstaller.
- **Settings:** `GetSettings` / `SetSettings` (typed, validated in the agent).
- **Diagnostics:** `GetDiagnostics` (local) and `GetPeerDiagnostics` (fetched over the authenticated
  session). See §8.
- **Errors:** grow `ControlError` with typed recoverable reasons (`NotConfigured`,
  `PeerNotConfirmed`, `PermissionMissing{which}`, `Busy`, `VersionMismatch`). This ends the
  `coarse_error()` strings. Error text is a UI concern; the agent sends codes.

**Migration sequence:**

1. Add the v2 messages next to the v1 ones (same frame version and new tags, or bump the control frame
   version with a dual decoder for one release).
2. The agent serves both. During phases 1 and 2 the old React UI talks to v2 through the rebuilt
   `control.rs`, keeping its current Tauri command names as an adapter, so the old UI keeps working.
3. Retire the file control (`runtime.control`, `runtime.status`) and the `run-managed` CLI path after
   the new UI ships. Keep `runtime.lock` as the agent singleton lock.
4. **The peer-to-peer wire is untouched.** Pairing packets (`software-kvm-pairing/1`), beacons and
   protocol v4 stay byte-compatible, so a v-old peer and a v-new peer still pair and connect. The
   discovery beacon carries the app version, which drives the "update peer" hint.

**Persisted state migration (config v3) [P]:** on first agent start, read `setup-state.json`,
`runtime.toml` (v2) and `config.toml`. Write one `kvm-config` v3 document (reuse the
`kvm-config/migrate.rs` patterns) plus keys in the OS store. Rename the originals to `*.v2.bak`.
Migration is idempotent and has fixture tests built from real v2 files. Keep the existing
`%LOCALAPPDATA%\…\runtime` ACL hardening.

---

## 6. Lifecycle and input safety [P]

**Invariants** (these extend the existing ones and are never relaxed):

- **I1.** Only the agent installs hooks or taps or injects input. The UI process links none of the
  native capture code. This has to be checked: today `src-tauri/Cargo.toml` depends on
  `kvm-windows`, `kvm-macos` and `kvm-daemon` for display enumeration. Move that enumeration
  behind IPC.
- **I2.** Every path that stops capture (stop, gate off, failsafe, shutdown, sleep, lock, permission
  loss, agent panic) releases logically held keys and buttons first. This uses the existing
  `native_capture_discontinued` and `failsafe_hook`.
- **I3.** The failsafe chord works with the UI absent, hung or mid-update.
- **I4.** No lifecycle path leaves the pointer on the remote host with local input suppressed and
  no way back. Within 1 s of any session loss, routing returns to local.

**Quit semantics.** "Quit" in the menu asks once, with a remembered choice:
**Quit and turn KVM off** (the default) or **Hide icon, keep KVM running**. "Quit and turn KVM off"
sends `Shutdown{release_input}` and waits up to 3 s for an ack. **[V]** Today a UI exit leaves the
runtime running with no visible surface, which is a hidden-state hazard that this removes.

**Updates.** The updater stages the update, sends `Shutdown`, waits for the agent's lock to drop,
swaps the binaries, then relaunches. It never swaps while KVM is routing remotely: it waits for
pointer-local or asks first.

**Sleep, lock and fast user switching.** The agent gates off and releases input on suspend, lock or
session disconnect. On resume it reconnects and stays gated until unlock. Windows:
`WTSRegisterSessionNotification` and `WM_POWERBROADCAST` on a hidden message window. macOS:
`NSWorkspace` sleep/wake and `com.apple.screenIsLocked` / `screenIsUnlocked`. **[A]** The agents of
two logged-in users must not fight over ports 24800/24802. The second agent should detect the
bind failure and show "In use by another user on this Mac/PC".

**Async correctness.** The 15 s `thread::sleep` loop in `stop_runtime` goes away. The UI never
blocks a Tauri command thread on agent operations; it awaits IPC with timeouts.

---

## 7. Permissions [P]

- **macOS:** onboarding step 2 and the popover card. The agent reports `PermissionChanged`, polling
  `probe_permissions()` every 1 s only while not granted, then stopping. The deep links are
  `x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility` and
  `…?Privacy_ListenEvent`. Local Network permission (macOS 15+) is triggered on the first discovery
  send and must be explained before it appears.
- **Windows:** no prompts for input. A firewall prompt appears for inbound 24800/24802 and the
  UDP discovery port. See the sign-off question on installer-added rules versus the first-run prompt.
- KVM never auto-enables while any required permission is missing.

---

## 8. Security [P]

1. **Keys move into the OS store.** Move `local-key.pk8` into Keychain or Credential Manager through
   the existing `KeyedCredentialStore` backends, which brings the code in line with `docs/security.md`.
   Migration deletes the file after a verified read-back.
2. **Local IPC hardening:**
   - Windows: give the pipe an explicit security descriptor that grants only the current user SID
     (plus SYSTEM), set `first_pipe_instance(true)` on the first instance to stop squatting, and
     verify the client with `GetNamedPipeClientProcessId` plus a user SID check. Add a per-user
     suffix to the pipe name (`software-kvm-control-<sid-hash>`) for fast user switching.
   - macOS: move the socket into a 0700 directory under `~/Library/Application Support/Software KVM/run/`,
     which closes the umask window, and check `getpeereid` uid.
   - Both: the mutating commands (pairing, forget, settings, shutdown) are logged to the existing
     failsafe or audit sink.
3. **Diagnostics port.** Stop serving unauthenticated diagnostics on the LAN. Local diagnostics go
   over IPC. Peer diagnostics go over the mTLS session as a bounded request. Remove TCP 24801, or
   bind it to loopback behind a dev flag. The UI-owned UDP diagnostic relay in `nearby.rs` goes away.
4. **Pairing:** keep the mutual verification code, the 2-minute expiry, the bounded packet parsing
   and the signed display-map sync. Move them to the agent unchanged. Add a rate limit of 3
   incoming requests per minute per source, and auto-decline while another pairing is in progress.
   **[V]** `nearby.rs` already enforces the N-3 "no overwrite of a configured peer" rule.
5. **Tauri hardening:** one capability per window with only the commands that window needs.
   Keep the CSP. No `shell`, `fs` or `http` plugins. Updater signatures use the Tauri updater's
   minisign key, with the private key kept out of the repo (CI secret).
6. **Supply chain:** the existing `deny.toml` plus `npm audit` in CI. Generate an SBOM on release.
7. **Redaction:** "Copy details" and "Export report" strip addresses, fingerprints and names by default.

---

## 9. Accessibility [P]

- Everything in the popover and windows can be reached by keyboard. The popover traps focus while
  open, Esc closes it, and focus returns to the tray. On Windows, Win+B reaches the tray
  icon. On macOS, the menu-bar item has an AX label.
- Status changes are announced through an `aria-live="polite"` region, with no repeats for unchanged state.
- Status never depends on colour alone: glyph, text and icon always appear together.
- Contrast is at least 4.5:1 for text and 3:1 for UI glyphs in both themes and under `forced-colors`.
- The layout survives 200% text scaling. The popover grows vertically, or scrolls, instead of clipping.
- Toggles are native `role="switch"` elements with labels.
- `DisplayLayoutEditor` gets arrow-key nudging and a text-based alternative ("Place MacBook: left
  of Display 1").
- **Gate:** axe-core runs in vitest for each surface, plus a manual pass with Narrator on Windows and VoiceOver on macOS.

---

## 10. Performance budgets [P]

| Metric | Target |
|---|---|
| Agent idle CPU (KVM off) | < 0.2% of one core, with no timers faster than 1 Hz |
| Agent RSS (KVM on) | ≤ current `kvm-runtime` + 10 MB |
| UI with popover hidden | Webview destroyed after 60 s hidden **[A]** (needs a spike on reopen latency). The tray-only footprint stays under 40 MB RSS |
| Popover open → first paint | Under 120 ms warm and under 400 ms cold (webview re-created), p95 |
| UI → agent state propagation | Under 50 ms from event to render |
| Input latency regression | None. The existing `kvm-network` and `kvm-protocol` benches and the end-to-end pointer latency measurement must stay within noise (≤ 2%) with the UI open and animating |
| Bundle size | Under 15 MB installer on Windows and under 25 MB DMG on macOS (one arch) |

---

## 11. Packaging, update and uninstall [P]

| | Windows | macOS |
|---|---|---|
| Format | NSIS **per-user** installer (no admin), Tauri bundler. MSI is optional for IT later | `.app` in a DMG, Developer ID signed, hardened runtime, notarized and stapled |
| Agent | `kvm-agent.exe` through Tauri `externalBin` (sidecar), next to the app exe | `Contents/MacOS/kvm-agent`, signed with the same team ID. Entitlements: none beyond the defaults **[A]** |
| Login | `HKCU\…\Run` (via `tauri-plugin-autostart`) | `SMAppService.mainApp` login item |
| Signing | Authenticode (EV or Azure Trusted Signing) **[A]** | Developer ID Application |
| Update | `tauri-plugin-updater` with a signed manifest on GitHub Releases; stable and beta channels | Same |
| Uninstall | The NSIS uninstaller sends `Shutdown`, removes the Run key and firewall rules, and asks "Also remove pairing and settings?" (deletes `%LOCALAPPDATA%` data and Credential Manager entries) | In-app **Settings → Reset & Remove** stops the agent, deletes Keychain items, data and the login item, then explains `tccutil reset`. Dragging the app to the Trash leaves data, which is documented |
| Identifier | Change `dev.software-kvm.control-panel` to a final reverse-DNS ID **before the first signed release**, because it keys app-data paths, TCC and Keychain. Migration reads the old path once |

**Release CI:** a new `release.yml` builds signed artifacts per OS on a tag, then generates the
updater manifest, SBOM and checksums. The existing `ci.yml` remains the PR gate.

---

## 12. Phased implementation

Each phase ends with measurable gates. The phases are sequential unless marked parallel.

### Phase 0: decisions and spikes (about 1 week)
- Answers to the sign-off questions in §14.
- Spikes: (a) macOS TCC attribution for a child agent spawned by the .app, including after the parent
  exits; (b) Windows 11 tray-anchored flyout positioning and Mica in Tauri 2; (c) webview
  destroy/recreate cost; (d) the pipe DACL plus `first_pipe_instance` with tokio `ServerOptions`;
  (e) how session lock and sleep currently behave on hardware.
- **Gate:** a written spike report per item with pass/fail; the open sign-off questions closed.

### Phase 1: the agent takes ownership (depends on P0)
- Create `kvm-setup` from `setup.rs` and `nearby.rs` with their tests. Create `kvm-agent` from
  `kvm-runtime`, idle by default, with an optional active runtime. Add Control API v2 (handshake,
  subscribe, setup, pairing, lifecycle). Rebuild `control.rs` as an adapter so **the old UI still works**.
- **Gates:**
  - All existing tests pass, with the moved tests now running in the root workspace.
  - A headless integration test pairs two agents on loopback through v2 only, syncs the layout,
    starts KVM and stops it.
  - With KVM off, the UI gets `GetStatus` back (no `Unreachable`).
  - `runtime.control` is no longer written in the new path.

### Phase 2: security and config consolidation (depends on P1; can overlap with P3)
- Move keys into the OS stores, migrate to config v3, harden the pipe and socket, move diagnostics
  behind auth, add the sleep, lock and FUS handlers.
- **Gates:**
  - Migration fixture tests (v2 to v3), including idempotence and the `.bak` restore.
  - A test shows a second-user or impostor pipe client is rejected (Windows) and a bad uid is rejected (macOS).
  - No private key file remains on disk after migration (asserted).
  - Port 24801/TCP is no longer reachable from another host (asserted on hardware).
  - Lock, sleep, resume tests on hardware: input is released within 250 ms, and the gate resumes only after unlock.

### Phase 3: tray app and new UI (depends on P1's API surface; parallel with P2)
- Tray icon states, the popover, onboarding, settings, notifications, and theming.
- Delete the old wizard and the 400 ms polling. The fixture-driven UI state catalogue reuses the
  `bridge.ts` preview idea with neutral names.
- **Gates:**
  - Every row of §3.1 and §3.6 has a rendered fixture and a vitest test.
  - axe-core reports 0 serious or critical findings.
  - Popover p95 open time meets §10 on reference hardware.
  - First-run usability: 3 people who have not used the product complete setup unaided in under 5
    minutes on a Mac+PC pair (see the sign-off question).

### Phase 4: lifecycle hardening (depends on P2 + P3)
- Single instance, quit semantics, agent crash restart with backoff, adoption after a UI restart,
  login item, and update choreography.
- **Gates:** a lifecycle matrix (about 25 cases: UI kill, agent kill, kill during remote control,
  update during remote control, network flip, dock/undock, lock, sleep, user switch, permission
  revoke) passes on both OSes with no stuck keys and pointer-local within 1 s.

### Phase 5: packaging, update and uninstall (depends on P4; signing setup can start in P0)
- Bundling, sidecar, signing, notarization, the updater, the uninstaller, the identifier change and `release.yml`.
- **Gates:**
  - A clean VM install leads to onboarding and pairing.
  - Updating vN to vN+1 while paired keeps the pairing and settings.
  - Uninstall leaves no Run key, process or pipe, and removes data when the user chose that.
  - Notarization and Gatekeeper pass (`spctl -a`). SmartScreen is acceptable.

### Phase 6: physical acceptance and beta
- Re-run milestone-10 physical acceptance and the latency benches with the new process model.
  Beta channel for about 2 weeks.
- **Gates:**
  - Latency within budget (§10).
  - 0 stuck-input reports.
  - Crash-free sessions ≥ 99.5% (local opt-in counter only, no telemetry upload unless signed off).

---

## 13. Risks

| Risk | Likelihood / impact | Mitigation |
|---|---|---|
| macOS TCC attribution differs for the helper agent, so the user sees two entries or the grant is lost after an update | Med / High | Spike in P0. Sign the helper with the same team; consider a stable designated requirement; LaunchAgent fallback |
| Behaviour drift while moving `setup.rs` and `nearby.rs` (signing messages, pairing state machine) | Med / High | Move the code verbatim first and refactor second. Keep the tests byte-for-byte. Add a golden-vector test for the signature messages |
| Windows tray flyout positioning and Mica feel non-native in Tauri | Med / Med | P0 spike; fallback to a plain rounded window plus the native context menu |
| A webview that is always resident costs memory | High / Low | Destroy it on hide (with a spike), with a native tray menu covering quick actions |
| Updating mid-session strands input | Low / High | The §6 update choreography plus the existing fail-open behaviour; lifecycle matrix gate |
| A mixed-version peer pair is confusing | Med / Med | The beacon carries the version; version-mismatch card; peer wire unchanged |
| Firewall prompts during onboarding confuse users | High / Med | Explain them before they appear, and put the decision in sign-off |
| Code-signing cost and lead time hold up P5 | Med / Med | Start procurement in P0 |
| Scope creep into multi-peer | Med / Med | Principle 8; contract fields stay list-shaped but the UI shows one peer |

---

## 14. Sign-off questions (unanswered; need the user's decision)

1. **Agent lifetime:** should KVM keep running after the user quits the tray app ("Hide icon, keep
   running")? Or should quit always stop KVM?
2. **macOS helper identity:** is a second Accessibility/Input Monitoring entry acceptable if the
   P0 spike forces a `SMAppService` LaunchAgent? Or must there be one entry, even if that constrains
   the architecture (agent always a child of the app)?
3. **Windows install scope:** a per-user NSIS installer (no admin, but a firewall prompt on
   first run), or a per-machine installer with admin that pre-adds private-profile firewall rules?
4. **Signing budget:** Windows EV certificate, Azure Trusted Signing, or unsigned beta? Is an Apple
   Developer ID account available?
5. **Final app identifier and product name** (they affect data paths, TCC and Keychain): keep
   "Software KVM", and which reverse-DNS domain?
6. **Diagnostics port:** OK to remove unauthenticated TCP 24801 from release builds entirely?
7. **Pairing fallback:** keep the copy/paste pairing card, add a QR code, or nearby-only?
8. **Global hotkey** for KVM toggle and switch input: wanted in v1? Is the failsafe chord fixed or
   user-configurable?
9. **Update channel:** auto-download and install on quit by default, or notify only?
10. **Telemetry:** none at all (local counters only), or opt-in crash reporting?
11. **Usability gate:** who are the 3 people for the P3 first-run test, and is "under 5 minutes" the right bar?
12. **Compatibility window:** how many releases must the old `run-managed` and file-control path
    and the v1 control frames be kept?

---

## 15. Strengths and trade-offs of this plan

**Strengths**
- It keeps the hardest-won parts untouched: the input path, failsafe, transport latency work and audited conformance.
- It fixes the root cause behind the UX: the agent owns state, so the window becomes optional.
- One contract (Control API v2) replaces the file control, the status file, polling and UI-owned UDP.
- It aligns the implementation with the security posture the project already documents (OS key stores, no unauthenticated LAN surface).
- Every phase has a gate that can be measured, and a working UI exists at every step thanks to the adapter in P1.

**Trade-offs**
- There is one more process to supervise, and one more signed binary on macOS, with a TCC risk.
- Moving about 4.8k lines out of `src-tauri` costs real effort without showing users anything until P3.
- Destroying the webview on hide saves memory but adds cold-open latency.
- A per-user install keeps setup friction low but leaves the firewall prompt in place.
