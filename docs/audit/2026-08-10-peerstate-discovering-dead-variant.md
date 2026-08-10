# Audit: §22 `PeerState::Discovering` is a dead (unreachable) variant

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 21
**Spec ref:** `.spec/implementation.md` §22 (Connection State)
**Severity:** Low-Medium — observability + spec-conformance gap. No correctness impact (input gating is unaffected); a peer is shown "disconnected" while the daemon is actively probing the LAN for it.

## Conformance baseline (mostly good)

§22 specifies a 6-variant `PeerState` and four heartbeat timestamps. Mapping to
the daemon:

- `PeerState` (`kvm-daemon/src/core.rs:32`) has **exactly** the 6 spec variants:
  `Disconnected`, `Discovering`, `Connecting`, `Authenticating`, `Connected`,
  `Degraded`. ✅
- `PeerHealth` (`kvm-network/src/heartbeat.rs`) carries the four heartbeat fields
  (spec `last_sent_ping`/`last_received_packet`/`last_received_pong`/
  `round_trip_time` → code `last_sent_at`/`last_received_at`/`last_pong_at`/
  `last_rtt`). ✅
- `PeerState::accepts_input` gates input to `Connected` only (not `Degraded`) — a
  conservative, safe choice. ✅

## The gap: `Discovering` is never produced

Five of the six variants are driven by real transitions:

```text
Disconnected  core.rs:621,1116,1635,1890  session.rs:1557,1584   (init/teardown)
Connecting    session.rs:1078
Authenticating session.rs:1087
Connected     session.rs:1120  core.rs:1575,1578
Degraded      session.rs:1129                                    (heartbeat degradation)
```

`Discovering` appears **only in the two enum definitions** and is set nowhere:

```text
$ grep -rn "Discovering" crates/ --include=*.rs
crates/kvm-daemon/src/core.rs:34:        Discovering,          # enum def
crates/kvm-protocol/src/control.rs:54:   Discovering,          # control-protocol enum def
```

No `set_endpoint_state(.., PeerState::Discovering, ..)` call exists. So a peer's
lifecycle in the daemon's peer map is:

```
Disconnected → Connecting → Authenticating → Connected ⇄ Degraded → Disconnected
```

— it never occupies `Discovering`. The discovery phase itself is real (the
`kvm-discovery` crate, LAN discovery, peer scheduling — milestone-05), but when a
peer is actively being probed on the LAN its daemon-side state stays
`Disconnected` until a candidate is found and a connection is attempted, at which
point it jumps straight to `Connecting`.

## Why it matters

A control panel / diagnostics view showing connection state (§32 Connections
page, §35 "connection state") would display **"disconnected" while the daemon is
actively searching** — which reads as "idle / given up" to a user waiting to pair
or reconnect. Web-verified: connection state machines across the industry
distinguish a discovery/probing phase (WebRTC `iceConnectionState: "checking"`,
802.11's discovery-before-association, Unity Transport's connecting state); an
explicit "discovering/searching" indication is the expected, more informative
signal. The spec authors included the variant for this reason; the daemon simply
never sets it.

## Recommended fix (improvement cycle)

1. When the peer scheduler / discovery layer begins actively probing for a paired
   host (or schedules a reconnect attempt), transition that peer to
   `PeerState::Discovering`.
2. On finding a candidate and initiating a connection, transition to `Connecting`
   (existing path). On probe timeout / no candidate, return to `Disconnected`.
3. This is a small, additive change in the scheduling layer: it flows the
   existing state machine through the already-present variant, with no change to
   `accepts_input` (Discovering must not accept input) and no wire/protocol
   change (the control-plane enum already has the variant).

Side note (minor): there are **two distinct types named `PeerState`** — the
daemon's 6-variant lifecycle enum and the network heartbeat's 4-variant liveness
enum (`Connecting`/`Healthy`/`Degraded`/`Disconnected`, `heartbeat.rs:7`). They
model different things (lifecycle vs liveness) but the shared name is a
readability hazard similar to the pre-cycle-12 `KeyboardMode` duplication; a
future cleanup could rename one (e.g. `PeerLiveness`).

## Non-goals for this audit

Did not modify code. Confirmed §22 is otherwise conformant; documented the single
dead variant and its observability consequence.
