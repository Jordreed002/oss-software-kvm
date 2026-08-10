# Audit: Input-injection authorization boundary — CONFORMANT

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 41
**Spec ref:** §16 (Injected-Event Detection), §21 (Pairing/trust), §22
(Connection State) — the security boundary on synthesized local input
**Severity:** N/A — conformance confirmation of a security-critical boundary.

## The question

A software KVM *injects* remote peers' input events into the local OS. That is a
privileged, trust-crossing action: only an authenticated, admitted peer's input
may reach the injection backend. If any code path injects an event that bypasses
the admitted-session / `accepts_input` / identity / sequence gates, an
unauthenticated or stale peer could synthesize keystrokes locally. This audit
asked: **is every `injection.inject()` site reachable only through the
authorized path?**

## Findings

### Single funnel — the coordinator owns the injection backend

A workspace grep for `.inject(` finds exactly **two** production call sites,
both in `PeerSessionCoordinator` (`session.rs`):

- `inject_received` → `self.injection.inject(&event)` (`session.rs:1332`) — the
  *new-input* path.
- `release_all_inbound` → `self.injection.inject(&event)` (`session.rs:1485`) —
  the *stuck-key release* path.

`kvm-runtime` (the capture/network layer) calls **zero** inject methods — it has
no direct line to the injection backend. The platform `Injection` trait
(`platform.rs:192`) is realized only via the coordinator. So there is one funnel,
and both its sites were inspected.

### New-input site — fully gated

`inject_received` is called only from `handle_authorized_message`
(`session.rs:1238`), which runs the full gate before reaching it:

```text
accepts_input            (session.rs:1223) — reject unless admitted AND accepting
message.validate()       (session.rs:1228) — integrity
source_host == expected  (session.rs:1232) — identity match
accept_sequence(seq)     (session.rs:1235) — monotonic / anti-replay
```

Any failure is `fail_session`-fatal. An unauthenticated, unadmitted,
non-accepting, wrong-identity, or stale-sequence frame can never reach
`inject_received`. ✅

### Release site — can only reverse previously-authorized state

`release_all_inbound` is called from disconnect / fatal-cleanup / shutdown /
failsafe (`session.rs:798, 876, 1073, 1196, 1630, 1657`). It injects synthetic
**releases** (key-ups / button-ups) for entries in `inbound_pressed`. That map is
populated *only* by `inject_received` applying an event after a successful
authorized inject — so every entry it can release was already authorized at
injection time. A release is the safe direction: it can undo held state but can
never introduce a new, unauthorized input. ✅

(The cycle-38 fix added one more `release_all_inbound` trigger — the failsafe
chord — which is the same safe-direction release, not a new input path.)

### Trust boundary is the pairing allowlist, independent of transport

Per cycle 25, the trust decision is the paired-peer allowlist
(`authorize_input` → `AuthorizationError::NotPaired`), vouched by the TLS
identity, separate from mDNS discovery. The injection funnel sits downstream of
that boundary: a frame cannot be `handle_authorized_message`'d unless the peer is
admitted, and admission requires the authenticated transport bound to a paired
peer.

## Web verification

The governing principle is the trust boundary between input and execution:
*"injection attacks target the trust boundary between input and execution, and
when that boundary fails, malicious hackers may find a way in"* (Invicti). The
canonical defense — validate/authorize every input before acting on it, at a
single chokepoint — is exactly the coordinator-funnel + gate-before-inject
design audited here, applied to OS input synthesis rather than data parsing.

## Non-goals

Did not modify code (AUDIT, conformance confirmed — not every audit finds a bug;
cycle 38 did). Did not re-audit the §15/§16 suppression/classification layer
(cycle 23) or the pairing crypto (cycle 25). Scoped strictly to "is every inject
site authorized."
