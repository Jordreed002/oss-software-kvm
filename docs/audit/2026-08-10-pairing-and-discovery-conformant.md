# Audit: §20 Discovery + §21 Pairing — CONFORMANT (security-critical)

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 25
**Spec ref:** `.spec/implementation.md` §20 (Discovery), §21 (Pairing)
**Severity:** N/A — conformance confirmation of the trust-establishment path.
Pairing is the security boundary of the entire system; this cycle records that
it is implemented correctly, fails closed, and follows industry best practice.

## What the spec requires

- **§20 Discovery** — mDNS LAN discovery surfaces `DiscoveredPeer { name,
  address, host_id }`. **Discovery must not imply trust:** a discovered host may
  not inject input until explicitly paired.
- **§21 Pairing** — initial workflow: discover → select → exchange ephemeral
  pairing info → **display matching verification code** → user approves both →
  persist peer identity. Subsequent connections authenticate automatically.
  Reject unpaired input connections.

## Implementation evidence (kvm-security crate)

The crate deliberately implements **no cryptography of its own** (see `lib.rs`
header): pairing consumes keying material exported by an already-authenticated
TLS session, and input authorization consumes an identity vouched for by an
authenticated, encrypted transport. rustls/OS-credential adapters live in the
transport crates. This separation is the correct architecture.

### §21 pairing — textbook SAS (short-authentication-string) flow

`pairing.rs`:

- `VerificationCode(u32)` — a **6-digit** code (`code_is_six_digits_and_round_trips`,
  `:436`) derived from TLS-exporter output (`start()` →
  `VerificationCode::from_exporter_output(material)`, label
  `EXPORTER-software-kvm-pairing-code-v1`, `:7`). This is **RFC 5705** TLS
  Keying Material Exporter usage — the canonical way to bind an
  application secret to the authenticated TLS handshake.
- The code is **deliberately never transmitted** (`approve_remote` doc, `:166`):
  it is displayed on each machine for human comparison, exactly as §21's
  "display matching verification code" requires.
- `PairingState { PendingApproval, Approved, VerificationFailed }` (`:68`).
  `approve_local()` + `approve_remote()` require **mutual** approval of the
  matching code; `finish()` returns a `PairedPeer` only after both approve.
- `report_verification_mismatch()` (`:205`) **fails closed permanently** when the
  human-visible codes differ — the MITM-detection escape hatch.
- `Debug` **redacts** the code and identity (`:96`, `"[REDACTED]"`) so logs
  cannot leak the secret.

### §21 persist + auto-authenticate + reject-unpaired

`allowlist.rs`:

- `PairedPeerStore` trait + `MemoryPairedPeerStore` — **persists** the paired
  peer identity (the "persist peer identity" requirement); `pair()` adds,
  `revoke()` removes.
- `AuthenticatedPeerTransport` trait — the transport must vouch for a presented
  identity via the authenticated TLS channel. This is how **subsequent
  connections authenticate automatically**: the already-trusted TLS identity is
  presented and checked against the store — no re-pairing needed.
- `PairedPeerAllowlist::authorize_input()` (`:251`) is the **reject-unpaired**
  gate: an authenticated-but-unpaired peer yields
  `AuthorizationError::NotPaired` ("authenticated peer is not paired and cannot
  authorize input", `:302`). Covered by tests `paired_authenticated_peer_can_authorize_input`
  and the unpaired-rejection tests.

### §20 discovery ≠ trust

`identity.rs` exposes `DiscoveredPeer`. The trust boundary is the allowlist
(`authorize_input`), entirely independent of mDNS discovery — a discovered host
that has not completed §21 pairing cannot pass `authorize_input`. The spec's
"discovery must not imply trust" is therefore structurally enforced.

## Why this is MITM-resistant

A network attacker performing a classic MITM terminates two separate TLS
sessions (A↔attacker, attacker↔B). Because the verification code is derived from
the **per-session** TLS exporter output, the two sessions produce **different**
codes. The humans compare, see a mismatch, and `report_verification_mismatch`
fails the pairing closed. This is the same property Bluetooth SSP "numeric
comparison" provides.

## Web verification (current best practice)

- **RFC 5705** "Keying Material Exporters for TLS" is the standard mechanism the
  crate uses to derive the pairing code from the TLS master secret — binding the
  SAS to the authenticated session.
- Bluetooth SSP **numeric comparison** (a 6-digit value derived from the key
  exchange, shown on both devices, human-compared to detect MITM) is the direct
  real-world analog of this `VerificationCode` + mutual-approval design.

The codebase matches both.

## Non-goals

Did not modify code. Confirmed §20/§21 are conformant and well-architected. The
only thing this audit did not exhaustively trace is the live mDNS
advertisement/registration path in the `kvm-discovery` crate (the security
properties above hold regardless of the discovery transport); that is a
separate, lower-risk surface.
