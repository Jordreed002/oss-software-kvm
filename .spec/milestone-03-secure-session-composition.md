# Milestone 03 — Secure Session Admission and Simulated Daemon Composition

## Status

Automated implementation completed on 2026-08-08. This milestone is platform-neutral and was
implemented without modifying the active Windows Milestone 02 hardware-validation scope.

The production listener, native-backend composition, and physical-host validation listed below
remain deliberately deferred; completion here means the scoped automated acceptance criteria pass.

## Objective

Prove three previously separate safety boundaries together:

1. an outbound TCP connection becomes a `SecurePeerStream` only after bounded TLS 1.3 negotiation,
   exact remote-certificate verification, and presentation of configured client credentials;
2. the existing `HelloV1` and `AuthenticateV1` exchange is bound to the negotiated TLS session and
   the complete, direction-specific handshake transcript before paired-peer admission succeeds;
3. a simulated daemon coordinator accepts input only from an admitted peer and deterministically
   restores local state after ordering, delivery, injection, or transport failure.

This is not an operational KVM milestone. It does not connect native capture to routing, enable
suppression, or inject into a physical operating-system session.

## Non-overlap boundary

This milestone must not modify:

- `crates/kvm-windows/**`;
- Windows-specific code in `crates/kvm-diagnostics/**`;
- `docs/validation/windows/**`;
- native capture or suppression behavior on either platform.

The active Windows worktree owns those files until its hardware report is reviewed.

## Workstream A — Sealed outbound rustls transport

Add the first concrete implementation of the sealed `kvm-network` transport boundary.

Required behavior:

- connect only to an explicit `DevelopmentAddress` in this phase;
- separately bound TCP connection and TLS handshake durations;
- TLS 1.3 only;
- exact ALPN `software-kvm/1`;
- present a configured client certificate and verify the remote server certificate;
- verify the authenticated end-entity certificate fingerprint against the expected paired
  `TransportPeerIdentity` before constructing a `SecurePeerStream`;
- set TCP `NODELAY` for the admitted input path;
- disable early data, plaintext fallback, key logging, and automatic trust derived from an address,
  host name, discovery record, or certificate display field;
- make TLS exporter material available through the sealed stream only after handshake completion;
- redact certificate, private-key, exporter, and proof material from `Debug` and error values.

The public constructor must not accept an arbitrary caller-built rustls client configuration that
could disable verification. It consumes explicit certificate/key/trust inputs and builds the safe
configuration internally.

A production listener/acceptor, simultaneous-connection arbitration, automatic interface binding,
and mDNS are deliberately deferred. Tests may run a bounded loopback TLS server.

## Workstream B — Exporter-bound paired admission

Repair and implement the caller-owned `SessionAdmission` boundary.

Required behavior:

- each connection receives a fresh cryptographically random `HelloV1.nonce`;
- the network handshake obtains TLS exporter material from the still-unsplit secure stream;
- the exporter context is domain/version separated and covers both complete Hello values in a
  deterministic order, the negotiated protocol version, and the proof sender's role;
- the authentication proof is direction-bound so one endpoint's proof cannot be reflected as the
  other endpoint's proof;
- derive the proof directly through the TLS exporter and use the exact versioned scheme name
  `tls-exporter-v1`;
- require the exact proof length and compare it in constant time;
- reject equal peer IDs, modified transcript values, unknown schemes, malformed proofs, replayed
  proofs, unpaired peers, revoked peers, changed host IDs, and changed credential fingerprints;
- map store availability failures to a coarse unavailable result and every trust mismatch to a
  coarse rejection result;
- apply the paired-peer allowlist only after transport identity and proof verification succeed.

No private credential or proof bytes may appear in protocol-independent logs or error text.

## Workstream C — Simulated daemon peer coordinator

Add a synchronous, platform-neutral coordinator in `kvm-daemon`. One coordinator instance is bound
to exactly one configured peer session.

Required behavior:

- a network `Connected` state alone never enables daemon routing;
- require an `AdmittedPeer` whose host ID, peer ID, and credential fingerprint match the configured
  paired identity before calling the daemon core connected;
- deliberately convert supported wire input into canonical domain input;
- preserve increasing session sequence order and fail closed on duplicates or regressions;
- pass input only to an injected `OutputInjectionBackend`, using recording/failing fakes in tests;
- track remotely pressed keys and pointer buttons per source device;
- implement device-specific and all-device `ReleaseInputV1` cleanup;
- on degradation, disconnect, event-channel closure, stale sequence, identity mismatch, injection
  error, send error, revocation, or shutdown, reject further input, release received held state,
  restore the daemon core to safe local state, and do not replay old traffic;
- deliberately convert daemon forward/release actions into wire messages through a bounded
  transport abstraction;
- treat unsupported topology, clipboard, inventory, and transition messages as explicit deferred
  outcomes rather than input.

The production daemon binary remains observation-safe and is not wired to native backends in this
milestone.

## Safety invariants

1. Plain TCP and incomplete TLS handshakes cannot satisfy the sealed secure-stream API.
2. A socket address or discovery claim never establishes peer identity.
3. Connected transport state never means authorized application input by itself.
4. TLS identity, Hello identity, exporter proof, and paired allowlist must all agree.
5. Proofs cannot be replayed across TLS sessions or reflected between roles.
6. Any ordering, transport, injection, authorization, or coordinator ambiguity restores safe local
   state.
7. Undelivered input is inventoried and discarded, never replayed after reconnect.
8. Secrets and input payload values remain absent from normal logs.
9. No physical input is captured, suppressed, routed, or injected by this milestone.

## Automated acceptance

Transport tests must cover:

- loopback TLS success with a server that requires the configured client certificate, plus framed
  traffic;
- authenticated remote host, peer, and certificate fingerprint propagation;
- plaintext endpoint, missing client certificate, unknown certificate, changed certificate, wrong
  expected fingerprint, wrong ALPN, malformed certificate, connect timeout, and handshake timeout;
- rejection of an unknown client certificate before application admission (the outbound connector
  may briefly complete its local TLS state before receiving the server's fatal alert);
- exporter availability only after a completed handshake;
- cancellation-safe framing over the TLS stream;
- redacted `Debug` and errors.

Admission tests must cover:

- matching exporter/transcript proofs;
- fresh nonce generation;
- proof replay on another exporter, reflection, modified nonce/ID/version/fingerprint, wrong scheme,
  wrong length, unpaired peer, revoked peer, identity mismatch, and unavailable store;
- no proof or exporter marker in `Debug` or error output.

Daemon composition tests must cover:

- input rejection before admitted identity;
- no enablement from a forged or premature connected state;
- exact paired identity admission;
- ordered key, repeat, button, motion, and scroll conversion through a recording sink;
- duplicate/regressing sequence failure;
- device-specific and all-device releases;
- deterministic release after disconnect, degradation, injection failure, outbound failure, and
  shutdown;
- reconnect with cleared session sequence and pressed state;
- no native capture backend or suppression callback involvement.

The repository must pass:

```text
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
git diff --check
```

## Explicitly deferred

- production inbound TLS listener and duplicate-connection arbitration;
- certificate issuance, rotation, recovery, and revocation distribution;
- macOS Keychain and Windows Credential Manager implementations;
- stable identity bootstrap in the production daemon;
- mDNS and production interface selection;
- pairing UI and remote pairing orchestration;
- native capture, suppression, injection, and physical input routing;
- pointer authority, clipboard watchers, daemon IPC, startup agents, and the control panel.
