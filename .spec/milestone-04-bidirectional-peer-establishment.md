# Milestone 04 — Bidirectional Secure Peer Establishment

## Status

Implementation and automated verification completed on 2026-08-08. The platform-neutral changes
remained isolated from the active Windows native-validation worktree. Final verification covered
65 network, 34 security, and 47 daemon unit tests within the green workspace suite, strict
workspace Clippy, formatting, whitespace validation, and Windows GNU check/strict Clippy for all
changed crates.

## Objective

Complete the secure peer-connection path in both directions without yet enabling physical input
routing:

1. accept inbound TCP connections only through a bounded, sealed TLS 1.3 server adapter that
   authenticates the presented client certificate;
2. run the same exporter-bound Hello/Authenticate admission and admitted-session engine over an
   outbound or accepted secure stream;
3. assign one deterministic connection direction to each paired peer so simultaneous dial races
   cannot create two authorized sessions;
4. allow exactly one admitted connection generation to reach daemon coordination and reconcile
   every rejected, stale, disconnected, or shutting-down generation.

This remains an automated composition milestone. It does not capture, suppress, or inject input
through a physical operating-system session.

## Non-overlap boundary

This milestone must not modify:

- `crates/kvm-windows/**`;
- `crates/kvm-macos/**`;
- `crates/kvm-diagnostics/**`;
- `docs/validation/**`;
- native capture, suppression, injection, startup, or clipboard watchers.

The only expected shared root changes are this specification, documentation, dependency metadata,
and `Cargo.lock` if dependency resolution requires it.

## Workstream A — Sealed inbound rustls acceptor

Add the server-side counterpart to `RustlsTcpConnector` in `kvm-network`.

Required behavior:

- consume an already accepted `TcpStream`; listener binding and interface selection remain outside
  the cryptographic adapter;
- build the rustls server configuration internally rather than accepting an arbitrary
  caller-built configuration;
- permit TLS 1.3 only and require exact ALPN `software-kvm/1`;
- require a client certificate and validate its chain against explicit trust roots;
- separately bound TLS handshake duration and set TCP `NODELAY`;
- disable early data, key logging, resumption, and anonymous/plaintext fallback;
- hash the authenticated leaf certificate and resolve that fingerprint through a caller-owned,
  fail-closed paired identity resolver before constructing a sealed stream;
- require the resolved identity fingerprint to equal the authenticated leaf fingerprint in
  constant time;
- expose exporter material only after the server handshake and identity resolution complete;
- redact certificates, keys, fingerprints, exporter material, and resolver internals from Debug
  and errors;
- validate positive certificate, key, trust-root, resolver, and handshake bounds before
  cryptographic processing or internal copying.

The network crate owns TLS sequencing, not paired-peer policy. The security crate supplies the
concrete resolver backed by a bounded public paired-peer snapshot. Application admission must
independently re-check the same stable host, peer, and fingerprint tuple.

## Workstream B — Direction-neutral admitted session engine

Refactor the existing persistent peer implementation without weakening its cancellation and
ordering guarantees.

Required behavior:

- extract a reusable session runner that accepts any sealed `SecurePeerStream`;
- perform the existing bounded exporter-bound admission before emitting application traffic;
- preserve incremental read/write/flush progress across cancellation;
- preserve priority lanes, bounded input bursts, heartbeat health, input identity validation,
  undelivered-traffic inventory, and payload-redacted diagnostics;
- make outbound reconnect scheduling a wrapper around the reusable engine rather than part of its
  security contract;
- provide an accepted-session entry point with bounded shutdown and the same event semantics;
- never replay queued or partially written traffic into another connection generation;
- expose no public constructor for `AdmittedPeer` or safe plaintext stream implementation.

## Workstream C — Deterministic connection ownership

Avoid timing-window arbitration. For every pair of distinct stable peer IDs:

- the endpoint with the lexicographically lower `PeerId` is the sole dial owner;
- the endpoint with the higher `PeerId` is the listener for that pair;
- both endpoints must independently derive mirror-image roles from the same IDs;
- equal IDs are rejected as an identity collision;
- a noncanonical inbound or outbound direction is rejected before admission;
- at most one pending and one active generation may exist for a paired peer;
- a duplicate pending/active generation is rejected and boundedly shut down;
- generation identifiers are local monotonic metadata and must not establish trust;
- stale events and messages from a prior generation must never reach the active daemon session;
- losing the active generation triggers reconciliation before any replacement is authorized.

The canonical-role rule deliberately favors correctness over fallback connectivity. Relay,
hole-punching, and reverse-dial fallback are non-goals for the initial LAN release.

## Workstream D — Security resolver and daemon supervisor

Add composition types without teaching `kvm-network` about the security or daemon crates.

Required behavior:

- create a bounded immutable paired-client resolver snapshot keyed by exact SHA-256 credential
  fingerprint;
- reject duplicate fingerprints mapped to different peer identities;
- reject invalid, missing, changed, or revoked identity metadata;
- never infer identity from socket address, certificate subject name, Hello display name, or mDNS;
- add a daemon supervisor that accepts events only from its current generation and feeds those
  events into `PeerSessionCoordinator`;
- ignore or reject stale-generation state notifications and application messages;
- reconcile held state and return the core to local control on active-generation failure,
  replacement, revocation, or shutdown;
- keep supervisor queues, generation records, and diagnostic output bounded and payload-redacted.

## Safety invariants

1. Only the canonical dial direction can progress to application admission.
2. A server-side sealed stream proves that rustls accepted the client certificate and that the
   exact leaf fingerprint resolved to paired public identity metadata.
3. TLS identity, Hello identity, exporter proof, allowlist identity, canonical direction, and
   active generation must all agree before input is accepted.
4. Connected TLS state alone never establishes application authorization.
5. Only one connection generation per peer can reach daemon coordination.
6. A stale or duplicate generation cannot inject messages after reconnect.
7. Every loss or ambiguity reconciles pressed state before replacement authorization.
8. All externally influenced queues, maps, credentials, certificates, and handshake durations are
   bounded.
9. Secrets and input payload values remain absent from normal Debug, errors, and logs.
10. No native input is captured, suppressed, routed, or injected by this milestone.

## Automated acceptance

Inbound transport tests must cover:

- loopback client-certificate-authenticated TLS and framed traffic;
- exporter equality between accepted and outbound streams;
- unknown, missing, changed, malformed, and revoked client credentials;
- wrong server trust, server name, fingerprint, or ALPN;
- plaintext input, handshake timeout, clean EOF, and abrupt reset;
- resolver unavailable, unknown fingerprint, ambiguous fingerprint, and identity mismatch;
- exact error/debug redaction and positive input-size bounds.

Session and ownership tests must cover:

- the same admitted session behavior for outbound and accepted streams;
- lower-ID dialer and higher-ID listener symmetry;
- equal-ID and noncanonical-direction rejection;
- duplicate pending and duplicate active connections;
- bounded shutdown during handshake, admission, partial read, partial write, and heartbeat wait;
- stale-generation Admitted, Message, Connected, Degraded, and Disconnected events;
- disconnect/reconnect cleanup with no queued traffic replay;
- deterministic resource bounds and count-only diagnostics.

The repository must pass:

```text
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff --check
```

The changed platform-neutral crates must also compile for `x86_64-pc-windows-gnu`. Native macOS
target verification requires an Apple SDK and remains a physical-host/CI gate when unavailable in
the Linux build container.

## Explicitly deferred

- mDNS discovery and production interface selection;
- certificate issuance, rotation, recovery, and revocation distribution;
- macOS Keychain and Windows protected credential-store adapters;
- pairing UI and remote pairing orchestration;
- reverse-dial fallback, NAT traversal, relay, WAN, or cloud connectivity;
- native capture, selective suppression, injection, and physical input routing;
- clipboard watchers, daemon IPC, startup agents, and the control panel.
