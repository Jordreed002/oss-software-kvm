# Milestone 05 — Bounded LAN Discovery and Peer Scheduling

## Status

Implementation and automated verification completed on 2026-08-08 after independent lifecycle,
trust-boundary, resource-bound, and diagnostic-redaction reviews. Final focused suites covered 84
network, 66 daemon, 18 discovery, 39 security, and 13 configuration tests within the green
workspace suite. Formatting, strict workspace Clippy, whitespace validation, and Windows GNU
check/strict Clippy for every changed platform-neutral crate also passed. The work remained
isolated from native validation occurring in the Windows worktree.

## Objective

Turn the bidirectional authenticated-session primitives into a bounded LAN connection pipeline
without yet enabling physical input routing:

1. advertise and browse Software KVM endpoints with DNS-SD/mDNS on the local link;
2. convert all discovered records into strictly bounded, expiring, untrusted reachability hints;
3. schedule outbound attempts only for currently paired peers for which the local peer is the
   canonical dial owner;
4. accept inbound TCP only through a bounded listener and the sealed TLS acceptor;
5. keep one task and one generation per paired peer, with deterministic cancellation,
   reconciliation, retry, revocation, and shutdown.

The mDNS adapter follows RFC 6762 and RFC 6763. Its records never establish identity or trust.
DNS-SD exposes local metadata and has privacy limitations described by RFC 8882; this initial LAN
release advertises only the minimum protocol/version/peer hint needed for paired reachability.

## Non-overlap boundary

This milestone must not modify:

- `crates/kvm-windows/**`;
- `crates/kvm-macos/**`;
- `crates/kvm-diagnostics/**`;
- `docs/validation/**`;
- native capture, suppression, injection, startup, or clipboard watchers.

Expected implementation paths are a new `crates/kvm-discovery/**`, new platform-neutral modules in
`kvm-network` and `kvm-daemon`, crate manifests, root documentation, this specification, and
`Cargo.lock`.

## Workstream A — Discovery model and mDNS adapter

Add `kvm-discovery` with a small policy-free model plus a production DNS-SD adapter using service
type `_software-kvm._tcp.local.`.

Required behavior:

- publish only protocol version, stable peer-ID hint, instance name, port, and selected local
  addresses; never publish a certificate, fingerprint, host ID, key, nonce, display inventory, or
  input metadata;
- treat service names, TXT data, addresses, ports, cache lifetime, and removal events as hostile;
- require an exact supported protocol version and canonical non-nil peer-ID encoding;
- reject zero ports, unspecified, multicast, broadcast, loopback, and non-LAN addresses;
- support private IPv4 and IPv6 unique-local candidates initially; scoped IPv6 link-local dialing
  is deferred until interface indices are preserved end-to-end;
- bound every string, TXT property count/value, addresses per service, services in the cache,
  emitted event queue, and TTL/expiry duration;
- key cache ownership by DNS-SD service fullname rather than trusting the claimed peer ID;
- permit multiple hostile services to claim one peer hint without merging them into trusted
  identity; provide deterministic candidate ordering and deduplication;
- expire stale records and remove goodbye records without extending them from unrelated events;
- shut down browsing/registration and bridge tasks within a bounded deadline;
- use custom Debug/errors that expose counts and coarse categories, not arbitrary TXT/service data.

The core cache/parser must be fully deterministic and testable without multicast networking. The
real adapter must have loopback/custom-port smoke coverage where the dependency supports it.

## Workstream B — Bounded inbound listener

Add a reusable listener service to `kvm-network` around `AuthenticatedAcceptor`.

Required behavior:

- bind only explicit caller-supplied LAN socket addresses; wildcard/public binding policy remains
  outside the listener and is rejected by the LAN address validator;
- positively bound listeners, outstanding handshakes, accepted-event queue, per-address attempts,
  and shutdown duration;
- enforce global and per-source admission concurrency/rate limits before expensive TLS work;
- set accepted sockets to `TCP_NODELAY` and feed them only into the sealed TLS acceptor;
- never derive peer identity from source address or discovery metadata;
- return only sealed, authenticated accepted streams or coarse rejected-attempt telemetry;
- handle accept errors, handshake timeout/error, queue saturation, clean shutdown, and task panic
  without leaking credentials or raw peer-controlled strings;
- stop accepting first on shutdown, cancel/drain handshake tasks within deadline, and never detach
  a task that can later mint a usable stream.

## Workstream C — Automatic paired-peer scheduler

Add a platform-neutral scheduler/composition module in `kvm-daemon`.

Required behavior:

- maintain a bounded immutable set of currently paired public identities and one supervisor/task
  slot per peer;
- consume discovery candidates only as addresses for an already paired peer-ID hint;
- for the canonical dialer, select candidates deterministically, apply bounded reconnect/backoff,
  and require the sealed connector plus exporter admission before activation;
- for the canonical listener, match an accepted sealed stream by its authenticated transport
  identity, never by the source address or advertised peer hint;
- use `GenerationBoundPeerSession` and `PeerSessionSupervisor` as the only path into daemon peer
  coordination;
- reject wrong-direction, unknown, revoked, duplicate, stale, and capacity-exceeding peers before
  application traffic;
- prefer an existing healthy generation over address churn; discovery removal alone must not
  revoke or disconnect an authenticated healthy session;
- on active failure, channel closure, revocation, configuration change, or shutdown, reconcile held
  input before replacement and retain failed-cleanup state fail closed;
- ensure every spawned task returns its affine pending/active terminal capability even when local
  queues close or fill;
- expose bounded count-only state and coarse errors.

Credential loading and concrete rustls configuration are injected dependencies. This milestone
must not place private keys in `kvm-config` or infer credentials from discovery.

## Workstream D — Public configuration correctness

Tighten the existing public configuration boundary needed by the scheduler:

- validate paired identity fingerprints as exact canonical SHA-256 values rather than arbitrary
  strings;
- reject nil local/paired peer and host identifiers wherever they enter a runtime snapshot;
- bound paired hosts, explicit bind addresses, and stored last-known candidates;
- treat `last_address` as an untrusted reconnect hint subject to the same LAN filtering and TLS
  identity checks as mDNS;
- retain backward-readable configuration only when values satisfy the current safety model;
- keep all long-term private credentials in `kvm-security`/OS credential stores, never TOML.

## Safety invariants

1. Discovery supplies reachability only; it never establishes identity, pairing, or authorization.
2. Only a paired identity may allocate a connection slot.
3. Only the canonical direction may allocate that peer's pending generation.
4. Only a sealed TLS stream with matching transport identity and exporter admission may activate.
5. Source IP, DNS name, instance name, TXT values, and cached address never bypass certificate
   validation.
6. One paired peer has at most one pending/active task and one daemon supervisor generation.
7. Every queue, cache, record, listener, task set, retry path, and shutdown duration is bounded.
8. Discovery loss never tears down a healthy authenticated session; revocation does.
9. Failed cleanup blocks replacement rather than losing held-input state.
10. Peer-controlled metadata, credentials, fingerprints, and input payloads remain redacted.
11. No native input is captured, suppressed, routed, or injected by this milestone.

## Automated acceptance

Discovery tests must cover malformed/oversized/non-UTF-8 TXT data, nil/noncanonical peer IDs,
wrong versions, duplicate claims, address filtering, deterministic ordering, TTL clamping/expiry,
goodbye removal, cache/event saturation, adapter shutdown, and redaction.

Listener tests must cover explicit safe binds, rejected wildcard/public binds, global/per-source
limits, plaintext and failed TLS, accepted authenticated streams, queue saturation, accept errors,
shutdown during handshake, cancellation, and redaction.

Scheduler tests must cover unpaired spoofed discovery, changed fingerprint, canonical dial/listen
roles, multiple candidates, address churn, duplicate inbound/outbound attempts, stale task events,
revocation, failed reconciliation, retry/backoff, task/channel failure, and bounded shutdown.

The repository must pass:

```text
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff --check
```

All changed platform-neutral crates must also pass Windows GNU check and strict Clippy. Real
multicast behavior remains a physical Windows/macOS/Linux LAN validation gate and is not inferred
from container tests.

## Explicitly deferred

- pairing UI and unauthenticated pairing discovery;
- certificate issuance, rotation, recovery, and revocation distribution;
- macOS Keychain and Windows protected credential-store adapters;
- IPv6 link-local candidates until interface scope IDs are retained;
- reverse dialing, NAT traversal, relays, WAN, or cloud connectivity;
- production daemon-main credential and native-backend wiring;
- native capture, suppression, injection, and physical input routing;
- clipboard watchers, daemon IPC, startup agents, and the control panel.
