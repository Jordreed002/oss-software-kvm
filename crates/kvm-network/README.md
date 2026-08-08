# kvm-network

`kvm-network` owns protocol framing, traffic prioritization, heartbeat health,
reconnect policy, direction-neutral admitted sessions, deterministic connection
ownership, and audited inbound and outbound TCP/rustls adapters.

`RustlsTcpConnector` builds its TLS configuration internally from an explicit
client certificate/key, server trust roots, server name, and expected paired
identity. It permits TLS 1.3 only, requires `software-kvm/1` ALPN, disables
early data and resumption, applies separate TCP/TLS timeouts, and compares the
authenticated leaf-certificate SHA-256 fingerprint before returning a sealed
`RustlsPeerStream`. Development overrides use `DevelopmentAddress`; production
discovery/cached endpoints must first become a validated `LanPeerAddress` and
use the separate sealed `AuthenticatedLanConnector` path. Either address is
reachability metadata and never establishes trust. Callers cannot provide an
arbitrary rustls configuration or label a plaintext wrapper secure.

A successful outbound `connect` proves completed encrypted TLS 1.3, exact ALPN,
and an authenticated, pinned remote certificate from the client's perspective.
The connector presents the configured client certificate and key, but TLS 1.3
allows client-side handshake completion before a server rejection alert is
observed. `connect` alone therefore does not prove that the server accepted the
client credential. Successful bidirectional `Hello`/`Authenticate` admission
proves both application endpoints are participating. `RustlsTcpAcceptor`
requires and verifies the client certificate directly on the server side,
then resolves its exact leaf fingerprint through a bounded paired-identity
policy before returning a sealed accepted stream.

`BoundedLanListener` binds only explicit private IPv4 or IPv6-ULA endpoints,
applies global and per-source rate/concurrency limits before TLS work, and
emits only sealed authenticated streams. Rejection telemetry is count-only so
an unauthenticated flood cannot occupy the accepted-stream queue. Listener and
handshake tasks are owned and drained or aborted on bounded shutdown.

Certificate generation, credential persistence, interface selection, peer
discovery, and allow-list policy remain outside the transport adapters.

The caller then implements `SessionAdmission`, normally by composing
`kvm-security` proof verification and paired-peer authorization. Each call to
`local_hello` must create a fresh nonce. The session exchanges both Hello
values on the still-unsplit TLS stream and derives two role-specific proofs
from a canonical, versioned transcript through the TLS exporter. Until that
policy accepts the remote `Hello` and `Authenticate` exchange, the session
rejects all input, pointer, release, clipboard, and state-transfer traffic.
Only the session can create an `AdmittedPeer` token.

Hello is always bootstrapped with protocol-v1 framing and advertises the
endpoint's supported range. The peers select the highest overlap, bind that
exact version into both exporter authentication proofs, and require it for
Authenticate and every admitted application frame. A v1 peer therefore falls
back safely, while protocol-v2 release proof cannot be encoded on a v1
session. A separate domain-separated exporter value identifies the exact
admitted transport generation for retained release obligations; normal Debug
output redacts that session binding, identities, payloads, and sequences.

`SecurePeerSession` runs that same admission and transport engine once over an
accepted or connected sealed stream. Transport direction is supplied by the
sealed stream implementation rather than by downstream callers. For each pair,
the lower stable peer ID is the sole dialer and the higher peer ID is the
listener; equal IDs and noncanonical directions fail before Hello exchange.
`ConnectionGenerationGate` then permits at most one pending or active local
generation and uses affine capabilities to reject duplicates and stale owners.
If an executor loses the task that owns a pending capability, an exact hidden
generation may be abandoned only to fail closed; it can never activate a
session. Active task loss still requires daemon reconciliation.

The admitted session retains incremental header, payload, encoded-frame, and
flush progress across async scheduling branches. Partial reads and writes are
therefore never restarted after cancellation. Every received message is also
checked against the authenticated remote host and, for pointer entry, the
local destination host.

Disconnects emit a redacted reason plus metadata for every unsent or partially
sent message. Pending channel traffic is drained and discarded rather than
replayed on a new connection; callers must perform input-state reconciliation
when the event requests it. Reconnect jitter is injected through
`ReconnectJitter` at the scheduler, and backoff resets only after the configured
healthy interval.

Production LAN discovery and interface selection remain outside this crate.
The transport preserves these boundaries:

1. plaintext streams, or streams without locally completed remote-peer
   authentication, never become `SecurePeerStream`;
2. application messages are never emitted before `SessionAdmission::admit`.
3. transport direction and connection generation must both be canonical before
   a session can reach daemon coordination.
