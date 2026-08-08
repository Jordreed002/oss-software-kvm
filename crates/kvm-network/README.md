# kvm-network

`kvm-network` owns protocol framing, traffic prioritization, heartbeat health,
reconnect policy, the persistent peer-session state machine, and the audited
outbound TCP/rustls adapter.

`RustlsTcpConnector` builds its TLS configuration internally from an explicit
client certificate/key, server trust roots, server name, and expected paired
identity. It permits TLS 1.3 only, requires `software-kvm/1` ALPN, disables
early data and resumption, applies separate TCP/TLS timeouts, and compares the
authenticated leaf-certificate SHA-256 fingerprint before returning a sealed
`RustlsPeerStream`. It accepts only an explicit `DevelopmentAddress`; the
address is reachability metadata and never establishes trust. Callers cannot
provide an arbitrary rustls configuration or label a plaintext wrapper secure.

A successful outbound `connect` proves completed encrypted TLS 1.3, exact ALPN,
and an authenticated, pinned remote certificate from the client's perspective.
The connector presents the configured client certificate and key, but TLS 1.3
allows client-side handshake completion before a server rejection alert is
observed. `connect` alone therefore does not prove that the server accepted the
client credential. Successful bidirectional `Hello`/`Authenticate` admission
proves both application endpoints are participating; a future inbound rustls
acceptor will enforce client-certificate acceptance directly on its side.

Certificate generation, credential persistence, inbound listening, peer
discovery, and allow-list policy remain outside this adapter.

The caller then implements `SessionAdmission`, normally by composing
`kvm-security` proof verification and paired-peer authorization. Each call to
`local_hello` must create a fresh nonce. The session exchanges both Hello
values on the still-unsplit TLS stream and derives two role-specific proofs
from a canonical, versioned transcript through the TLS exporter. Until that
policy accepts the remote `Hello` and `Authenticate` exchange, the session
rejects all input, pointer, release, clipboard, and state-transfer traffic.
Only the session can create an `AdmittedPeer` token.

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

Production LAN discovery and inbound connection arbitration remain outside
this crate. The adapter preserves these two boundaries:

1. plaintext streams, or streams without locally completed remote-peer
   authentication, never become `SecurePeerStream`;
2. application messages are never emitted before `SessionAdmission::admit`.
