# kvm-network

`kvm-network` owns protocol framing, traffic prioritization, heartbeat health,
reconnect policy, and the persistent peer-session state machine.

It intentionally does **not** open TCP sockets or implement TLS, certificate
generation, credential persistence, peer discovery, or allow-list policy. A
future socket/TLS adapter must implement `SecurePeerStream` only after
encryption and transport identity authentication have completed. Both adapter
traits are sealed, so this concrete adapter must be added and audited inside
this crate; downstream safe code cannot label a plaintext wrapper secure. A
connector returns that stream for an explicit `DevelopmentAddress`.

The caller then implements `SessionAdmission`, normally by composing
`kvm-security` proof verification and paired-peer authorization. Until that
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

Production LAN discovery remains outside this crate. The future in-crate
rustls/socket adapter must preserve these two boundaries:

1. unauthenticated or plaintext streams never become `SecurePeerStream`;
2. application messages are never emitted before `SessionAdmission::admit`.
