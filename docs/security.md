# Security

Discovery establishes reachability, not trust. A discovered daemon cannot inject input or receive
clipboard data until both machines complete a verification-code pairing flow.

Each daemon has a long-lived host identity. Pairing exchanges authenticated identity material over
an ephemeral session and requires approval on both hosts. Later connections use mutually
authenticated TLS and a paired-host allowlist. Secret key material is stored through macOS
Keychain or Windows Credential Manager abstractions, never in the ordinary configuration file.

The daemon listens only on explicitly selected local-network interfaces by default. There is no
WAN or cloud relay mode in version one. Protocol parsing enforces version, message-kind, and
payload-size limits before dispatch. Input is disabled until authentication and capability
negotiation finish.

Development address overrides must be opt-in and must not bypass peer authentication in release
builds.

The current platform-neutral transport client builds a TLS 1.3-only rustls configuration from
explicit client credentials and server trust roots. It requires the `software-kvm/1` ALPN,
validates the server name and certificate chain, and then compares the authenticated leaf
certificate's SHA-256 fingerprint with the paired identity before the sealed stream is created.
Client-side TLS completion proves the remote server identity and presentation of the configured
client credentials; because a TLS 1.3 server can reject that client certificate after the client
finishes its own handshake flight, reciprocal acceptance is established only by the successful
bidirectional application admission exchange. That exchange derives direction-specific proofs
through the TLS exporter over both complete Hello frames; the paired allowlist is applied only
after the proof succeeds.

The inbound adapter independently requires a WebPKI-validated client certificate, hashes the
authenticated leaf certificate, and resolves only that exact fingerprint through a bounded
immutable paired-peer snapshot. The lower stable peer ID is the only permitted dialer and the
higher peer ID is the listener; the sealed stream reports its direction, so downstream code cannot
mislabel a connection to bypass that rule. A local affine generation gate and daemon supervisor
then prevent duplicate or stale sessions from reaching input coordination.

DNS-SD/mDNS advertises only protocol version, a public peer-ID hint, endpoint port, and selected
private IPv4/IPv6-ULA addresses. Every record is size-bounded, expiring, and untrusted. The peer
scheduler considers a candidate only for an already paired peer and only in the canonical dial
direction; the sealed TLS stream must still prove the exact paired host, peer, and certificate
fingerprint before exporter admission. The production listener binds explicit private addresses,
rate-limits globally and per source, and returns only accepted sealed streams. No socket address,
DNS name, service instance, TXT property, or cached candidate is treated as identity.

The platform-neutral input composition accepts remote routing only through the immutable selected
peer's current admitted generation. Fresh authenticated display inventory must compile before
workspace routing becomes ready. For each trusted physical record, the synchronous manager path
queues the exact Input or ReleaseInput frame before returning a suppression decision; a retained
snapshot cannot authorize work or retag it into a replacement session. Held-state and cleanup
ledgers are positively bounded, and cleanup is discarded only after confirmed transport
termination. Normal diagnostics redact input payloads, stable identities, routes, and connection
generation values.

Certificate issuance and rotation, scoped IPv6 link-local dialing, physical-host multicast
validation, and native credential-store adapters remain deferred.
