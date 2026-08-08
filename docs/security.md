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

Production inbound listening, certificate issuance and rotation, mDNS, and native credential-store
adapters remain deferred. No socket address or discovery record is treated as identity.
