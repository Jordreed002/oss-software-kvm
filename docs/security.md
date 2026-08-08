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
