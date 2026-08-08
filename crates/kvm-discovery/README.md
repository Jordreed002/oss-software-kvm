# kvm-discovery

`kvm-discovery` turns DNS-SD/mDNS records into bounded, expiring, untrusted
LAN reachability hints. Discovery never establishes identity, pairing, or
authorization; consumers must match the peer-ID hint against current paired
metadata and still complete sealed TLS plus exporter-bound admission.

The production adapter advertises `_software-kvm._tcp.local.` with only
`ver=1`, a canonical stable peer-ID hint, an instance name, a non-zero port,
and caller-selected private IPv4 or IPv6 unique-local addresses. Certificate
material, fingerprints, host IDs, keys, nonces, display data, and input data
are never published.

The deterministic parser and cache reject or bound every externally supplied
name, TXT property, address set, TTL, service entry, snapshot, and update
queue. Cache ownership is the exact service fullname. Multiple services may
claim the same untrusted peer hint, but their records remain independently
owned and expire or disappear independently.
