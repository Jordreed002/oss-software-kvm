# kvm-runtime

This crate is the fail-closed composition boundary for the manually
provisioned two-host native alpha. On Windows and macOS, `run` securely loads
the profile and credentials, enumerates native displays and aggregate
whole-host input, starts the authenticated listener/canonical dialer, owns the
exact session event pumps, and enables suppressible capture only after the
runtime is ready. Ctrl+C gates capture first and then settles sessions.

This is still an engineering alpha: use it only on two test machines with the
emergency shortcut available, and complete the physical validation matrix
before relying on it for unattended work.

The profile is deliberately narrow:

- it is schema version 2 and disabled when `enabled` is omitted;
- it contains stable, non-nil local host and peer IDs plus a bounded local
  display name;
- it admits exactly one selected remote host/peer/fingerprint/address tuple;
- its selected endpoint and 1–4 unique listener endpoints are restricted to
  RFC 1918 IPv4 or IPv6 ULA addresses with nonzero ports;
- all listener ports are identical so later composition can require the same
  port from the main `kvm-config`;
- its selected-peer fingerprint is canonical lowercase SHA-256 hex and its TLS
  server name is bounded, nonblank, and control-free;
- it requires explicit absolute paths for the main `kvm-config`, local TLS
  certificate and private key, and selected-peer trust certificate;
- topology and routing are fixed to `selected_only`;
- enabling the profile requires an explicit `whole_host_alpha = true` opt-in.

Example (use deployment-appropriate absolute paths and identities):

```toml
version = 2
enabled = false
whole_host_alpha = false
kvm_config_path = "/Users/alice/.software-kvm/config.toml"
topology = "selected_only"
routing = "selected_only"
listen_addresses = ["192.168.1.10:24800"]

[local]
host_id = "11111111-1111-4111-8111-111111111111"
peer_id = "22222222-2222-4222-8222-222222222222"
display_name = "Office Mac"

[selected_peer]
host_id = "33333333-3333-4333-8333-333333333333"
peer_id = "44444444-4444-4444-8444-444444444444"
identity_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
socket_address = "192.168.1.20:24800"
server_name = "office-windows.kvm.test"

[tls]
certificate = "/Users/alice/.software-kvm/tls/local.der"
private_key = "/Users/alice/.software-kvm/tls/local-key.pk8"
peer_trust = "/Users/alice/.software-kvm/tls/selected-peer.der"
```

Validate without starting anything:

```console
cargo run -p kvm-runtime -- validate /absolute/path/to/runtime-profile.toml
```

Start the foreground native alpha (run the corresponding profile on both
hosts):

```console
cargo run -p kvm-runtime -- run /absolute/path/to/runtime-profile.toml
```

On macOS, every path component must be a real directory rather than a symlink
(use `/private/...` instead of `/etc/...` when appropriate), and the profile,
main config, and private key must be owned by the current user with no
group/other permissions. On Windows, use absolute local-drive paths; UNC,
reparse-point, remote, and removable paths are rejected, and sensitive files
must have an owner-only DACL. The certificate and trust inputs are single DER
certificates and the key is PKCS#8 DER—not PEM.

The main config must contain exactly the selected peer and explicit display
placements/links for both directions. Use
`kvm-diagnostics displays --host-id <profile-local-host-id>` on each host to
obtain IDs scoped to the same host identity used by the runtime. Display
identity and mixed-DPI topology still require physical verification after
docking, scaling, or GPU changes.

Errors and `Debug` output intentionally omit paths, IDs, fingerprints, socket
addresses, parser details, and file contents.

## Secure static preparation

`prepare(profile_path)` is the non-activating half of the runtime boundary. On
Unix it opens the profile, main config, local certificate,
PKCS#8 DER private key, and selected-peer trust certificate with `O_NOFOLLOW`.
On Windows it rejects UNC/device paths, requires handle-derived volume metadata
to identify a nonremote, nonremovable disk filesystem, then opens each component
relative to the checked parent handle with `FILE_OPEN_REPARSE_POINT`. Both
implementations require bounded non-empty regular files and validate metadata
from the open handle or descriptor.

The profile, main config, and private key must be owned by the current process
user. Unix permits no group or other permissions. Windows requires a present,
non-null, non-defaulted, structurally unambiguous DACL containing only standard
allow/deny ACEs; every nonzero allow ACE must name the owner SID. Certificate
and trust files may be public but must still be bounded, regular, and contain no
reparse point in any path component.

Preparation also requires exactly one config pairing matching the selected
profile host, peer, canonical fingerprint, address, and port; disables
discovery-derived trust; and accepts no configured device route other than
`follow_active_host`. The selected trust certificate's SHA-256 fingerprint must
match the provisioned fingerprint. Credentials are one DER certificate, one
PKCS#8 DER private key, and one DER trust certificate—not PEM bundles.

Platforms other than Unix and Windows fail closed.
