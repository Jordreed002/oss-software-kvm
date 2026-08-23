# Security Policy

## Supported scope

OSS Software KVM is a **pre-release alpha**. There are no released, supported versions;
only the `main` branch and open pull requests receive security attention. Security fixes
land on `main` and are documented in the [changelog](CHANGELOG.md) and
[docs/security.md](docs/security.md).

## Reporting a vulnerability

**Do not open a public issue for security-sensitive bugs.** Software KVM captures and
injects keyboard and pointer input and authenticates peers over the local network, so
anything that could leak input, bypass authentication, or escape suppression must be
reported privately via
[GitHub Security Advisories](https://github.com/Jordreed002/oss-software-kvm/security/advisories/new).

Please include the OS and versions of both hosts, the commit you tested, and a minimal
reproduction. If a proof of concept requires physical hardware (for example an injection or
suppression escape), describe the setup so maintainers can reproduce it.

## What we consider a vulnerability

Examples within scope:

- Input disclosure: captured keystrokes, pointer input, or clipboard text observable by
  anyone other than the paired peer.
- Authentication or pairing bypass, or downgrade of the mutually authenticated TLS 1.3 /
  exporter-bound admission path.
- Suppression escape: local input suppression releasing or failing without the failsafe
  invariants holding.
- Injection of input by an unpaired or unauthenticated peer.
- Panic-inducing remotely reachable parse paths (the workspace denies `unsafe`, but DoS
  via untrusted input still counts).

## Threat model (summary)

Discovery establishes reachability, not trust: a discovered daemon cannot inject input or
receive clipboard data until both machines complete a mutual-consent, verification-code
pairing flow. Sessions use mutually authenticated TLS 1.3 with exporter-bound admission
proofs, a paired-host fingerprint allowlist, and bounded, fail-closed parsing on every
untrusted surface. The daemon listens only on explicitly selected local-network
interfaces; there is no WAN or cloud relay mode. The full threat model and trust boundary
are documented in [docs/security.md](docs/security.md).

## Response expectations

This is a volunteer-maintained alpha; we aim to acknowledge reports within 72 hours and
will triage severity within two weeks, keeping reporters informed of progress. Fixes are
prioritized ahead of feature work. Once a fix is released we will credit the reporter
unless they prefer otherwise.

## Hardware validation before production trust

Software KVM is input-injection software: platform-neutral CI **cannot** validate native
input suppression, injection, permissions (Accessibility/Input Monitoring, UIPI/secure
desktop), or end-to-end latency. No alpha build should be trusted for production use
until the corresponding physical validation entries exist under
[docs/validation](docs/validation) and the [performance budget](docs/performance-budget.md)
has been measured on hardware. Treat every pre-release build as unvalidated on hardware
by default.
