# Native identity-key storage

Status: implementation direction, 2026-11-17. This is a fresh replacement
component, independent of the legacy security/platform crates.

## Scope

Add `kvm-identity-store` for opaque private-key bytes. Windows uses the current
user's generic Credential Manager store. macOS uses Keychain. No file fallback,
custom encryption, key generation, certificate parsing, trust database or
migration is included in this component. It is not wired into read-only agent
startup. Native calls belong to the control plane and may block or require OS
interaction; they must never run inside capture or input routing callbacks.

Use a fixed development namespace `software-kvm.rebuild.identity.v1`, distinct
from legacy credentials. The final installed application identifier and signed
Keychain access policy remain release decisions. A namespace does not prove code
identity or prevent another process of the same user from accessing the store.

## Data and lifetime

Credential names are nonempty ASCII letters/digits plus dot, underscore and
hyphen, with a 64-byte maximum. No machine names, file paths or user identifiers
are needed. Secret values are nonempty and at most 2560 bytes, matching the
Windows generic credential blob bound. Larger key encodings are explicitly
unsupported rather than silently written somewhere else.

Wrap secret memory with the established `zeroize` dependency. A consumed input
buffer must be protected before validation so rejected values are also wiped.
Do not implement Clone, serialization or content-bearing Debug/Display for
secrets. An explicit borrowed byte accessor is allowed for the cryptographic
owner and native calls. Zeroization covers owned Rust memory, not OS caches,
caller-created copies or an absolute guarantee about compiler/allocator history.

Native allocation/handle ownership must be expressed with RAII and narrow unsafe
blocks with safety explanations. Validate OS-returned sizes before copying.
Release native allocations on every success and failure path. Errors expose
closed categories and optional numeric OS codes only; never payloads, account
names, credential targets or Keychain labels.

## Operations and validation

Provide load, save/upsert and delete for a validated name. Load distinguishes
missing from access denied/unavailable. Delete has an explicit missing outcome.
Unsupported hosts report Unsupported and never persist to files. Unit tests use
an in-memory seam where needed to verify validation and error/lifetime behavior;
they must not mirror trivial getters or claim native-store behavior.

Native round-trip tests are ignored by default and use fresh per-test names
inside this namespace, deleting only their own item. Do not enumerate or read
existing credentials. Do not automatically run tests that may display Keychain
prompts, change global Keychain interaction settings or touch production items.
Native execution must be recorded separately from compilation and pure tests.

Run focused workspace tests, formatting, strict all-target clippy and Apple
cross-checks. Security review is required before integration into the identity
owner. This component alone does not prove enrollment, installed access policy,
safe key migration, physical input performance or release acceptance.
