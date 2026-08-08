# Protocol

The peer protocol is explicitly versioned and uses length-delimited frames. Wire data is defined
inside `kvm-protocol`; internal Rust domain structs are not serialized as an accidental public
contract.

Version one has logical control, input, clipboard, and diagnostics channels. They may initially
share an encrypted connection, but input scheduling is independent and higher priority. A later
transport may split physical connections without changing message semantics.

Keyboard and pointer-button messages carry monotonically increasing sequence numbers and remain
ordered. Pointer movement can be coalesced only where it cannot cross a button or transition
boundary. Every frame is size-limited and rejected before allocation if its version, kind, or
length is invalid.

Cross-host pointer handoff uses a transition identifier, workspace epoch, source display,
destination display, and normalized edge position. The receiving host acknowledges acceptance;
stale transitions cannot take workspace authority.
