# Audit: §19 Event Ordering — inbound (receiver) path CONFORMANT

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 39
**Spec ref:** `.spec/implementation.md` §19 (Event Ordering)
**Severity:** N/A — conformance confirmation of a safety-adjacent invariant.

## What the spec requires (§19)

```text
Input packets require monotonically increasing sequence numbers.
The receiver must preserve keyboard/button ordering.
Mouse movement may eventually support coalescing.
Keyboard and mouse button events must not be coalesced.
```

§19 is a **receiver** requirement. Cycle 9 audited the *outbound* side
(OutboundQueue strict-FIFO Input lane, no silent drops, no key/button
coalescing). This cycle scoped the *inbound* path: does the receiver enforce the
sequence invariant, preserve order, and avoid coalescing keys/buttons?

## Inbound receiver path

`handle_authorized_message` (`session.rs:1215`) is the single entry for an
arrived frame, over an ordered TLS stream:

```text
accepts_input gate           (session.rs:1223)   — reject before admission
message.validate()           (session.rs:1228)   — integrity check
identity check               (session.rs:1232)   — source_host == expected
accept_sequence(seq)         (session.rs:1235)   — monotonic gate
input_from_wire              (session.rs:1236)
inject_received              (session.rs:1238)   — inject in arrival order
```

### Monotonic sequence — enforced, strictly (and fatal on violation)

`accept_sequence` (`session.rs:1270-1284`):

```rust
if let Some(previous) = session.last_sequence {
    if received <= previous {
        return Err(self.fail_session(
            CoordinatorError::StaleSequence { previous, received }, now_ns));
    }
}
session.last_sequence = Some(received);
```

Per-session `last_sequence: Option<u64>` (`session.rs:315`). The check is
`received <= previous` → reject, i.e. **strictly** increasing (a duplicate or an
out-of-order/gap frame is rejected). Strictly-increasing satisfies §19's
"monotonically increasing" and is the safer reading (also rejects replays and
duplicates). A violation is **session-fatal** (`fail_session`): the peer session
is torn down rather than continuing past a break.

### Ordering preserved — structurally, no reorder buffer

The transport is an ordered TLS/TCP stream; frames arrive in order;
`handle_authorized_message` processes them one at a time in arrival order;
`inject_received` injects each in that same order. There is no reorder buffer —
and none is needed, because any sequence break is fatal before injection. The
receiver therefore cannot emit a reordered key/button sequence: it either
injects the exact arrival order or stops. This is the conservative choice for a
stream where a reorder is a correctness/safety bug (Ctrl-Down, C-Down, C-Up,
Ctrl-Up reordered could deliver a stuck Ctrl or a bare C).

### No coalescing of keys/buttons

A workspace-wide grep for coalesce/coalescing/merge/combine-move in the inbound
path finds none. `inject_received` (`session.rs:1286`) injects every event
individually via `injection.inject(&event)`. `PointerMove` is matched only for
the press/release classification (`session.rs:1379`) and otherwise passes
through like any other event — it is **not** coalesced. §19 makes move
coalescing explicitly optional ("may eventually support"); leaving it
unimplemented is the safe default that keeps ordering trivially preserved.

### Cleanup frames obey the same gate

`ReleaseInput` (stuck-key cleanup) frames also pass through `accept_sequence`
(`session.rs:1410`), so cleanup releases cannot overtake or duplicate input
frames outside the sequence discipline either.

## Web verification

The fatal-reject-on-reorder design is the canonical recommendation for
safety-critical ordered streams. ATProto's event-stream spec states it directly:
*"clients [should] treat out-of-order or duplicate sequence numbers as an error,
not process the message, and drop the connection."* The general literature
distinguishes buffer-and-reorder (latency-tolerant, complex, used where gaps are
expected) from error-and-drop (simple, conservative, used where ordering
correctness is paramount). A software-KVM input stream is firmly in the latter
category — the codebase matches.

## Non-goals

Did not modify code (AUDIT, conformance confirmed). Did not re-audit the
outbound path (cycle 9). Did not evaluate whether a future optional PointerMove
coalescing optimization would be desirable (§19 leaves it open; current
no-coalesce behavior is conformant).
