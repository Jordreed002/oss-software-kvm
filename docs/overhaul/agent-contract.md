# Replacement agent state and command contract

Implementation contract, 2026-11-17. This defines the replacement's intended behavior; no native agent or transport implementation is certified by this document.

## Authority

The agent is the only writer of committed configuration, trust, session lifecycle and input authority. The native shell owns presentation and process supervision. A webview owns drafts only. Reads cannot authorize suppression. Suppression requires successful reservation of an ordered event into the exact healthy session generation by the capture owner.

Use one serialized session owner with bounded work per tick/callback. Native adapter threads submit to explicitly designed bounded channels; the initial foundation ring is single-owner storage, not that thread bridge. Do not extend it into shared memory without a reviewed synchronization and memory-ordering contract.

Separate these dimensions in a snapshot:

| Dimension | Values and meaning |
| --- | --- |
| Agent identity | Fresh instance ID, binary/API version and negotiated capabilities. A process ID is observational only. |
| Observation | Monotonic snapshot revision and local observation age. Age is host-local; no cross-host subtraction. |
| User intent | Paused or requested sharing. Requested intent does not prove readiness. |
| Session lifecycle | Idle, preparing, active, draining, faulted. Active means capture/session preparation has actually completed. |
| Readiness | Explicit blockers for configuration, enrollment, permissions, inventories, peer authentication and authority. |
| Input authority | Local, remote for an exact host/session/generation, transitioning, or unknown. Unknown is never displayed as confirmed local. |
| Safety | Clear or latched with a structured cause. Ordinary Resume cannot clear a latch. |
| Configuration | Committed revision plus pending transaction status. Drafts are not committed state. |

Expose only negotiated supported capabilities. Initially unavailable mutations must not be presented as working controls.

## Commands

Every command has an instance-bound request ID and, when mutating committed settings, an expected configuration revision. The owner validates authorization, capability, preconditions and bounded admission before acceptance. Acknowledging queue entry is distinct from applying the operation.

Results are rejected, accepted/pending, completed with resulting revision, or failed with reason. A timeout leaves the outcome unconfirmed. The caller requests command status/fresh state before retrying. Duplicate IDs replay the bounded retained outcome or return an explicit expired-result error; never re-run a non-idempotent operation blindly. The retention capacity and lifetime are part of the eventual API implementation.

Do not let command floods starve cleanup or input processing. Each queue has a capacity, work budget and rejection behavior. API and peer protocol versions are independent; host/agent binary mismatch blocks unsafe mutations and offers repair guidance.

## Lifecycle transitions

| Request or event | Required owner behavior | Completion evidence |
| --- | --- | --- |
| Resume | Validate current config, inventories, permissions, authentication and authority. Prepare native/session resources with admission closed. Open admission only after all prerequisites commit. | Confirmed session generation and readiness in the resulting snapshot. |
| Pause | Set paused intent first. Close admission, invalidate pending handoff, reconcile held input and stop suppression. Clipboard sharing also pauses. Keep agent/control endpoint available. | Local teardown completes; destination recovery is confirmed when reachable or left explicitly subject to its independent watchdog. Never promise remote cleanup over a severed link. |
| Quit | Perform Pause/cleanup, stop native/session resources, then stop agent and shell. | Acknowledged drain and observed agent exit. A timeout remains an error, not successful quit. |
| Failsafe | Latch the condition independently of IPC/webview; gate capture and perform bounded cleanup. | Snapshot reports safety latch. A fresh process cannot accidentally restore the previous sharing intent. |
| Native permission loss | Gate input and initiate cleanup immediately; report the exact missing permission/affected process. | Readiness blocked until fresh preflight; user must explicitly Resume. |
| Peer/link failure | Reject new remote suppression, invalidate generation and reconcile held input. | Local recovery independent of UI; destination's own failure detector releases its tracked state. |
| Sleep/lock/session change | Pause and drain before session handover where OS notifications permit; validate readiness after return. | No automatic capture rearm after unlock/wake in the initial utility. |
| Agent restart | Acquire exclusive ownership, validate installed identity and config, publish idle/paused. | New instance ID invalidates old subscriptions, commands and authority. |
| Webview failure | Keep native shell, emergency path and agent operational. | Native Pause and Quit remain usable. |
| Native shell loss | Agent's native health lease expires into paused recovery state. | Lease bound and false-trip behavior must pass load/fault experiments before this design ships. |

Forced termination is not acknowledged cleanup. Recovery guidance must distinguish killed, drained and unknown states. Late events/commands from a retired generation cannot reactivate it.

## Configuration and enrollment

Use draft/validate/commit transactions with expected revisions and atomic durable writes. Apply layout only after inventories and peer revision confirmation agree. Initially stop/edit/validate/restart is acceptable; do not implement unsafe partial live mutation for visual responsiveness.

Enrollment requests are untrusted until the approved protocol binds identity and explicit consent. Keep expiry, rate limits, mismatch and cancellation visible. A changed certificate never triggers silent replacement. Local forgetting immediately revokes local trust and terminates the session without depending on the peer being reachable.

The legacy implementation and the replacement never write the same active profile simultaneously. Imports preserve originals and require explicit version handling. Future-version files are not overwritten. Legacy peer-wire compatibility is a deliberate later decision, not an implicit promise made by reusing an enum.

## Events and performance

Observers obtain a full snapshot first, then events keyed by instance and monotonic revision. Gaps or lag invalidate local state until resynchronization. The server never waits for a renderer subscriber. Slow observers lose observational events, not input events. Hidden webviews unsubscribe; the native shell retains only minimal state needed by menus and health supervision.

Performance evidence must cover commands, pairing, diagnostics and clipboard running under active input load. No renderer event, persistence operation, diagnostic serialization or synchronous log write runs inside a capture callback. Review every steady-state allocation and wakeup introduced by the eventual implementation.
