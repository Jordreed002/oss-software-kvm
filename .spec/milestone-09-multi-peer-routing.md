# Milestone 09 — Exact-Generation Multi-Peer Device Routing

## Status

Implementation started on 2026-08-08 after Milestone 08 passed independent inventory,
transaction, composition, and security audits plus the full Linux and Windows GNU gates.
Arbitrary third-peer routing remains disabled while the versioned release-applied proof and global
exact-generation authority are built and independently audited.

This milestone is platform-neutral. It does not enable native enumeration, hotplug, capture,
suppression, injection, display, clipboard, IPC, or UI code.

## Objective

Lift the M08 two-host routing restriction without weakening its exact-session, lifecycle, and
transaction guarantees:

```text
Local                    -> remain on the device's physical local host
FollowActiveHost         -> local, or the exact admitted selected pointer peer
Host(local)              -> remain local
Host(any paired peer)    -> that peer's exact healthy admitted generation
```

Several paired peers may be admitted concurrently. A local keyboard or pointer may be explicitly
pinned to any one of them, while `FollowActiveHost` continues to follow only the M06 committed
pointer authority between the local host and the manager's selected pointer peer. M09 does not
make pointer focus itself a multi-peer election protocol.

Remote dispatch must remain synchronous and conservative: the caller may suppress a local event
only after the exact destination FIFO accepts it. No route change, task replacement, retry, or
peer selection change may retag a captured event or split a key/button lifecycle across peers or
connection generations. FIFO acceptance proves only that a frame entered the sender's queue. It
does not prove that the old destination injected a synthetic release into its OS, so it is never
sufficient by itself to reopen a device on a different live destination.

## Release decision and fallback

M09 may ship arbitrary explicit peer targets only if one manager-owned transaction can prove all
of the following for every affected destination:

- captures are gated before cleanup begins;
- every old held lifecycle is attached to its exact peer and `ConnectionGeneration`;
- accepted cleanup prefixes are never recreated or replayed as new effects; an ack-lost request may
  use only the exact idempotent v2 retry/resync form;
- unsent cleanup suffixes remain owned and retryable per FIFO;
- each live old destination returns an authenticated application-level `ReleaseAppliedAck` bound
  to the exact peer, host, generation, release transaction, release token, and input sequence;
- policy publication and device reopening wait until every required release has both entered its
  exact FIFO and received that exact applied acknowledgment;
- EOF, transport loss, task loss, timeout, and generation retirement never substitute for proof
  that the remote OS applied a release;
- affected physical controls remain quarantined until their physical release;
- no replacement generation can inherit or implicitly satisfy an old generation's cleanup
  obligation; it may only transport an explicitly bound resync and exact old-obligation ack.

If implementation or independent audit cannot prove those properties, the release must retain the
M08 selected-only remote execution path. It may land internal global-ledger types and tests, but it
must continue rejecting third-host runtime routes and must not expose partial multi-peer behavior.
The existing v1 protocol is not silently extended: arbitrary peer routing remains disabled unless
both ends negotiate the authenticated M09 release-proof capability and all required applied-ack,
reconnect, bounds, and replay proofs pass independent audit.

## Non-overlap boundary

M09 must not modify:

- `crates/kvm-windows/**`;
- `crates/kvm-macos/**`;
- `crates/kvm-diagnostics/**`;
- `docs/validation/**`;
- native enumeration, hotplug, capture, suppression, injection, display, or clipboard code;
- Tauri, local IPC, control-panel, startup, or installer code.

Expected implementation paths are `kvm-types`, `kvm-protocol`, `kvm-router`, `kvm-config`,
platform-neutral `kvm-daemon`, this specification, root documentation, and `Cargo.lock` only when
required. Protocol changes are permitted only when necessary for bounded exact-generation
composition; native adapters remain untouched.

## Architecture decision — one global routing authority

`PeerManager` must own the only mutable routing authority for the workspace. Per-peer supervisors
remain responsible for authentication, exact-generation session lifecycle, FIFO sequencing, and
inbound injection, but they must not own independent copies of route policy or physical held state.

The manager-owned state must include, directly or behind one affine control object:

- the checked published policy revision and at most one staged candidate;
- the current selected pointer peer and committed pointer authority needed by
  `FollowActiveHost`;
- one bounded physical held/quarantine ledger keyed by local device and control;
- each remote latch's exact `PeerId`, `HostId`, and `ConnectionGeneration` destination;
- bounded cleanup groups and their accepted-prefix/unsent-suffix progress for every exact FIFO;
- per-device capture gates and global failsafe/disable/shutdown gates;
- current authenticated inventory and admission observations used to validate destinations.

No public or cloneable sender, per-peer routing snapshot, host-only lookup, or supervisor-local
held ledger may independently authorize suppression or remote dispatch. Read-only snapshots are
observational and cannot be converted back into routing authority.

## Workstream A — Global bounded policy and destination resolution

- preserve the existing durable `Local`, `FollowActiveHost`, and `Host` configuration forms;
- permit an explicit remote `Host` target only when it is a currently paired host with an
  unambiguous configured peer identity;
- require a healthy exact admitted session with fresh exact-generation inventory immediately
  before an explicit remote event is enqueued;
- retain an offline paired route as dormant policy, but do not silently fall through to the
  selected peer or another remote peer;
- continue treating `Host(local)` as `Local`;
- keep `FollowActiveHost` bound solely to committed pointer authority: it resolves to local when
  local is active and to the exact selected pointer-peer generation when remote is active;
- never resolve `FollowActiveHost` to an arbitrary healthy peer when the selected peer is absent;
- reject nil, local/remote ownership-inconsistent, unpaired, ambiguous, revoked, or excess route
  targets transactionally;
- require runtime mutation of a route only for a device in the current validated local inventory;
- preserve dormant policies for validated devices that later disappear and reactivate them only
  after a checked inventory revision reports the stable ID again;
- publish policy revision and complete route set atomically after cleanup settlement and durable
  persistence;
- use checked counters for policy, transaction, effect, capture, and cleanup identities;
- keep the existing safe default `FollowActiveHost` for unknown physical devices, while an
  explicitly removed/gated stable ID stays gated until validated reappearance and restoration.

Destination resolution must return a short-lived exact capability, not a host-only promise. The
capability is valid only within the manager's serialized mutable operation and must be rechecked
against peer task slot, admission, generation, health, inventory freshness, workspace readiness,
and route revision immediately before enqueue.

## Workstream B — Exact multi-peer held lifecycles

- latch every state-bearing key or button on its first accepted press to exactly one of local or
  `(PeerId, HostId, ConnectionGeneration)`;
- send repeats and physical release to the latched destination regardless of later pointer,
  policy, health, or selection changes;
- commit a remote latch only after the exact FIFO accepts the first Input frame;
- preserve a remote latch across a policy transaction only when peer, host, generation, and
  effective route are unchanged;
- treat the same host on a replacement generation as a different destination requiring cleanup;
- never migrate a held lifecycle directly from peer A to peer B or from generation A1 to A2;
- after a synthetic release, quarantine the still-physical control and suppress its repeats and
  final physical release without synthesizing a press on its new destination;
- keep local lifecycles local through release even when focus or policy changes;
- ensure injected remote input cannot re-enter physical capture or contribute to the emergency
  chord;
- retain device-correct aggregate emergency-key accounting across all local physical keyboards;
- make unmatched releases, motion, scroll, invalid records, and stale retries allocate no held
  state;
- positively bound devices, controls per device, aggregate controls, latches per peer/generation,
  quarantined controls, and all cleanup records.

Capacity or checked-counter exhaustion must not partially latch, enqueue, publish, or move a
control. A fresh press that cannot be remotely committed stays local or gated according to the
existing fail-safe contract. A repeat or release belonging to an already suppressed remote
lifecycle remains suppressed and enters retryable cleanup/quarantine; it must never leak into the
local OS.

## Workstream C — Transactional multi-FIFO cleanup

Only one manager-wide route or local-device inventory transaction may be staged. Route mutation,
inventory removal/metadata change, pointer transition, failsafe, disable, revocation, and shutdown
must share the same cleanup ownership rules.

A multi-peer transaction follows this order:

1. validate expected revision, local ownership, pairing, target, admission feasibility, aggregate
   capacity, persistence candidate, and complete affected set without mutation;
2. allocate one checked affine transaction identity;
3. gate every affected local device before reading or changing held state;
4. partition required releases by exact `(PeerId, HostId, ConnectionGeneration)`;
5. establish a deterministic cleanup-group order and preserve original per-FIFO Input order;
6. allocate a checked, unpredictable release token for each bounded release effect and bind it to
   the global transaction, exact old destination, and exact last affected Input sequence;
7. enqueue each group's v2 release effects through its manager-owned exact session capability;
8. record each FIFO-accepted prefix immediately and retain only its exact unsent suffix on full,
   closed, sequence exhaustion, task loss, or other failure;
9. retain FIFO-accepted effects as `AckPending` until an authenticated exact
   `ReleaseAppliedAck` proves successful remote OS injection through the bound sequence;
10. on EOF, transport loss, or task loss, keep every unacknowledged effect gated; either obtain a
    bounded authenticated reconnect resynchronization and exact applied ack, or leave its affected
    devices permanently gated;
11. durably save the complete candidate only after all required release acknowledgments settle;
12. publish the complete policy and incremented revision atomically through an infallible commit;
13. restore eligible devices only after publication, keeping synthetically released physical
    controls quarantined until physical release.

There is no total ordering between independent network FIFOs. M09 atomicity therefore means that
all affected capture remains gated until every old destination barrier has settled and the new
policy is published. Releases accepted by peer A may arrive before peer B accepts its suffix, and
an ack from B may arrive before A's ack, but no affected event may start on any new destination
until all exact applied acknowledgments have settled.

Retry must resume the deterministic first unsettled group and exact unsent suffix. It must not
resend an accepted prefix, rebuild effects under a new generation, recompute the affected set from
live policy, or publish a subset. An accepted but unacknowledged release is retried only through the
idempotent v2 release/resync protocol with the same transaction, token, old generation, and
sequence; it is never recreated as a new-generation effect. Abort before durable commit must drain
and obtain applied proof for already-created cleanup, discard the candidate, and restore only
devices eligible under the still-published policy. A candidate is no longer abortable after
durable commit. Crash recovery must preserve permanent gates for cleanup whose applied proof was
not durably known; restarting the sender is not evidence that the remote OS released input.

## Workstream D — Protocol v2 release proof and capability negotiation

The current protocol has a hard v1 version and must remain byte- and behavior-stable. M09 must not
reuse a v1 discriminant, append fields that a v1 decoder silently ignores, or infer support from
receipt of an unknown application message.

- define an explicit protocol v2 framing/version path; protocol v2 normatively includes the
  release-proof capability, exposed to composition through a named semantic capability query
  rather than scattered raw version comparisons;
- negotiate the exact version before application traffic, bind that selection to the
  authenticated session transcript and paired identities, and reject downgrade or mismatch;
- keep v1 peers interoperable only through the M08 selected-only behavior; never send them an M09
  release effect and never enable an arbitrary peer route involving them;
- define a bounded release request carrying a release transaction ID, unpredictable release token,
  exact old owner host/peer identity, old connection-generation identity, affected device/control
  scope, and the exact last Input sequence it covers;
- define `ReleaseAppliedAck` with the same transaction, token, old host/peer/generation, and
  sequence binding plus a coarse applied outcome;
- accept an ack only on an authenticated currently admitted channel for the same paired peer and
  host, and only when it exactly matches one outstanding manager-owned effect;
- emit an ack only after every covered release has been successfully applied to the receiver's OS
  injection backend and its inbound held ledger has committed the corresponding removal;
- order the release request after all covered Input on the old session FIFO; order the ack after
  receiver-side application, not merely decode or channel receipt;
- make exact duplicate release requests and acks idempotent; reject token reuse with different
  transaction, generation, sequence, device/control scope, or outcome as a conflict;
- reject unsolicited, early, stale, cross-peer, cross-host, cross-generation, future-sequence,
  malformed, and already-retired-conflicting acks without opening a gate or settling other work;
- retain bounded replay tombstones long enough to answer exact duplicates without applying a
  release twice or accepting a conflicting token;
- positively bound outstanding release requests, acks, tokens, tombstones, resync scopes, encoded
  bytes, controls per request, aggregate controls, and retry attempts; use checked counters only;
- redact all release identities, tokens, sequences, generations, scopes, and backend details from
  ordinary diagnostics.

If the old connection ends before its ack is authenticated, transport loss does not settle the
barrier. A replacement authenticated v2 session for the same paired peer/host may perform a bounded
release-state resynchronization. The resync request must cite the original old generation,
transaction, token, and covered sequence. The receiver must idempotently apply or prove all covered
releases against its retained old-generation ledger/tombstone, then return an exact
`ReleaseAppliedAck`. The ack is logically bound to the old release obligation even though it is
transported by the explicitly recorded replacement generation.

If resynchronization cannot establish exact scope, the receiver cannot apply every release, its
ack cannot be delivered/authenticated, a replay bound is exhausted, or either peer lacks the v2
capability, the affected local devices remain permanently gated. Neither timeout, EOF, operator
retry, fresh inventory, same-host admission, nor a successful new TLS session reopens them.

## Workstream E — Multi-peer session and task composition

- allow bounded concurrent admitted sessions for distinct paired peers while retaining at most one
  current admitted generation per peer;
- keep `ManagedSessionOutbound` or its successor manager-installed and non-cloneable;
- require manager identity, peer identity, exact task generation, admission state, and lifecycle
  match before installing or using an outbound capability;
- return all affine prepared resources unchanged when exact installation is rejected;
- bind every queued Input, release request, `ReleaseAppliedAck`, resync, inventory message, pointer
  message, cleanup effect, task loss, and terminal event to the exact peer generation that owns it;
- ensure a stale event for peer A cannot mutate peer B, and stale generation A1 cannot retire,
  satisfy cleanup for, or enqueue into A2;
- retain A1 cleanup as a separate obligation when A2 replaces it; A2 may carry an explicitly bound
  resync/ack for A1, but neither A2 admission nor A1 terminal invalidation settles that obligation;
- keep every device affected by A1 cleanup gated while A2 serves unrelated devices or attempts
  resynchronization;
- do not block healthy peer B merely because unrelated peer A is reconnecting, except while a
  manager-wide transaction intentionally gates devices whose cleanup spans both peers;
- preserve each peer's FIFO order independently: earlier Input precedes its ReleaseInput, protocol
  control messages retain their established priority ordering, and later Input cannot overtake a
  transaction barrier;
- process outbound closure/transport termination only through the existing exact session lifecycle
  path, but treat it as session retirement rather than release-applied proof; queue `Full`, logical
  degradation, timeout, retryable reconciliation, and exact EOF all leave ack-pending gates closed;
- clear exact remote inventory authority on degradation or terminal loss as specified by M08,
  without rolling back committed local inventory or global policy;
- keep nonselected inventory broadcasts exact-generation and best effort; failure reconciles only
  the failing session and cannot falsely retire another task;
- make task-loss recovery exact and idempotent, including task loss during partial multi-FIFO
  enqueue, ack wait, and reconnect resynchronization.

The selected pointer-peer supervisor may continue owning pointer protocol mechanics. It must call
the same global routing barrier for affected `FollowActiveHost` controls. Nonselected explicit
peer pins coexist with pointer handoff and are unchanged when their exact destination remains
healthy and identical.

## Workstream F — Aggregate bounds, privacy, and observation

- add positive configuration limits for paired peers, concurrently admitted peers, global routes,
  held devices, controls, cleanup groups, cleanup records, per-peer cleanup, inventories, pending
  tasks, outstanding acks, replay tombstones, resync work, and outbound work;
- validate aggregate limits before per-peer allocation so distributing work over many peers cannot
  evade a global bound;
- make maximum-plus-one and multiplication/sum overflow fail transactionally;
- keep all revisions, sequences, generations, deadlines, attempts, and identifiers checked and
  non-reusable;
- expose only deterministic coarse/count summaries for policy, held state, cleanup/ack progress,
  peer readiness, negotiated capability, and pending transactions;
- redact host, peer, device, key/button, route, generation, revision, network, credential, device
  name, and backend payloads from ordinary `Debug`, errors, and tracing;
- ensure error variants identify only an actionable category and bounded failure count;
- make snapshots immutable and observational; stale snapshots cannot authorize enqueue,
  suppression, ack acceptance, cleanup settlement, or policy commit.

## Safety invariants

1. `PeerManager` owns one authoritative route policy, physical held ledger, quarantine ledger, and
   cleanup transaction for the whole workspace.
2. `FollowActiveHost` resolves only from committed pointer authority and the exact selected peer;
   it never load-balances or fails over to another peer.
3. An explicit remote route dispatches only to its paired, healthy, freshly inventoried, exact
   admitted peer generation.
4. Suppression is reported only after that exact destination FIFO accepts the event.
5. One state-bearing physical lifecycle never splits across local, peers, or generations.
6. Same host plus a different peer or generation is a different destination.
7. FIFO acceptance moves a release from unsent to ack-pending; only its exact authenticated
   `ReleaseAppliedAck` proves remote OS application and settles it.
8. EOF, transport loss, task loss, retirement, timeout, and replacement admission never settle an
   unacknowledged release obligation.
9. A partial multi-FIFO failure retains exact unsent suffixes and ack-pending effects and never
   permits partial policy publication.
10. No affected event reaches a new destination until every old-destination applied-ack barrier
    settles.
11. A stale capture, effect, ack, resync, snapshot, task, terminal event, revision, or generation is
    a no-op and cannot be retagged.
12. Replacement sessions cannot inherit old queued work, held state, inventory authority, or
    cleanup obligations; they may carry only an explicitly bound resync for the old obligation.
13. Pointer handoff affects `FollowActiveHost`; unchanged exact explicit pins and local lifecycles
    remain independent.
14. Unavailable explicit peers do not silently fall through to local, selected, or another remote
    destination for an already-suppressed lifecycle.
15. Durable policy never changes before all required applied acknowledgments settle, and in-memory
    publication never precedes successful durable save.
16. Peer-local failure is isolated unless the peer participates in the one active global
    transaction.
17. Held state, quarantines, routes, peers, inventories, cleanup groups, ack state, replay
    tombstones, resync work, queues, strings, files, and counters are positively and aggregately
    bounded.
18. Protocol v2/capability negotiation is authenticated and downgrade-resistant; a v1 peer cannot
    enter an M09 multi-peer release transaction.
19. Normal diagnostics reveal neither input payloads nor stable identity, routing, session,
    release-token, sequence, network, inventory, or credential data.
20. No native event is enumerated, captured, suppressed, injected, or routed by M09.

## Adversarial acceptance matrix

All cases are deterministic and must assert both the returned disposition/outcome and the complete
post-state, including queue contents, policy revision, gates, latches, cleanup suffixes, session
tasks, and redacted diagnostics where applicable.

| Case | Setup and adversarial action | Required result |
| --- | --- | --- |
| Explicit third peer | Pair capable v2 peers A and B; admit both; pin a local keyboard to B | Press/repeat/release use B's exact FIFO and suppress locally only after each required enqueue; A receives nothing |
| Follow remains selected | B is healthy, but A is selected and pointer authority is remote | An unknown/default device routes only to exact A; B is never chosen as fallback |
| Follow local authority | A and B are healthy while committed pointer authority is local | Follow input remains local and allocates no remote latch |
| Explicit peer unavailable | A is selected and healthy; explicit target B is degraded/offline | A receives nothing; a fresh event follows the safe gated/local contract, while an existing B latch stays suppressed and retryable |
| Same host, replacement generation | A1 owns a held key; A1 terminates and A2 is admitted | A2 cannot receive the old repeat/release or ordinarily satisfy A1 cleanup; only exact A1 resync plus applied ack may settle it |
| Cross-peer route churn | Hold controls on A and B, then replace both routes with local/C | All affected devices gate first; releases enter A and B FIFOs and both exact applied acks arrive before one atomic publication; no new-destination Input appears early |
| First cleanup FIFO full | A is the first deterministic group and accepts nothing | No policy publication; A's full suffix and all B work remain owned; retry starts at A without mutation |
| Middle cleanup failure | A accepts and acks all; B accepts a prefix then becomes full; C is untouched | A is never replayed, B retains its ack-pending prefix and exact unsent suffix, C remains pending, and all affected devices stay gated |
| Last cleanup failure | Earlier groups have exact acks; final group is full | Policy remains old; retry addresses only the final exact suffix and does not recreate prior acked effects |
| FIFO accepted but ack delayed | A's release FIFO accepts the old release; B is ready for a new press; A delays its applied ack | The device remains gated and B receives no new press until A's exact ack is authenticated |
| Receiver injection failure | A decodes a release request but its OS injection backend fails | A emits no success ack, sender retains `AckPending`, session reconciliation begins, and the device cannot reopen elsewhere |
| FIFO closed or EOF | Release is unsent or ack-pending when the exact transport closes and terminal EOF is authenticated | Session retirement occurs, but no cleanup obligation settles and no affected gate opens |
| Stale terminal event | A1 cleanup exists, A2 is current, and a delayed A0/A1 duplicate arrives | It cannot retire A2, settle A1 applied proof, publish policy, or alter another peer |
| Task loss during cleanup | Runner for B disappears after an accepted prefix and before its ack | Exact unsent suffix and ack-pending prefix remain owned; task recovery is idempotent and opening waits for resync plus applied proof |
| Duplicate retry | Retry is invoked repeatedly after one group is ack-pending or settled | FIFO-accepted prefixes are not recreated, exact tokens/counters are not reallocated, and settled acks stay idempotent |
| Exact duplicate ack | A repeats the same authenticated ack after its first copy was processed or lost | The duplicate is idempotent, applies no release twice, allocates nothing, and cannot advance another effect |
| Ack token conflict | A reuses an outstanding/retired token with a different transaction, old generation, sequence, scope, or outcome | The conflict fails closed, opens no gate, and does not replace the original tombstone/effect |
| Forged cross-peer ack | B sends a structurally valid ack for A's transaction/token | Authentication context and exact owner binding reject it before cleanup mutation |
| Stale-generation ack | A2 sends an ordinary ack naming A1, without an authorized A1 resync exchange | It cannot satisfy A1; only the explicitly bound replacement-resync path may transport old-generation proof |
| Early/future ack | Ack arrives before its release was FIFO-accepted or cites an unissued/future covered sequence | It is rejected without publication, gate opening, counter advancement, or effect creation |
| Lost ack response | Receiver applies the release, but its ack FIFO is full/closed | Receiver retains a bounded replay tombstone; exact request/resync retry returns the same ack without reinjection |
| Reconnect resync success | A1 ends ack-pending; authenticated capable A2 resyncs the exact A1 transaction/token/sequence | Receiver idempotently applies or proves the old scope, returns an ack bound to A1 and transported by recorded A2, then and only then may the barrier settle |
| Reconnect resync ambiguity | A2 cannot prove the old scope, receiver lost required ledger state, or one covered release fails | No success ack is accepted and affected devices remain permanently gated |
| Ack/tombstone capacity | Outstanding effects or replay tombstones reach the aggregate maximum, then one more release is proposed | The proposal fails before enqueue/policy mutation; existing proof and replay records remain intact |
| v1 peer | One target negotiates only the current hard v1 protocol | No v2 message is emitted and arbitrary routing involving that peer remains selected-only/rejected |
| Capability downgrade | An intermediary/peer strips or changes the v2 release-proof capability or version | Transcript/authentication binding detects mismatch and admission fails closed without enabling M09 |
| Unknown v2 message to v1 | A v2 release/ack discriminant is presented to a v1 decoder | v1 rejects it explicitly; no trailing fields are ignored and no v1 semantic is reinterpreted |
| Abort before commit | Cleanup was partially accepted, persistence has not committed, caller aborts | Existing cleanup obtains exact applied proof before abort completes; old policy/revision remains; eligible devices restore only after ack barriers |
| Abort after durable commit | Candidate has been durably saved | Abort is rejected without rollback; retry completes publication/reconciliation of the same candidate |
| Persistence failure | Every applied-ack barrier settles, but saving the candidate fails | Old policy stays published; candidate and gates remain retryable; no release or ack is replayed as a new effect |
| Stale policy revision | A second caller submits an old expected revision during/after a transaction | It is a no-op with no enqueue, gate, allocation, persistence, or publication |
| Concurrent mutation | Inventory removal, pointer handoff, or another route candidate races a staged transaction | One serialized authority wins; the other is rejected/busy and cannot cross the existing barrier |
| Pointer handoff with explicit pin | Follow control is held on A; another device is explicitly held on healthy B | Handoff cleans/gates the Follow lifecycle as required; unchanged exact B pin remains on B through release |
| Peer failure isolation | B disconnects while A-only devices continue and no global transaction spans B | A continues safely; B state is reconciled without clearing A task, inventory, or latches |
| Multi-peer inventory spoof | An admitted A generation sends B-owned device metadata or a stale A generation sends a delta | Message fails closed atomically; neither inventory authorizes routing or injection |
| Remote input ownership | A sends Input for an unknown, B-owned, wrong-capability, or removed device | Injection is rejected before mutation; B and local ledgers are unchanged |
| Capture retag race | A capture decision is delayed across A1 retirement and A2 admission | It cannot enqueue or suppress into A2; no generation field is rewritten |
| Prepared sender escape | Build a session, attempt install into another manager/peer/generation, then retry owner | Rejection returns all affine resources unchanged; only exact owner installation permits the runner/event pump to use the private FIFO |
| Sequence/effect exhaustion | Exhaust one peer's sequence or a global transaction/effect counter | No wrap, reuse, partial latch, or partial publication; exact affected routing stays conservatively gated |
| Per-peer bound evasion | Spread maximum controls/cleanup over every peer, then add one more globally | Aggregate maximum-plus-one fails before mutation even when each peer remains under its local cap |
| Peer-count bound | Admit or configure maximum peers plus one | The excess operation fails atomically without evicting or aliasing an existing peer |
| Quarantine across peers | A applies and acks a synthetic release, route changes to B, then repeats/release arrive | Neither repeat nor release is sent to B or leaked local; final physical release drains quarantine only |
| Emergency chord | Chord keys are split across trusted local keyboards while several peers are active | Failsafe is synchronous and local, gates all remote decisions, and creates bounded exact cleanup for every affected peer |
| Revocation/shutdown | Several peers own held controls and one release or ack FIFO backpressures cleanup | Revocation/shutdown does not discard unsent/ack-pending work or treat EOF as applied proof; terminal lifecycle remains conservative and bounded |
| Dormant explicit route | Paired capable B is offline when policy loads, then admits a fresh exact generation | Policy stays dormant while offline and activates only after exact capability/health/inventory readiness; no earlier event is replayed |
| Removed/re-added local ID | Remove a device pinned to B, obtain applied cleanup proof, then re-add the same validated stable ID | Removal stays gated and retains durable policy; re-add restores the B policy only after the new inventory revision and exact ack barrier |
| Diagnostics markers | Put unique markers in peer/host/device IDs, names, routes, keys, generations, revisions, release tokens/sequences, addresses, credentials, and backend errors | Public Debug, errors, snapshots, and normal tracing contain none of the markers; only coarse categories/counts remain |
| Selected-only fallback | Disable or fail v2 negotiation, applied-ack, resync, bounds, replay, or multi-FIFO proof | Third-host routing remains rejected and all M08 selected-only tests continue to pass without a partial feature mode |

The existing M06-M08 adversarial suites remain mandatory, especially pointer Ack/Commit ordering,
press/repeat/release bijection, exact inventory authority, partial cleanup retry, offline removal and
re-add, committed inventory retry, task loss, outbound-capability closure, and diagnostics markers.

## Quality gates

```text
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff --check
```

Every changed platform-neutral crate must also pass Windows GNU workspace check and strict Clippy.
Focused test runs must exercise every branch of first/middle/last multi-FIFO failure, exact terminal
non-settlement, delayed/lost/conflicting/replayed applied acks, reconnect resync success/failure,
v1/v2 downgrade rejection, stale-generation rejection, aggregate maximum-plus-one, and
selected-only fallback.

Independent routing-ledger, multi-FIFO lifecycle, protocol-version/capability, applied-ack/resync,
session-capability, persistence, bounds/privacy, and final integration audits must report no
blocker or high-severity finding. Release review must explicitly record either:

- arbitrary paired-peer routing is enabled because atomic cleanup, authenticated remote-applied
  proof, reconnect safety, and exact-generation ownership were proven by source audit and the
  complete acceptance matrix; or
- arbitrary paired-peer routing remains disabled and M08 selected-only rejection is preserved.

## Explicitly deferred

- multi-peer pointer-focus election, dynamic selected-peer switching, and a general workspace graph;
- distributed consensus or transactions stronger than the required authenticated v2
  `ReleaseAppliedAck` barrier;
- simultaneous policy candidates, per-device independent commits, and cross-daemon policy
  consensus;
- automatic rerouting/failover of an explicit host policy to another peer;
- native enumeration, hotplug, capture, suppression, injection, and physical stable-ID validation;
- native callback-to-actor reservation/drain wiring and physical latency/performance validation;
- high-resolution scroll, advanced mouse buttons, trackpad gestures, and device fingerprinting;
- Tauri UI, local IPC, control-panel editing, remote administration, and policy synchronization;
- clipboard, file transfer, audio, startup/service installation, and internet relay operation.
