# Milestone 06 — Authenticated Logical Workspace and Pointer Handoff

## Status

Completed on 2026-08-08 after independent pointer-safety and composition audits found no remaining
blocker or high-severity issue. The full locked workspace test suite, strict workspace Clippy,
formatting, Windows GNU workspace check, and strict changed-crate Windows GNU Clippy all passed.
This milestone is platform-neutral and remains isolated from native validation work occurring in
the Windows worktree.

## Objective

Turn authenticated peer sessions and the existing topology primitives into a safe, simulated
cross-host pointer-control plane without enabling native capture or suppression:

1. accept bounded display inventories only from the exact admitted host that owns them;
2. compile local and authenticated remote inventories plus configured placements/links into one
   immutable, revisioned logical workspace;
3. propose a cross-host pointer transition only across a configured, geometrically valid edge;
4. prepare the destination, make source routing inert before the ordered commit is queued, and
   transfer authority only when that exact commit is observed;
5. abort or reconcile every stale, duplicate, rejected, disconnected, timed-out, or reconfigured
   transition deterministically.

The result is a platform-neutral control-plane milestone. Native backends may later feed local
display enumeration and boundary observations into it, but this milestone uses deterministic
simulated inputs only.

## Non-overlap boundary

This milestone must not modify:

- `crates/kvm-windows/**`;
- `crates/kvm-macos/**`;
- `crates/kvm-diagnostics/**`;
- `docs/validation/**`;
- native display enumeration, capture, suppression, injection, startup, or clipboard watchers.

Expected implementation paths are `kvm-protocol`, `kvm-topology`, platform-neutral modules in
`kvm-daemon`, configuration validation where necessary, root documentation, this specification,
and `Cargo.lock` only if dependency resolution requires it.

## Workstream A — Authenticated display inventory

Add deliberate wire/domain conversion and a bounded inventory state machine.

Required behavior:

- validate every `DisplaySnapshotV1` and `DisplayUpdatedV1` again at the daemon composition
  boundary even when it arrived through the protocol decoder;
- require the message host and every contained display owner to match the exact admitted remote
  host; never infer ownership from peer names, discovery, addresses, or configuration placement;
- reject nil host/display IDs, duplicate display IDs, empty/control-character names, invalid or
  excessive geometry, multiple primaries, zero revisions, stale/equal revisions, and snapshots
  above a positive display bound;
- apply snapshots atomically and apply updates only at the next exact revision so gaps cannot hide
  missing inventory state;
- keep local inventory updates behind the same validation rules without pretending they are remote
  network messages;
- expose immutable snapshots with deterministic ordering and count-only/redacted diagnostics;
- clear or mark remote inventory unavailable on generation loss, revocation, or identity change;
  cached inventory must never authorize a new session.

The inventory layer owns public display metadata only. It does not decide trust, topology, routing,
or native display handles.

## Workstream B — Immutable configured workspace compilation

Extend `kvm-topology` with a bounded, immutable logical workspace compiled from validated display
inventories and explicit placement/link inputs.

Required behavior:

- require globally unique, non-nil display IDs and non-nil owning host IDs;
- bound hosts, displays, links, coordinates, workspace extent, and epoch progression;
- require every placement and link endpoint to reference a current inventory display exactly once;
- reject ownership collisions, dangling/unplaced displays, self-links, duplicate source edges,
  non-reciprocal conflicting links, non-finite geometry, and arithmetic overflow;
- treat refresh rate as informational and derive workspace display size from logical size only;
- permit a transition only through an explicitly configured source edge whose destination geometry
  touches and covers the normalized crossing position;
- map mixed resolution/DPI positions using normalized logical coordinates;
- increment the workspace epoch only after a complete candidate compiles successfully; a failed
  update leaves the previous immutable workspace active;
- provide owner lookup and transition results containing source/destination display and host,
  source/destination edge, normalized position, and destination logical point;
- keep Debug/errors count-only or coarse and free of display names and stable identifiers.

## Workstream C — Prepare/ack/commit pointer handoff

Add a daemon coordinator around `PointerLeaveV1`, `PointerEnterV1`, and
`PointerTransitionAckV1`, plus an explicit `PointerTransitionCommitV1` finalization message.

Required behavior:

- bind every transition to the current admitted session, active host/display, compiled workspace
  epoch, and one checked monotonically increasing transition ID/sequence domain;
- only the current authoritative host may propose leaving its active display;
- derive the destination exclusively from the compiled configured workspace; caller-supplied host
  or display targets are never trusted;
- send one bounded `PointerEnterV1` proposal and retain local routing authority until an exact
  `Accepted` acknowledgement arrives;
- accept an inbound enter only when the source matches the admitted host, the destination is local,
  the workspace epoch is current, the configured transition is exact, and no conflicting handoff
  is pending;
- make exact duplicate proposals/acknowledgements idempotent while rejecting conflicting reuse,
  stale epochs, wrong receivers/displays, future IDs, and replay from an old admitted generation;
- treat an accepted acknowledgement as preparation only: the destination must retain its prior
  remote-authority view until it receives the exact commit;
- put `PointerTransitionCommitV1` in the same bounded FIFO traffic lane as later input; before
  enqueueing it, publish an operational handoff gate that suppresses trusted physical input
  without forwarding it, and retain the emergency shortcut path;
- update the source `WorkspaceState` only after the commit has been queued successfully, and update
  the destination only after it validates that exact commit; a queue failure rolls the source back
  to local authority;
- on rejection, source timeout, disconnect, degradation, revocation, workspace replacement,
  sequence exhaustion, or outbound failure, remain/return local and clear pending authority;
- on destination preparation timeout or inbound sequence exhaustion, preserve the prior remote
  authority until mandatory session-fatal reconciliation restores local control, preventing two
  simultaneously authoritative hosts;
- keep at most one pending inbound and one pending outbound proposal per peer with a positive
  timeout bound;
- return outbound protocol effects explicitly so tests can drive two coordinators without sockets
  or native input;
- use custom diagnostics that expose state/count/category only, never pointer coordinates, display
  names/IDs, peer IDs, or input payloads.

`PointerLeaveV1` remains an observation/control hint, not authority by itself. A destination must
never activate from a leave message alone.

## Workstream D — Session and configuration integration

Connect the new state machines to the existing admitted peer composition without expanding native
scope.

Required behavior:

- route display and pointer-control messages currently returned as `Deferred` into explicit
  inventory/handoff handlers bound to the same current `AdmittedPeer` generation;
- make this the mandatory peer-manager path before any connection/session task can start; the M06
  control plane has one immutable selected pointer-authority peer, while other admitted peers may
  publish bounded display inventory but cannot mutate pointer authority;
- preserve the existing single inbound sequence safety domain for input/release traffic; pointer
  control uses its own checked transition sequence and cannot reset or bypass input ordering;
- invalidate pending transitions before applying an inventory/config workspace replacement, and
  expose a bounded transactional runtime replacement API for placements and links;
- publish a local full display snapshot after admission and after a local inventory revision;
- reject display/pointer traffic before admission or from a stale generation;
- ensure degradation/disconnect/revoke/shutdown reconciliation clears transition authority before
  a replacement generation is possible;
- drive pointer deadlines from the manager lifecycle tick; a stale/late commit, exhausted sequence,
  or other pointer protocol inconsistency is fatal to that exact generation and cannot leave its
  manager task slot occupied after cleanup succeeds;
- make outbound queue failure visible and fail closed without losing the last committed workspace;
- keep integration deterministic with fake outbound/inventory backends and no OS calls.

## Safety invariants

1. Display ownership comes only from the admitted transport identity plus exact message ownership.
2. Discovery, address, name, config placement, and prior-session inventory never establish trust.
3. A workspace replacement is atomic; invalid candidates cannot partially alter active topology.
4. Only explicitly configured, geometrically valid links permit cross-host transition.
5. The destination cannot acquire authority from an acknowledgement alone. The source becomes
   operationally inert before queueing the exact commit, publishes remote authority only after the
   commit is queued, and the destination publishes local authority only after receiving it.
6. A stale epoch, generation, transition ID, sequence, or inventory revision cannot change state.
7. Duplicate messages are either exact and idempotent or conflicting and rejected.
8. Failure, timeout, degradation, disconnect, revocation, or reconfiguration restores local
   authority before replacement.
9. Every inventory, map, link set, pending transition, counter, duration, coordinate, and outbound
   effect is positively bounded.
10. Peer-controlled display metadata, stable IDs, pointer coordinates, credentials, and input
    payloads remain absent from normal diagnostics.
11. No native input is captured, suppressed, routed, or injected by this milestone.

## Automated acceptance

Inventory tests must cover nil/wrong owners, duplicate IDs, invalid/control names, malformed and
oversized geometry, no/multiple primaries, atomic replacement, stale/equal/gapped revisions,
identity/generation changes, capacity, deterministic order, and redaction.

Workspace tests must cover global ID collision, missing inventory, duplicate/dangling/conflicting
links, gaps, partial overlap, mixed DPI/resolution, negative placement, finite/extent bounds,
normalized seam endpoints, atomic failed recompile, epoch exhaustion, owner lookup, and redaction.

Handoff tests must drive two simulated hosts through accepted round trips, both directions, exact
duplicate delivery, simultaneous proposals, rejection outcomes, wrong host/display/epoch,
generation replay, lost acknowledgement, destination preparation timeout, delayed/conflicting
commit, commit queue failure and ordering, disconnect, degradation, reconfiguration, outbound
saturation, sequence/transition exhaustion, and cleanup/local-authority restoration. Manager-level
tests must additionally prove mandatory control-plane attachment, fresh-inventory recompilation,
runtime layout replacement, local snapshot publication, timeout polling, exact-session teardown,
task-slot recovery, and callback-visible suppression during commit dispatch.

The repository must pass:

```text
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff --check
```

All changed platform-neutral crates must also pass Windows GNU check and strict Clippy. Physical
display enumeration and real pointer-boundary behavior remain Windows/macOS hardware validation
gates and are not inferred from simulated tests.

## Explicitly deferred

- native display enumeration wiring and hotplug callbacks;
- physical cursor observation/warping, capture, selective suppression, and injection;
- certificate issuance/rotation and pairing UI;
- semantic gestures, acceleration matching, absolute pointing devices, and precision touch;
- automatic layout inference and control-panel layout editing;
- scoped IPv6 link-local discovery, WAN, relay, or cloud connectivity;
- clipboard watchers, daemon IPC, startup agents, and the control panel.
