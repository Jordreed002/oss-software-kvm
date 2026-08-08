# Milestone 08 — Authenticated Device Inventory and Transactional Per-Device Routing

## Status

Completed on 2026-08-08 after independent inventory, routing-transaction, composition, and
security audits found no remaining blocker or high-severity issue. The full Linux workspace
format, test, and strict Clippy gates pass, as do Windows GNU workspace check and strict Clippy.

The completed slice remains deliberately platform-neutral and limited to the local host plus the
immutable selected peer. Native device enumeration/hotplug and arbitrary multi-peer routing remain
deferred to later milestones.

## Objective

Complete the platform-neutral portion of Product Phase 7 and Implementation Task 25 by making
per-device routing a safe, observable, durable runtime feature for the initial two-host product:

```text
FollowActiveHost -> follow the M06/M07 committed pointer authority
Local            -> remain on the device's physical host
Host(local)      -> remain local
Host(selected)   -> route through the exact admitted selected-peer session
```

The daemon must maintain bounded authenticated device inventories and apply route changes without
splitting held controls, publishing partial policy, losing cleanup ownership, or reusing stale
connection capabilities.

## Scope decision

The initial product specification describes two connected systems. M08 therefore retains the
immutable selected pointer peer as the only remote routing target and continues to reject an
explicit third-host target.

Arbitrary multi-peer dispatch is deliberately M09 work. It requires one global outbound routing
ledger, exact-generation cleanup across several independent FIFOs, aggregate bounds, and a defined
cross-peer release barrier. Combining that refactor with the first inventory and persistence
transaction would make partial multi-FIFO failure the first implementation of runtime routing.

All new domain and policy values remain host-generic, and cleanup/effect identities must include
the exact peer generation so the two-host foundation can be lifted safely later.

## Non-overlap boundary

M08 must not modify:

- `crates/kvm-windows/**`;
- `crates/kvm-macos/**`;
- `crates/kvm-diagnostics/**`;
- `docs/validation/**`;
- native enumeration, hotplug, capture, suppression, injection, display, or clipboard code;
- Tauri, local IPC, or control-panel code.

Expected paths are `kvm-types`, `kvm-protocol`, `kvm-router`, `kvm-config`, platform-neutral
`kvm-daemon`, root documentation, this specification, and `Cargo.lock` only when required.

## Workstream A — Bounded authenticated device inventory

Add a platform-neutral inventory state machine for local and authenticated remote devices.

- represent one current local inventory and bounded remote inventories;
- bind every remote inventory to the exact admitted host, peer, and connection generation;
- revalidate `DeviceSnapshotV1`, `DeviceAddedV1`, and `DeviceRemovedV1` at the daemon boundary;
- reject nil host/device IDs, wrong ownership, duplicate IDs, empty/control-character/oversized
  names, invalid revisions, and maximum-plus-one inventory size;
- require a nonzero initial snapshot revision;
- accept only a strictly newer full snapshot; allow a snapshot revision jump because it is a full
  replacement;
- require deltas to use the exact next revision, add only a new ID, and remove only an existing ID;
- make failed snapshot/delta application atomic and deterministic;
- require a fresh snapshot after a delta gap;
- clear remote inventory authority on degradation, disconnect, revocation, task loss, or shutdown;
- prevent a retained old-generation snapshot or delta from repopulating a replacement session;
- publish the bounded full local snapshot after admission and after each committed local revision;
- keep inventories ordered deterministically for tests/presentation and diagnostics coarse.

Remote inventory is observational metadata. It never authorizes capture, input injection, pairing,
or creation of a local-device route.

## Workstream B — Device ownership and durable policy

- only a device in the current validated local inventory may receive a new runtime route;
- a remote-owned device ID can be displayed but cannot be configured by this daemon;
- an unknown device still routes with the safe default `FollowActiveHost`, but cannot receive a new
  explicit policy until locally inventoried;
- a durable route for a temporarily absent local device remains dormant across unplug/replug;
- removal never silently deletes durable user policy;
- a reappearing stable local device activates its dormant policy only after a validated local
  inventory revision reports the same ID;
- local device removal while controls are held remotely gates that device and enters the same
  retryable release/quarantine path as a route change;
- explicit host targets are limited to the immutable local host or selected peer in M08;
- config loading may retain a dormant historical route before native inventory is available, but
  runtime creation and mutation must enforce current local ownership;
- route and inventory metadata remain absent from ordinary Debug, errors, and tracing.

Physical stable-ID correctness and native unplug/replug delivery remain hardware-validation work.

## Workstream C — Revisioned transactional route management

Add one manager-owned, headless route-management authority. The public API may use different names,
but must support:

- querying the checked current policy revision and a deterministic redacted summary;
- replacing the complete bounded route set with an expected revision;
- setting one local device route with an expected revision;
- clearing one explicit route with an expected revision;
- retrying or aborting the one staged transaction when safe.

Only one transaction may be staged. A route transaction follows this order:

1. validate the expected revision, local ownership, target, capacity, and complete candidate;
2. allocate a checked affine transaction/effect identity without mutating published policy;
3. gate captures affected by the candidate;
4. preserve a held lifecycle only when its effective destination and exact admitted generation are
   unchanged;
5. otherwise enqueue releases to the old exact session and quarantine still-physical controls;
6. retain any unsent cleanup suffix after queue full/closed, sequence exhaustion, or task failure;
7. durably save the complete candidate through the config-store boundary;
8. publish the candidate and incremented policy revision atomically through an infallible commit;
9. reopen eligible routing only after the transaction has settled.

Stale revisions and a second concurrent candidate are rejected without mutation. Persistence
failure leaves the old policy published and the candidate retryable while affected routing remains
gated. A crash after durable save but before in-memory publication is recovered by loading the
saved candidate after transport-held state has ended.

The persisted configuration must carry enough revision information for deterministic restart and
stale-client rejection. Counter exhaustion is a coarse fail-closed error, never saturation or
reuse.

## Workstream D — Exact-session daemon composition

- `PeerManager` is the sole public inventory and route-management entry point;
- serialize inventory, policy, capture, pointer, lifecycle, and persistence transitions through
  its mutable authority;
- route device messages through the opaque generation-bound peer event path;
- while handling the real admitted event, bind inventory publication and outbound dispatch to the
  exact current generation;
- do not expose a cloneable `PeerSender` as independent routing authority;
- recheck selected peer, current admission, task slot, generation, policy revision, and workspace
  readiness immediately before every remote enqueue;
- keep per-peer coordinators responsible for exact FIFO sequencing and inbound injection;
- never key cleanup or terminal invalidation by `HostId` alone where a replacement generation can
  exist;
- logical degradation or a closed enqueue is not proof that transport invalidation occurred;
- block generation replacement while old cleanup remains retryable;
- preserve ReleaseInput, pointer Ack/Commit, inventory, and subsequent Input order on the existing
  priority FIFO;
- device messages from pre-admission, stale, wrong-host, revoked, or replacement sessions fail
  closed and cannot alter inventory or policy;
- local inventory broadcasts are best effort per active exact session, but send failure follows the
  same session-fatal reconciliation rules rather than silently retaining stale remote metadata.

The selected two-host execution engine may remain internally attached to its selected supervisor,
but manager-owned policy and transaction state must have only one authoritative copy and no public
bypass path.

## Safety invariants

1. Remote device metadata is accepted only from the exact currently admitted owner generation.
2. Only current validated local devices can receive a new runtime route.
3. Unknown devices remain `FollowActiveHost`; absent known devices retain dormant policy.
4. Published route policy and its checked revision change atomically.
5. A route transaction never splits a held key/button lifecycle across destinations or generations.
6. Cleanup remains bounded and owned until FIFO acceptance or exact transport invalidation.
7. Persistence never exposes a candidate that runtime can later reject after durable save.
8. Stale generation, stale revision, stale inventory, and stale terminal events are no-ops.
9. One selected peer remains the only remote M08 target; third-host routes fail safely local/gated.
10. Inventory entries, routes, transactions, held controls, queues, files, strings, and counters are
    positively bounded.
11. Device metadata, input payloads, stable IDs, routes, revisions, generations, and credentials
    stay out of normal Debug, errors, and tracing.
12. No native input or device callback is enabled by this milestone.

## Automated acceptance

Required deterministic tests include:

- full local/remote snapshots reject wrong/nil owner, duplicate/nil device, invalid names,
  stale/equal revision, and maximum plus one without partial mutation;
- exact-next add/remove deltas succeed; gaps, duplicate add, missing remove, and overflow require a
  new snapshot and preserve the old snapshot;
- an old admitted generation cannot apply inventory after disconnect/replacement;
- local snapshot publication occurs after admission and every committed local revision;
- new explicit routes reject unknown, remote-owned, unpaired, and third-host targets;
- `Local`, `FollowActiveHost`, and selected `Host` each route through the expected M07 path;
- an absent known device retains a dormant route and safely reactivates after validated reappearance;
- current expected revision commits; stale revision and concurrent candidate are no-ops;
- remote-to-local and Follow/Host changes release on the old FIFO before policy publication and
  quarantine a still-held control until physical release;
- same target plus same exact generation may preserve a held lifecycle; same host plus replacement
  generation may not;
- local device removal while held uses the same release barrier and does not erase policy;
- first/middle/last cleanup queue failure retains only the exact unsent suffix, never resending a
  confirmed prefix;
- persistence failure retains the old published revision, staged candidate, routing gate, and
  retryability; simulated restart loads a durably saved candidate coherently;
- degradation, revoke, shutdown, task loss, and actual terminal loss settle only the exact
  generation and block or release replacement correctly;
- pointer handoff, route mutation, inventory mutation, and selected capture cannot interleave past
  their barriers;
- route/inventory/effect/counter exhaustion and maximum-plus-one bounds are transactional;
- marker-based diagnostics prove names, IDs, routes, input, revision, generation, and backend text
  are absent.

## Quality gates

```text
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff --check
```

Every changed platform-neutral crate must also pass Windows GNU check and strict Clippy. Independent
inventory, transaction, and lifecycle/security audits must report no remaining blocker or
high-severity finding before completion.

## Explicitly deferred

- arbitrary third-peer routing and multi-FIFO atomic settlement;
- any release-applied acknowledgment needed for stronger cross-peer ordering;
- native enumeration/hotplug/capture/suppression/injection and physical stable-ID validation;
- Logitech high-resolution scroll, advanced buttons, and trackpad gesture work;
- device renaming/fingerprinting heuristics and automatic route deletion;
- Tauri UI and local IPC (M08 provides the headless contract they will later call);
- clipboard, startup/service installation, and native performance validation.
