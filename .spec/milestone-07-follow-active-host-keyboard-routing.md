# Milestone 07 — Authenticated Follow-Active-Host Keyboard Routing

## Status

Completed on 2026-08-08 after independent routing, composition, and specification audits found no
remaining blocker or high-severity issue. The full Linux workspace format, test, and strict Clippy
gates pass; every changed platform-neutral crate also passes Windows GNU check and strict Clippy.

The implemented slice remains platform-neutral: it deliberately does not wire native capture or
suppression. Native adapters must preserve `KeyState::Repeated` as a key-down/repeat operation when
that deferred integration begins.

## Objective

Make the active host committed by the Milestone 06 pointer protocol control keyboard routing:

```text
active host is local  -> physical keyboard input remains local
active host is remote -> physical keyboard input is queued to that exact admitted peer
```

The result must work identically for simulated keyboards attached to either host, without manual
switching, duplicate input, split key lifecycles, stuck modifiers, forwarding loops, or stale
session reuse.

## Non-overlap boundary

This milestone must not modify:

- `crates/kvm-windows/**`;
- `crates/kvm-macos/**`;
- `crates/kvm-diagnostics/**`;
- `docs/validation/**`;
- native capture, suppression, injection, startup, display enumeration, or clipboard watchers.

Expected implementation paths are `kvm-router`, `kvm-config`, platform-neutral `kvm-daemon`, root
documentation, this specification, and `Cargo.lock` only if dependency resolution requires it.

## Scope decision

Milestone 07 owns the default `FollowActiveHost` policy and preserves the existing explicit
`Local` and exact selected-peer `Host` policies. Arbitrary multi-peer device routing and runtime
per-device policy editing remain the next product phase. A selected coordinator must reject a
configured host target it cannot dispatch to through its exact admitted session.

The only authoritative capture API in this milestone is a synchronous mutable operation on the
selected `PeerManager`. A read-only `RoutingSnapshotHandle` may remain useful for observation, but
must not independently decide suppression or enqueue work. Native callback concurrency and its
future bounded reservation/drain bridge are explicitly deferred; no buffered captured event may
be accepted by the M07 API after an authority transition and retagged into a newer generation.

## Workstream A — Bounded routing policy and readiness

- preserve `FollowActiveHost` as the default for unknown physical devices;
- positively bound configured routes and runtime routing-table entries;
- reject nil device IDs, duplicate device entries, and `Host` targets outside the paired set;
- in the selected M07 composition, permit explicit `Host` only for the local host or immutable
  selected peer;
- bound configuration file input before parsing so hostile or corrupted files cannot force an
  unbounded allocation;
- add an explicit workspace-routing readiness gate to the selected daemon core/snapshot;
- initialize the selected composition local and not ready; a caller-supplied remote initial
  authority must be rejected;
- set readiness only after fresh exact selected-peer inventory compiles, the pointer session is
  healthy, and the resulting workspace is published;
- clear readiness before activation/recompile, degradation, retirement, revocation, shutdown, or
  any failed route/authority transition;
- keep diagnostics count-only/coarse and redact device, host, route, and input payload data.

## Workstream B — Stateful key routing and retryable cleanup

Route state-bearing controls as complete physical lifecycles rather than independent events.

- latch a key/button destination on its first press;
- send repeats and the physical release to that same destination even if active host changes;
- keep local presses local through release;
- on a remote-to-local or remote-to-different-target transition, queue a release to the old target
  before publishing the new route;
- after a synthetic remote release, quarantine the still-physically-held control: suppress repeats
  and its final release without synthesizing a press on the new host;
- preserve an explicit pinned route whose effective exact destination/session does not change;
- pointer handoff gates only `FollowActiveHost` controls; explicit `Local` stays local and an exact
  healthy selected-peer pin may continue on its unchanged FIFO;
- track physical emergency keys per device with bounded aggregate counts, so releasing a modifier
  on keyboard B cannot clear the same modifier still held on keyboard A;
- define the emergency chord as the aggregate of trusted physical local keyboards; injected,
  unknown, wrong-host, or non-finite records never contribute;
- positively bound held devices, controls per device, total controls, cleanup entries, and checked
  sequence/counter space;
- motion, scroll, and unmatched releases must not allocate held-state entries;
- capacity exhaustion gates remote routing and fails safely local without partial mutation.

Remote held state must be committed only after its Input frame enters the exact session FIFO.
Cleanup must remain owned and retryable until each release enters that FIFO or transport
invalidation is confirmed. A partial cleanup failure must not discard the unsent suffix or allow a
replacement generation to receive retagged work.

## Workstream C — Mandatory selected capture composition

Add one synchronous platform-neutral chain, with names chosen to fit the implementation:

```text
PeerManager selected capture entry
  -> exact selected PeerSessionSupervisor
  -> exact current PeerSessionCoordinator
  -> DaemonCore decision
  -> existing authenticated Input FIFO
```

Required behavior:

- serialize capture decisions with pointer/config/lifecycle transitions through `&mut PeerManager`;
- accept only trusted physical, finite input from the immutable local host and non-nil device;
- allow local decisions without a network hop;
- require ready workspace, healthy exact current generation, and matching selected destination
  before a remote decision;
- enqueue conversion/sequence/frame work before returning `SuppressLocal`;
- commit held state only after queue success;
- return a compact redacted outcome containing disposition, failsafe activation, and coarse state;
- any conversion, sequence, queue, identity, or destination failure returns an explicit safe
  disposition, gates routing, retires/reconciles the exact session, and settles the manager task
  only after cleanup completes; an uncommitted first event falls back local, while a repeat/release
  from an already-suppressed remote lifecycle remains suppressed and quarantined until physical
  release;
- stale generation-A decisions cannot suppress or dispatch into generation B for the same host;
- expose a selected lifecycle tick so failsafe suspension expiry and pointer deadlines are driven
  through the same mandatory manager composition;
- keep release, Commit, and subsequent Input ordering in the shared FIFO.

The emergency chord is evaluated synchronously before suppression. Its triggering records are
always local and never become outbound Input, including while handoff is pending or the outbound
queue is full.

## Workstream D — Affine route and authority transitions

Configuration changes, workspace changes, failsafe, disable, degradation, revocation, and shutdown
must use the same fail-closed transition discipline:

1. prevent new affected remote decisions;
2. finish any earlier synchronous decision;
3. generate bounded releases for affected remote holds without discarding retry state;
4. queue releases in order;
5. publish the new authority/config only after the release barrier succeeds;
6. on failure, retain cleanup ownership, keep routing gated, and block replacement until retry or
   confirmed transport invalidation.

For the M06 pointer commit path the required order is:

```text
earlier Input -> affected ReleaseInput -> handoff gate -> PointerTransitionCommit -> later Input
```

An unchanged explicit pinned route may retain its held state only when its exact destination and
admitted generation remain identical. Global failsafe, disable, revoke, and shutdown always clean
up every remote hold.

## Safety invariants

1. Pointer-committed `WorkspaceState.active_host` is the only authority for `FollowActiveHost`.
2. Suppression is reported only after the exact remote frame has been accepted by the FIFO.
3. One key/button lifecycle never splits across destinations or generations.
4. Old decisions, snapshots, sessions, workspace epochs, or config revisions cannot retag input.
5. Cleanup state remains bounded and retryable until queued or transport invalidation is certain.
6. Authority/config publication never overtakes affected releases.
7. The emergency chord is trusted-physical-only, synchronous, local, and device-correct.
8. Local and unchanged exact pinned routes are not silently overridden by pointer focus.
9. Every route, held control, cleanup item, counter, duration, file, and queue is positively bounded.
10. Input payloads, device metadata, stable IDs, routes, credentials, and generations stay out of
    normal Debug, errors, and tracing.
11. No native event is captured, suppressed, injected, or routed by this milestone.

## Automated acceptance

Required deterministic tests include:

- both simulated hosts route both unknown/default keyboards to the committed active host;
- the first key after a complete pointer Commit follows the new host and remains behind Commit;
- local press/repeat/release remains local across a pointer transition;
- remote press is released before a destination change and quarantined until physical release;
- multiple keyboards retain independent modifier state and aggregate failsafe counts correctly;
- injected, unknown, wrong-host, nil-device, and non-finite events stay local and allocate nothing;
- no fresh selected inventory or degraded/stale session means no remote routing;
- ordinary handoff-pending FollowActiveHost input is inert, while explicit Local remains local and
  the emergency chord escapes synchronously;
- queue full/closed and sequence exhaustion on press, repeat, release, and middle cleanup return an
  explicit safe disposition, retain retry state, and block replacement when cleanup is incomplete;
  first presses not accepted by the FIFO remain local, while already-remote lifecycles never leak a
  repeat/release into the local OS;
- motion/scroll/unmatched release create no held entries; duplicate press at capacity is idempotent;
- maximum devices, per-device controls, total controls, routes, cleanup items, and config bytes plus
  one fail transactionally and safely;
- config/workspace/failsafe/disable/degrade/revoke/shutdown barriers order releases before later
  input and never admit stale generation work;
- explicit third-peer targets are rejected by the selected two-host composition;
- failsafe tick re-enables routing only after physical chord drain and timeout, with authority local;
- marker-based diagnostics prove keys, deltas, names, IDs, targets, and backend strings are absent.

## Quality gates

```text
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff --check
```

Every changed platform-neutral crate must also pass Windows GNU check and strict Clippy.

## Explicitly deferred

- native callback wiring and the future callback-to-actor reservation/drain bridge;
- arbitrary multi-peer device dispatch and runtime device-routing UI;
- native device unplug/replug callbacks and hardware stable-ID validation;
- native keyboard capture/suppression/injection and physical latency measurement;
- pointer acceleration, high-resolution scroll, advanced buttons/trackpads;
- clipboard watchers, daemon IPC, startup agents, and control panel UI.
