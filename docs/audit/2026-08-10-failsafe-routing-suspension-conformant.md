# Audit: §24 Failsafe routing-suspension — enforced on all egress CONFORMANT

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 43
**Spec ref:** `.spec/implementation.md` §24 (Emergency Failsafe)
**Severity:** N/A — conformance confirmation of a safety-critical invariant.

## The question

§24 requires that, once the failsafe fires, input routing is suspended for a
configured window (`routing_suspend_seconds`). Cycle 27 confirmed
`activate_failsafe` sets `suspended_until_ns` and that *a* routing gate checks
it. But cycle 38's lesson is that "assumed-solid" areas can hide a second,
ungated path. This audit asked: **is the suspension enforced on every routing
egress point**, or is there a remote-routing path that bypasses it (forwarding
input to a peer while the user believes routing is killed)?

## Findings — single consolidated gate, no bypass

`DaemonCore::routing_should_be_active` (`core.rs:2178`) is the one predicate:

```rust
fn routing_should_be_active(&self, now_ns: u64) -> bool {
    self.is_enabled()
        && now_ns >= self.suspended_until_ns      // ← §24 suspension
        && !self.drain_failsafe_keys
        && self.workspace_ready
        && (!self.cleanup_pending() || self.pending_route_policy.is_some())
        && self.pending_remote.is_none()
}
```

Every **remote** routing egress in `prepare_captured` funnels through one gate,
`remote_target_endpoint` (`core.rs:2068`):

```rust
fn remote_target_endpoint(&self, target, route, now_ns) -> Option<SessionEndpoint> {
    let availability = self.endpoint_availability.get(&target)?;
    (self.routing_should_be_active(now_ns) && … && availability.state.accepts_input())
        .then_some(availability.endpoint)
}
```

`prepare_captured` has exactly two remote egress points, and both are gated by it:

| Path | Site | Gate | Behavior while suspended |
|------|------|------|--------------------------|
| Latched remote | `core.rs:894` `remote_endpoint_available` → delegates to `remote_target_endpoint` (`:2087`) | `routing_should_be_active` | `false` → `gated_suppressed` + `fail_closed` (`:895-899`); **not forwarded** |
| Non-latched remote | `core.rs:942` `remote_target_endpoint` | `routing_should_be_active` | `None` → `Local(Gated)` (`:943-946`); **not forwarded** |

While `now_ns < suspended_until_ns`, `routing_should_be_active` is `false`, so
`remote_target_endpoint` returns `None`, so neither path can produce a
`Remote` effect. A captured event is forced to `Local`/`Gated`/`Inert` — it can
never reach a peer during the suspension window. There is no third remote path.

## Why this is structurally safe

The suspension check is not sprinkled across multiple decision sites (the
pattern that invites a missed path); it lives in one predicate consulted by one
endpoint resolver, which is the sole way a remote effect is prepared. Adding a
new remote-routing path in future would have to go through `remote_target_endpoint`
to obtain an endpoint, so it inherits the gate by construction.

## Relationship to the cycle-38 fix

This audit complements cycle 38: cycle 38 ensured the chord *releases held
state*; this cycle confirms the chord *blocks new forwarding*. Together they
cover both halves of §24's "user regains safe local control" guarantee — no
stuck modifiers, and no further input leaked to the peer during the suspension.

## Web verification

"Kill switch" / emergency-stop designs in safety engineering mandate that the
stop be enforced at a single chokepoint on the actuator path, not at multiple
independent decision sites — precisely so that adding a new actuator path cannot
accidentally bypass the stop. The consolidated `routing_should_be_active` →
`remote_target_endpoint` design matches that principle.

## Non-goals

Did not modify code (AUDIT, conformance confirmed). Did not re-audit chord
detection or `activate_failsafe`'s action set (cycle 27) or the inbound release
(cycle 38). Scoped strictly to "is the routing suspension enforced on every
remote egress point."
