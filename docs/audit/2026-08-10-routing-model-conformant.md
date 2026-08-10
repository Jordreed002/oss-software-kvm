# Audit: §8 Routing Model — CONFORMANT (core input-routing correctness)

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 31
**Spec ref:** `.spec/implementation.md` §8 (Routing Model)
**Severity:** N/A — conformance confirmation. Routing is the heart of the KVM;
this cycle verifies the per-device routing decision and active-host authority
resolution are correct and defensively coded.

## What the spec requires

- `DeviceRoute { FollowActiveHost, Local, Host(HostId) }`.
- `RoutingTable { routes: HashMap<DeviceId, DeviceRoute> }`; **default route for
  supported keyboard/mouse/trackpad devices is `FollowActiveHost`**.
- `Destination { Local, Remote(HostId) }`.
- `InputRouter::destination(&event, &state) -> Destination`.

## Implementation evidence (`kvm-router/src/lib.rs`)

### All variants + trait present

- `Destination { Local, Remote(HostId) }` (`:55`).
- `InputRouter::destination(&self, event, state)` trait (`:64`); implemented for
  `RoutingTable` by delegating to `destination_for_device(event.source_device,
  state)` (`:304-308`) — exactly the spec API.
- All three `DeviceRoute` variants are exercised in the resolution
  (`FollowActiveHost` `:282`, `Local` `:281`, `Host(host)` `:283`).

### Default route = FollowActiveHost (including for missing devices)

`route_for(device)` (`:239`) returns `routes.get(device).unwrap_or(
DeviceRoute::FollowActiveHost)`. So an unmapped device — including one not yet
seen — behaves as `FollowActiveHost`. This matches §8's stated default and the
documented design note (`:69`): "missing devices deliberately behave as
`FollowActiveHost`" so a newly attached keyboard/mouse routes correctly without
an explicit configuration step.

### Correct authority resolution (`destination_for_device`, `:272`)

```text
Local                 → Destination::Local
FollowActiveHost      → active_host
Host(host)            → host
then: target == local_host → Local, else Remote(target)
```

This is exactly right:

- `FollowActiveHost` follows whoever currently holds authority (`active_host`),
  which is transferred by the §12 pointer handoff — when the local host is
  active, input stays `Local`; when a remote is active, input goes `Remote`.
- `Host(x)` pins a device to a specific host, folding back to `Local` when `x`
  is the local host (no needless network round-trip for a locally-pinned device).
- `Local` short-circuits to `Local`.

### Defensive hardening (beyond the spec, but load-bearing)

- **Fail-closed nil guard** (`:277-279`): if `active_host` or `local_host` is the
  nil id (`[0;16]`), return `Local` — never `Remote(nil)`, so a malformed
  workspace snapshot can never address a phantom endpoint. The authority layer
  above separately gates unknown endpoints; this is the router's own nil guard.
- **Insertion validation** (`validate_entry`, `:294`): rejects a nil device id
  (`InvalidDevice`) and a nil `Host(...)` target (`InvalidTarget`) at `set_route`
  time, so the table cannot be populated with unrouteable entries.

## Web verification (current best practice)

Barrier/Synergy — the reference open-source software KVMs — use a server/client
model where the shared keyboard/mouse follow the "active screen" (the screen the
pointer currently resides on). This codebase's `FollowActiveHost` is the
spec-clean generalization: the active host is whichever holds authority after a
§12 pointer transition, and routing follows it. Per-device pinning (`Host(x)`)
and force-local (`Local`) are standard refinements (Synergy/Barrier expose
per-screen options of the same shape).

## Non-goals

Did not modify code. §8 is conformant. The *authority transfer itself* (how
`active_host` changes) is governed by §12 pointer handoff and §11 topology
(audited as conformant in earlier cycles); this cycle scoped itself to the
routing decision given an authoritative `active_host`.
