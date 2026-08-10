# Audit: §9 Workspace State — CONFORMANT

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 33
**Spec ref:** `.spec/implementation.md` §9 (Workspace State)
**Severity:** N/A — conformance confirmation.

## What the spec requires

```rust
pub struct WorkspaceState {
    pub local_host: HostId,
    pub active_host: HostId,
    pub active_display: DisplayId,
    pub pointer: LogicalPointer,
}
pub struct LogicalPointer { pub display_id: DisplayId, pub x: f64, pub y: f64 }
```

Plus the invariant: the pointer is a **logical workspace pointer**, not tied to
the physical device that last moved it.

## Implementation evidence (`kvm-types/src/workspace.rs`)

- `WorkspaceState` (`:40`) has exactly the four spec fields (`local_host`,
  `active_host`, `active_display`, `pointer`). `LogicalPointer` (`:9`) has
  exactly `display_id` / `x` / `y`. ✅
- **"Not tied to the physical device" is structurally enforced.** `LogicalPointer`
  is documented as "the single logical pointer shared by all
  follow-active-host devices" (`:7`) and carries **no device field** — only a
  display id and coordinates. There is one workspace pointer that every
  `FollowActiveHost` device shares; no per-device cursor state exists. The
  invariant cannot be violated because the type cannot express a device binding. ✅
- **Atomic transitions.** `set_active_pointer(active_host, pointer)` (`:65`)
  updates `active_host`, `active_display`, and `pointer` together, so a reader
  never observes a torn state (e.g. active_host on one display while the pointer
  is on another).
- **`active_display` stays consistent with `pointer.display_id`.** `new` derives
  `active_display` from `pointer.display_id` (`:59`), and `set_active_pointer`
  keeps them in lockstep (`:67`). `active_display` is therefore never an
  independent source of truth that could drift — verified by
  `changing_pointer_keeps_active_display_consistent`. ✅
- **Secrets redacted.** Both `LogicalPointer` and `WorkspaceState` implement
  `Debug` as `[REDACTED]` (`:17`, `:49`), so coordinates and stable host/display
  identities are not leaked through logs.

## Web verification

Software KVMs (Synergy/Barrier, Microsoft PowerToys Mouse Without Borders) all
model a single logical cursor that moves seamlessly across computers and is not
tied to a specific physical mouse — exactly this `LogicalPointer` design.

## Non-goals

Did not modify code. §9 is conformant. How `active_host`/`pointer` change
(authority transfer via §12 pointer handoff) was audited as conformant in
earlier cycles; this cycle scoped itself to the workspace state shape and the
device-agnosticism invariant.
