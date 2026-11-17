# Display layout and explicit edge handoff

Status: replacement implementation direction, 2026-11-17. This component does
not start capture, establish peer trust or authorize input suppression.

## Geometry contract

Implement a fresh dependency-free `kvm-layout` crate. No legacy crate imports
or copied implementation. Use fixed-capacity inline storage, no unsafe code,
heap allocation, synchronization or I/O. Non-test code uses no_std.

Host IDs are nonzero u128 values, retaining a full UUID without truncation.
Display IDs are nonzero u64 values scoped to a host. A point is finite f64 x/y.
Display rectangles use host-local physical desktop coordinates, including
negative origins. Width/height and both computed extents must be finite and
strictly positive/increasing. A rectangle is half-open on right and bottom.
Do not infer DPI, normalize one host against another or compare host clocks.

Each display belongs to a host. Reject duplicate host/display keys and positive
area overlap between displays on the same host; touching edges are valid.
Mirrored/overlapping display spaces are unsupported in this increment. Capacity
zero and exhausted capacity return explicit errors without state changes.

## Committed links

Links explicitly connect one complete display edge to an opposite edge on a
different host. Left maps to Right, Right to Left, Top to Bottom, Bottom to Top.
Reject missing endpoints, same-host links, mismatched orientation and duplicate
source-edge links. Do not manufacture reciprocal links; each direction is an
explicit independent configuration entry. No nearest-monitor guessing.

A builder validates a draft and produces immutable layout state. Failed draft
operations leave the draft unchanged. Store per-display four-edge adjacency so
runtime crossing does not allocate or rebuild topology. Expose no mutable access
that could bypass geometry validation. This first version supports full-edge
links only; partial seams and installed display-inventory synchronization remain
later work, not silently approximated features.

## Crossing and mapping

The caller supplies the current display key, a start point inside that display,
and a finite end point in the same host's coordinates. Find the first rectangle
exit of the segment. An unlinked first exit yields no handoff, even if a later
segment intersection would meet a linked edge. A fixed documented edge order
resolves exact corner ties. Movement staying inside or of zero length produces
no handoff. Reject invalid starts and non-finite derived arithmetic explicitly.

For a linked exit, map the tangent fraction along the source edge onto the
destination edge. Return a point inside the destination's half-open rectangle,
clamping the maximum tangent coordinate and Right/Bottom entry coordinates to
the next representable interior value. Require representable finite extents;
do not invent arbitrary epsilon offsets or apply the remaining movement as a
catch-up burst. Return destination identity and crossed edges, not native calls.

## Acceptance

Meaningful tests cover each direction, unequal display sizes, negative origins,
multiple displays per host, reciprocal independence, no link, zero movement,
inside movement, invalid start, exact corner tie, an unlinked first exit,
fraction endpoints, NaN/infinity and derived overflow, duplicate/overlap errors,
zero/full capacities and unchanged state on rejected draft edits. Every returned
handoff point must satisfy destination containment. Review numerical edge cases
and test coverage independently before acceptance.

Run workspace formatting, focused tests and strict host/Apple cross-clippy.
GLM implementation requires coordinator-owned Opus review. No native input,
physical smoothness, mixed-DPI adapter behavior or performance budget is certified
by pure geometry tests. Native placement and physical validation remain separate.
