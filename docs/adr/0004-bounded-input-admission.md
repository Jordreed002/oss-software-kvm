# Bounded input admission and route generations

Status: implementation direction, 2026-11-17. This defines the next replacement
Rust increment. It does not enable capture or sharing in the agent.

## Boundary

Add a new `kvm-input-engine` crate with one synchronous owner and no I/O,
threads, timers, synchronization, unsafe code or heap allocation. Its only
dependency is the replacement foundation. Use its fixed-capacity FIFO and input
values. Do not import the legacy router, runtime or platform orchestration.

The initial engine is bounded input admission, not a complete routing or native
suppression implementation. Authentication, native resource preparation, display
handoff, encryption, held-input delivery and teardown fences remain outside it.
Only the agent session owner may activate it after those prerequisites commit.
A successful enqueue does not prove peer delivery or authorize suppression by
itself. The native adapter must also hold current committed route authority.

## Identity and transitions

The owner supplies a nonzero process instance and nonzero peer identity. Each
activation allocates a checked, increasing nonzero generation. The resulting
route epoch binds process instance, generation and peer. Counter exhaustion must
leave state unchanged. A replacement process requires a fresh instance identity.

Start local with an empty queue. Activation requires local state and an empty
queue. Closing revokes admission immediately. Existing queued input may then be
discarded explicitly, one bounded operation at a time, before another activation.
The engine never forwards queued input after close or fault. The session owner
must separately fence work already removed from the queue and reconcile remote
held input; clearing a queue is not cleanup confirmation.

Both admission and consumption require the exact active epoch. A stale epoch
cannot enqueue, consume another generation's input or fault its active route.
Rejecting a stale epoch leaves all state unchanged. Epochs carry identity, not
cryptographic authentication or installed application identity.

## Bounds and overload

The owner configures a nonzero maximum event age in host-local nanoseconds.
Capture timestamps and the supplied current time must come from the same local
monotonic clock. This contract makes no cross-host time comparison. Reject future
timestamps, excessive age and non-finite motion/scroll values at admission.
Check age again before consuming the oldest event.

All event families share one ordered FIFO in this first increment. No coalescing,
priority reordering, fixed sleep or catch-up burst is introduced. On full queue,
invalid current-generation input or stale queued input, latch a fault and close
admission. Preserve existing entries for explicit discard. There is no unlatch
operation in this increment. The owner must execute its independent failsafe and
held-input reconciliation; it must not claim the rejected event was forwarded.

Native callbacks may suppress only after successful bounded admission while
their committed generation remains current. Failed admission passes through
locally and triggers the owner's safety path. This synchronous model does not
implement that native callback or solve cross-thread publication. Select a native
worker/queue synchronization design only with correctness and measurement evidence.

## Acceptance evidence

Tests must distinguish FIFO order, wraparound, zero capacity, full-queue failure
without overwriting an already queued release, generation changes, stale producer
and consumer epochs, instance mismatch, counter exhaustion, close/discard/open,
NaN/infinity, future timestamps, the age boundary and expiry while queued.
Snapshot/debug output must not expose input content or peer identifiers.

Run actual workspace formatting, focused tests and strict all-target clippy.
GLM implementation requires Opus review before acceptance. Later allocation and
optimized benchmarks must state their scope; these software checks alone do not
establish physical latency, smoothness, release delivery or installed safety.
