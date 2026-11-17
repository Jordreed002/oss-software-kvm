# Ground-up Rust rebuild and implementation boundaries

Status: accepted implementation direction, 2026-11-17. Implements the user-approved overhaul and performance priority. Detailed release budgets still require physical measurements.

## Ownership and first increment

Build the replacement alongside the legacy code, with one capture owner per desktop. The new Rust implementation starts in `crates/kvm-foundation`. This is fresh code, not a renamed legacy crate. Begin with dependency-free event values and a single-owner bounded queue; native capture and authenticated transport follow after contracts and tests exist. Do not activate new capture during development tooling or UI startup.

The initial queue is a fixed-capacity ring with inline storage, no unsafe code and no synchronization. Its owner serializes access; it is not a cross-thread queue. Full insertion returns the original item to the caller without overwriting queued input. Capacity zero must be well-defined without arithmetic panics. Queue policy belongs to the future session owner: ordered key/button events cannot be silently dropped; pointer coalescing must respect ordering barriers. Establish these mechanisms before adding routing authority.

Input values describe physical key transitions, pointer movement, pointer buttons and scrolling, with monotonic source timestamps and explicit device identity. They do not grant routing authority or imply successful capture/injection. Use compact owned values and validate nonfinite movement at external boundaries. A timestamp is local to its host and cannot establish cross-host latency by subtraction.

The native shell owns tray and windows; the new agent owns confirmed state, identity, pairing and runtime lifecycle. The frontend does not fabricate connection health. Initial UI work lives behind an explicit development entry and uses clearly labelled fixtures or an unavailable state until the new agent contract exists. Production legacy behavior remains available for comparisons.

## Work lanes and review

- GLM 5.3 implements bounded Rust foundation work against this contract. Opus reviews that work before it is accepted into a commit.
- Opus owns all UI implementation and visual decisions.
- Sol builds baseline tooling and maintains evidence-based implementation progress records.
- The coordinator integrates, fixes small review findings, runs relevant checks and commits bounded increments. Agents do not commit shared files or switch branches.

Reuse requires a register entry with source, contract, safety review, tests and measurements. No legacy implementation is implicitly approved. Phase-zero baseline tooling must distinguish unmeasured hardware metrics from software benchmark results. Neither codec benchmarks nor UI previews certify physical input latency or correctness.

## Performance and cutover

The foundation must demonstrate bounded storage and zero queue-owned steady-state allocations. Later end-to-end measurements cover both operating systems and both directions with encryption enabled. CPU, memory, wakeups, pointer jitter, event age and release latency are release gates alongside tail latency. Do not invent measurements when native hardware is unavailable.

Stop legacy capture before replacement capture starts. Keep legacy configuration and trust intact until migration and rollback tests pass. The first increments are groundwork, not a completed native utility or proof of cross-platform readiness.
