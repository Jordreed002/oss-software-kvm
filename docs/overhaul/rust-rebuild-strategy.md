# Rust rebuild and performance strategy

Status: scope updated to reflect the user's instructions on 2026-11-17. Planning only. This supersedes the original selective-backend-refactor recommendation. Both Windows 11 and macOS remain required platforms.

## Required outcome

Design and implement the Rust application from the ground up. New process ownership, module/crate boundaries, domain state, native platform adapters, capture/routing/injection path, transport/session coordination, security/enrollment, configuration, local API and desktop lifecycle are in scope. No existing crate is automatically retained. Reusing a validated part is permitted; carrying over the existing backend wholesale under new names does not meet the requirement.

Performance is a primary architectural constraint. Optimize for low and predictable input latency, smooth pointer motion, prompt keyboard/button delivery, bounded memory and efficient background operation. Throughput or a fast average must not conceal jitter, delayed release events or long latency tails. Safety and authentication remain mandatory; performance does not justify bypassing them.

Retain Rust and the two-process product design: a native tray/menu-bar shell and a per-user agent whose active input session is optional. React is presentation only. The new Rust architecture is designed against explicit contracts and measurements rather than inherited module structure.

## Architecture to design before implementation

Specify these boundaries and their owners in an architecture decision record:

- Domain input events and immutable identifiers, host/display geometry and state transitions.
- A single authoritative owner for each capture session, route/authority generation and held-input ledger.
- Windows and macOS native capture, suppression, injection, permissions and session lifecycle adapters.
- The bounded capture-to-routing-to-transport-to-injection path, with documented scheduling, batching, wakeup and backpressure policy at each boundary.
- Authenticated peer enrollment, identity storage, peer sessions, reconnection and revocation, using established cryptographic libraries and reviewed protocols.
- Agent control/configuration plane, versioned local API, committed topology and atomic persistence.
- Native tray shell, process supervision, update and shutdown, independent of renderer responsiveness.
- Observability that reports counters and timing without blocking the input path or exposing input content.

Crates follow actual dependency and ownership boundaries. Do not choose a crate count or introduce an actor/task per event source simply to make the tree look cleaner. Benchmark synchronous owner loops, native workers and async boundaries before fixing the concurrency model. A full runtime framework rewrite is not a reason to implement custom cryptography, TLS or operating-system APIs unnecessarily.

## Selective reuse rules

Maintain a reuse register with source path/revision, purpose, contract, dependencies, safety review, known issues, tests, benchmark results and a retain/adapt/replace decision. Candidates include key mapping tables, geometry algorithms, framing/parsing, native bindings and credential adapters. These are candidates, not blanket approvals.

Reuse safety invariants and behavioral scenarios even when the implementing code changes. Independently test assumptions embedded in old tests. Preserve licenses and attribution. Audit unsafe native boundaries and resource lifetimes on each platform. Reusing a table does not require importing its old orchestration or dependency graph.

The legacy implementation remains a reference build for differential tests, physical comparisons, migration and rollback. Implement the new backend alongside it in clearly separated targets/modules selected by an architecture decision. Do not run both capture engines on one user desktop. Do not delete legacy code before replacement parity and cutover acceptance.

## Hot-path requirements

- Capture callbacks do bounded work. No file/network I/O, blocking waits, unbounded lock contention, config parsing, logging formatting or UI work in callbacks.
- Design steady-state capture/routing processing to avoid per-event heap allocation after initialization. Instrument allocations and document any platform/crypto-layer exceptions and their measured cost.
- Prefer explicit ownership and preallocated bounded storage. Choose synchronization from measured contention and correctness needs; use lock-free structures only when evidence justifies their complexity.
- Bound queue occupancy and event age. Protect ordered key/button state transitions and releases from starvation. Coalesce replaceable pointer movement deliberately without crossing button/scroll ordering boundaries or inventing catch-up bursts.
- Select pacing and batching from real smoothness/tail-latency data, including both healthy and impaired networks. Avoid arbitrary fixed sleeps or aggressive busy polling. Measure wakeups, energy and latency together.
- Keep discovery, clipboard, pairing, settings, diagnostics and UI subscriptions outside the critical input scheduling path. Load-test their resource contention rather than assuming separate tasks provide isolation.
- Cache validated state where appropriate and use bounded snapshots for observers. Avoid repeated serialization and full inventory enumeration for hidden UI status.
- Apply timeouts, work limits and memory limits to untrusted traffic. Performance under malformed input and reconnect storms is part of the design.
- Preserve ordered teardown, generation rejection and held-input cleanup. A benchmark that skips encryption, authorization or cleanup is not a production-path result.

## Measurement and budgets

Phase zero records a reproducible legacy baseline and proposes explicit absolute targets plus allowable regression bounds. Set budgets before accepting the new architecture. The goal is better behavior than the legacy implementation where it misses those targets; simply matching it is insufficient. Precise numbers depend on named reference machines and measurement noise, not unsupported claims in the plan.

Measure separately:

- Physical capture-to-injection end-to-end latency, with p50/p95/p99 and p99.9 only when sample counts support it. Record stage timing within each host and external measurement or validated clock alignment across hosts.
- Pointer inter-injection gaps, jitter, movement fidelity, dropped/coalesced samples, queue age, release latency and behavior at display boundaries.
- Event throughput and sustained handling of supported device rates without delayed ordered events or accumulating backlog. Test representative 125/500/1000 Hz sources where hardware permits; higher rates require an explicit support decision and evidence.
- Agent/native-shell/webview CPU, resident/private memory by platform, allocation counts/bytes, peak queue capacity, thread/task counts and resource growth over long sessions.
- Idle wakeups, timer cadence and energy/battery behavior with sharing off, connected idle and active use. Low average CPU alone does not establish battery efficiency.
- Widget first useful paint, cold/warm activation, input response and state propagation while input sharing is loaded. Compare keeping versus destroying hidden webviews before choosing a policy.

Benchmark release builds with normal authentication and encryption enabled. Record OS, architecture, hardware, network, device rate, build SHA, power mode, warmup, sample count, loss conditions and measurement method. Keep raw results and compare repeated runs under equivalent conditions. Avoid performance claims based on debug builds or unsynchronized cross-host timestamps.

## Required performance matrix

Exercise both Mac-to-Windows and Windows-to-Mac, wired and representative Wi-Fi, UI visible/hidden, agent idle/active, keyboard and pointer separately and together, clipboard/diagnostics load, reconnects, packet delay/loss/reordering and CPU contention. Include mixed DPI, multi-monitor handoff and high-rate input. Hardware variants and native architectures follow the agreed support matrix.

Use microbenchmarks for routing, serialization, parser bounds, queues and state transitions; integration benchmarks for real scheduling and transport; physical tests for actual capture/injection and perceived smoothness. Dedicated controlled performance runs enforce tail-latency/energy budgets. Shared CI runners provide useful deterministic checks and trend signals but cannot reliably certify small physical-latency differences.

Every critical-path feature records before/after performance evidence. Regression gates cover tails, jitter, release behavior and resource use, not just a single throughput score. No hidden webview polling or animation when dismissed. Diagnostics instrumentation overhead is measured enabled and disabled.

## Implementation order

1. Establish behavior, hardware baseline, new Rust contracts, performance targets and a reuse register. Prototype signed native capture and the small desktop shell on both OSes.
2. Build the smallest new two-host authenticated capture-to-injection path with emergency release. Prove both-direction safety, ordering and performance before expanding features.
3. Implement authority/handoff, session recovery, held-input state and native lifecycle in the new architecture. Stress overload and failures while measuring the hot path.
4. Implement idle agent, versioned local API, enrollment, persistence, topology and optional clipboard, keeping background work within the input-path budgets.
5. Integrate the new tray/widget UI, setup and settings. Validate the full app under visible/hidden UI load.
6. Prove credential/config migration, mixed-version policy, installed permissions, fault recovery, packaging and rollback. Decide deliberately whether to preserve the old peer wire, support a negotiated compatibility mode, or require both hosts to update; no silent unsafe downgrade.
7. Cut over only after physical correctness, full performance matrix and long-running soak gates pass. Stop legacy capture before enabling new capture. Retire legacy compatibility at a documented checkpoint.

Feature parity means required behavior, not line-for-line porting. The new plan has more design, native validation and security work than the original selective refactor. Re-estimate after the first measured end-to-end slice. Architecture, reuse decisions and performance targets are reviewable outputs before full implementation.
