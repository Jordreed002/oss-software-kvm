# Performance baseline procedure

Status on 2026-11-17: metadata tooling accepted in `7848029`; current batched software lifecycle measurements and superseded history recorded below. Physical and native performance measurements remain unmeasured. No numerical performance budgets have been accepted here.

## Metadata collector

Requires Node.js 18 or newer. No npm dependencies or installation step. Run from the repository root on Windows, macOS or Linux:

```text
node scripts/performance/collect-baseline.mjs
node scripts/performance/collect-baseline.mjs --stdout
node scripts/performance/collect-baseline.mjs --output target/performance/baseline-001.json
node --test scripts/performance/collect-baseline.test.mjs
```

The default emits structured JSON to stdout. `--output` creates a new JSON file and parent directories. Existing files are never overwritten. Repository output is restricted to `target/performance`, already excluded by the root `.gitignore`. An explicit new JSON destination outside the repository is also allowed. Source directories, including new JSON files there, are rejected. Symlinked parent directories are resolved before checking repository boundaries. Do not change output directory links concurrently with collection.

The collector records SHA, branch, dirty state, OS release, architecture, CPU models/count, total memory, Node/V8 and Git/Rust toolchain versions. It omits hostname, username, absolute repository path and dirty filenames. Metadata can still identify hardware; inspect results before sharing and do not commit machine results. Missing commands, command failures and timeouts produce explicit unavailable fields. Unknown Git state is `null`, never clean by assumption. Each subprocess has a three-second timeout and a bounded output buffer, uses argument arrays and has no shell. Git status does not update the index.

Rust probes list installed rustup toolchains and explicitly run version commands with the first listed toolchain. `probedRustToolchain` identifies that selection. This is not necessarily the project's selected toolchain. Direct rustc/cargo shims are deliberately skipped when no installed rustup toolchain is available, avoiding project override installation. The collector never builds, downloads, runs benchmarks, launches capture/KVM or changes system settings. Version tools must be trusted executables on PATH.

In collector JSON, all benchmark entries and physical latency, pointer jitter, energy, release latency, queue age, CPU/memory usage, allocations, wakeups and widget activation remain `unmeasured` with a null value. Total machine memory is inventory, not application memory usage. The CLI does not ingest results or certify release gates.

## Existing Rust benchmarks

Inspected at architecture commit `06e56770771b569c5602fc5cafeedb2ffc2cd542`. These are legacy reference benchmarks, not approvals to reuse their implementation. Run explicitly on prepared machines with the project's Rust dependencies already available. Commands below use Cargo's optimized bench profile and locked, offline inputs. If dependencies are missing they fail rather than install them. Native build prerequisites must already exist.

```text
cargo bench --locked --offline -p kvm-protocol --bench frame_codec
cargo bench --locked --offline -p kvm-protocol --bench frame_roundtrip
cargo bench --locked --offline -p kvm-network --bench pointer_datagram_codec
cargo bench --locked --offline -p kvm-network --bench tls_record
cargo bench --locked --offline -p kvm-network --bench outbound_queue
```

| Target | Scope and interpretation |
| --- | --- |
| `frame_codec` | Handwritten allocating/reused-buffer encode, decode and roundtrip. 300 ms warmup, 31 samples of 100,000 frames per scenario. Reports median and p95 throughput, not latency percentiles. |
| `frame_roundtrip` | Criterion equivalent of those frame codec operations, one element per iteration. Default Criterion timing applies; preserve invocation and raw `target/criterion` output. |
| `pointer_datagram_codec` | Criterion plaintext pointer encode/parse/roundtrip and reliable reassembly. Excludes encryption and sockets. |
| `tls_record` | Handwritten TLS 1.3 mutual-authenticated client/server benchmark over in-memory duplex streams, not physical LAN or OS capture/injection. Preserve full output and scenario parameters. |
| `outbound_queue` | Handwritten push/coalescing and drain scenarios. 300 ms warmup, 31 samples of 100,000 events per scenario. Throughput cannot establish jitter, emergency release or zero allocations. |

Benchmarks may run for a substantial period and compilation may be expensive. The collector invokes none of them. Preserve exact command, build SHA and dirty state, selected `rustc --version --verbose`, Cargo version, profile/flags, warmup/sample settings, raw output and repeated-run count with each result. Use fresh result names under ignored storage. Existing benchmark printouts contain historical headroom claims; those claims do not establish rebuild budgets. No Rust benchmarks were executed for this tooling delivery.

## Machine and scenario matrix

Reference machines and the final support matrix still need coordinator confirmation. Windows 11 and macOS are required by the approved direction. CPU rows below are proposed test coverage, not established support or available machines.

| Machine row | Architecture | Availability and measurements |
| --- | --- | --- |
| Windows 11 reference desktop/laptop | x86_64 proposed; ARM64 decision pending | Machine designation, power mode, hardware and all metrics unmeasured |
| macOS reference Apple Silicon | aarch64 proposed | Machine designation, macOS version, hardware and all metrics unmeasured |
| macOS Intel if retained in support scope | x86_64 decision pending | Machine availability and all metrics unmeasured |

Run standalone microbenchmarks per approved machine. For physical tests, pair Windows and macOS and exercise both directions. Cross wired/Wi-Fi, hidden/visible UI, paused/connected-idle/active sharing, keyboard/pointer/combined input, representative 125/500/1000 Hz devices where available, mixed DPI and multiple displays. Include clipboard/diagnostic contention, CPU load, reconnects and controlled delay/loss/reordering. Record device rate, topology, network, power mode, encryption/authentication state and measurement method. Any unsupported or unavailable matrix cell stays unmeasured with a reason.

Physical capture-to-injection latency needs external measurement or validated cross-host clock alignment. Record p50/p95/p99 and p99.9 only with enough samples, plus sample count and noise/repeated-run evidence. Independently measure pointer gaps/fidelity/jitter, event age, held-state release, per-process CPU/memory, allocations, wakeups and energy. Keep agent, native shell and webview resource figures separate. Measure instrumentation overhead. Safety acceptance also requires lifecycle/fault transitions and a 24-hour soak. A metadata capture, microbenchmark or UI fixture cannot close those gates.

## Superseded lifecycle software measurement at f9f30b1, 2026-11-17

Historical evidence only. Superseded by `84b974d` and the current Cargo run below. The old 0/0/100 ns results provide no evidence of zero-cost calls. Cargo parsing and clippy limitations in this section describe that earlier checkpoint, not current blockers.

Build identity: HEAD `f9f30b1d70a942646baae7e2ca4991829c01164e`, with dirty benchmark/manifest files and concurrent UI work. Core `crates/kvm-agent-model/src/lib.rs` had no diff against that committed SHA. These are measurements of the current dirty benchmark build against committed core, not results from a clean committed benchmark revision. One run used rustc 1.97.1 and Cargo 1.97.1. No machine-identifying inventory is included.

The dependency-free `lifecycle` target uses `harness = false`. Each of ten operations has exactly 2,000 untallied warmup calls followed by 10,000 samples. Each sample times one synchronous API call with Instant. Setup, sorting and semantic assertions are outside timing. Inputs and mutable state pass through black_box and results are consumed and asserted. Optimized assembly retains the indirect operation call between Instant::now and elapsed and state writes in the operation closures. This confirms the timed operation was not eliminated. Output checks confirm returned effects/tickets, expected phase, admission and terminal latch rejection. This is no allocation-count measurement.

Percentiles use nearest ranks on individual-call durations, with the lower middle sample for median. They are not percentiles of loop averages. Timer/barrier and dispatch overhead remains included; zero values indicate the timer resolution floor, not free execution. The uniform 0/0/100 ns distribution cannot resolve useful differences between these operations or establish real-world tail latency.

Attempted commands, all blocked before compilation by the concurrent foundation manifest having no target:

```text
cargo bench --locked --offline -p kvm-agent-model --bench lifecycle
cargo test --locked --offline -p kvm-agent-model
cargo clippy --locked --offline -p kvm-agent-model --all-targets -- -D warnings
```

Successful focused fallback commands from repository root, using existing ignored target storage:

```text
rustfmt --edition 2021 crates/kvm-agent-model/benches/lifecycle.rs
rustc --edition=2021 --crate-name kvm_agent_model --crate-type rlib -C opt-level=3 crates/kvm-agent-model/src/lib.rs -o target/performance/lifecycle/libkvm_agent_model.rlib
rustc --edition=2021 -C opt-level=3 crates/kvm-agent-model/benches/lifecycle.rs --extern kvm_agent_model=target/performance/lifecycle/libkvm_agent_model.rlib -o target/performance/lifecycle/lifecycle.exe
& target/performance/lifecycle/lifecycle.exe
rustc --edition=2021 --test crates/kvm-agent-model/src/lib.rs -o target/performance/lifecycle/lifecycle-tests.exe
& target/performance/lifecycle/lifecycle-tests.exe
rustc --edition=2021 -C opt-level=3 --emit=asm crates/kvm-agent-model/benches/lifecycle.rs --extern kvm_agent_model=target/performance/lifecycle/libkvm_agent_model.rlib -o target/performance/lifecycle/lifecycle.s
rg -n 'callq|movb' target/performance/lifecycle/lifecycle.s
```

Actual software-only output summary, all durations in ns:

| Operation | Min | Median | p95 |
| --- | ---: | ---: | ---: |
| resume_ready | 0 | 0 | 100 |
| prepared_success | 0 | 0 | 100 |
| pause_sharing | 0 | 0 | 100 |
| drained_success | 0 | 0 | 100 |
| prepared_failure | 0 | 0 | 100 |
| drained_failure | 0 | 0 | 100 |
| failsafe_sharing | 0 | 0 | 100 |
| failsafe_preparing | 0 | 0 | 100 |
| failsafe_paused | 0 | 0 | 100 |
| failsafe_drain_completion | 0 | 0 | 100 |

The executable reported all warmup/sample semantic checks passing. Direct tests reported 8 passed, 0 failed, finished in 0.00s. Execution plus direct compilation completed in seconds. Direct rustc uses opt-level=3 for both library and benchmark, not Cargo's bench profile; the integrated Cargo bench now passes as recorded below. Coordinator reports current package clippy passing; this lane did not independently rerun clippy. These host-local synchronous state transitions execute no native cleanup, capture, injection, transport, cross-host operation or installed lifecycle. Physical/native measurements and acceptance gates remain unmeasured.


## Current lifecycle batch measurement, 2026-11-17

One fresh run in the actual workspace at HEAD `5b1688cbc95af3b23b25fbe5dde48236555def35`, branch `overhaul/widget-app-planning`. Benchmark revision is `84b974d`, lifecycle fixes are `b660e2e`, and accepted foundation is `f4ddbf3`. Git status before and after execution showed only `docs/overhaul/implementation-progress.md` and `docs/overhaul/performance-baseline.md` modified. This was a dirty documentation build, with no benchmark/core edits. No machine-identifying inventory was collected.

Invocation from the repository root, repeated-run count 1:

```text
cargo bench --locked --offline -p kvm-agent-model --bench lifecycle
```

Tool versions were `rustc 1.97.1 (8bab26f4f 2026-07-14)` and `cargo 1.97.1 (c980f4866 2026-06-30)`. Cargo reported its optimized bench profile and reused the built executable `target/release/deps/lifecycle-aff5e8e95256766f.exe`. No extra profile/compiler flags were supplied. Verbose compiler configuration was not captured in this bounded rerun.

Source inspection confirms 100 warmup batches, 1,000 measured samples and 128 calls per sample. Setup and semantic assertions run outside timing. Each sample measures an entire batch, including dispatch/timing overhead. Median uses the lower middle sorted sample; p95 uses nearest rank. These are whole-batch durations, not per-call averages or individual-event latency percentiles. The benchmark does not measure allocations or execute native cleanup, capture, injection or transport.

Raw summary:

```text
    Finished `bench` profile [optimized] target(s) in 0.07s
     Running benches\lifecycle.rs (target\release\deps\lifecycle-aff5e8e95256766f.exe)
Host-local lifecycle batches: warmup=100, samples=1000, batch=128
Batch durations include dispatch/timing overhead; NOT individual-call tail latency.
resume_ready: batch_min=800 ns batch_median=900 ns batch_p95=1000 ns calls_per_batch=128
prepared_success: batch_min=800 ns batch_median=900 ns batch_p95=900 ns calls_per_batch=128
pause_sharing: batch_min=800 ns batch_median=900 ns batch_p95=900 ns calls_per_batch=128
drained_success: batch_min=800 ns batch_median=900 ns batch_p95=900 ns calls_per_batch=128
prepared_failure: batch_min=900 ns batch_median=1000 ns batch_p95=1000 ns calls_per_batch=128
drained_failure: batch_min=800 ns batch_median=900 ns batch_p95=900 ns calls_per_batch=128
retry_cleanup: batch_min=800 ns batch_median=900 ns batch_p95=900 ns calls_per_batch=128
failsafe_sharing: batch_min=900 ns batch_median=1000 ns batch_p95=1000 ns calls_per_batch=128
failsafe_preparing: batch_min=900 ns batch_median=900 ns batch_p95=1000 ns calls_per_batch=128
cancelled_preparation_fenced: batch_min=900 ns batch_median=1000 ns batch_p95=1000 ns calls_per_batch=128
failsafe_paused: batch_min=300 ns batch_median=300 ns batch_p95=400 ns calls_per_batch=128
failsafe_drain_completion: batch_min=800 ns batch_median=800 ns batch_p95=900 ns calls_per_batch=128
All batch state/effect assertions passed. No native or cross-host measurements.
```

Coordinator evidence separately reports actual-workspace `cargo test --locked --offline -p kvm-agent-model -p kvm-foundation` passing 12 + 17 + 1 tests and `cargo clippy --locked --offline -p kvm-agent-model -p kvm-foundation --all-targets -- -D warnings` passing. These checks were not rerun here. The accepted foundation includes a counting allocator integration test with a positive control for its tested queue construction/steady-state operations. That evidence does not establish allocation behavior of a native agent or the full input path.

No supported performance comparison follows from the superseded single-call timing and this batch method. Physical/native metrics, browser/native UI validation and installed-agent acceptance remain unmeasured. There is no real native agent yet.

## Rebuild correctness checks, 2026-11-17

`scripts/check-rebuild.ps1` and `scripts/check-rebuild.sh` now provide package-focused fmt, locked offline library/integration tests and strict all-target clippy for the three approved rebuild packages. Their defaults do not execute benchmarks. Panel and separately excluded Tauri checks require explicit independent options. Optional macOS cross-clippy uses installed targets only and reports a skip if none exist. These scripts launch no capture, application or server, change no configuration and provide no physical/native input certification. Usage and exact correctness evidence are recorded in `implementation-progress.md` under the rebuild check scripts checkpoint.

Actual Windows script checks passed IPC 12, model 14, foundation 23 unit tests plus one allocator integration test, host strict clippy and Apple Silicon strict cross-clippy. Actual Ubuntu WSL script checks passed IPC 9, model 14, foundation 23 unit tests plus one allocator integration test and Linux strict clippy. WSL skipped the optional macOS check because no Apple target was installed. Its existing isolated Rust installation and output remain under ignored `target/wsl-tools` and `target/wsl-check`; no installation was performed.

Windows uses Rust 1.97.1; Linux uses Rust 1.100.0. These are correctness checks on different toolchains, not controlled same-toolchain performance comparisons. No new performance measurements or benchmarks were run. The historical lifecycle batch measurements above retain their original build identity and interpretation. Hardware measurements, actual macOS execution, native agent integration and physical input acceptance remain pending.
