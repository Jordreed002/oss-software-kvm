# Performance baseline procedure

Status on 2026-11-17: metadata tooling accepted in `7848029`; current batched software lifecycle measurements and superseded history recorded below. Physical and native performance measurements remain unmeasured. No numerical performance budgets have been accepted here.

## Accepted benchmark implementation, 2026-11-17

Coordinator-owned Opus review conditionally accepted the benchmark mechanics. The coordinator addressed all required framing corrections and committed the implementation in `4c392ec`: pair labels identify best-case occupancy, the mixed engine pair explicitly measures only the head-stage path, fault rows print the observed Windows timer-quantization caveat, outcome checksums and truncated decimal display are described accurately, and the wraparound check accounts for all warmup and measured operations. The corrected optimized benchmark and strict all-target clippy passed. This accepts a repeatable microbenchmark implementation, not a release budget or physical performance claim.

The numeric record below remains the original dirty run at `eb40c9b`; it is not relabelled as a measurement of `4c392ec`. Its mixed engine pair never exercised the engine's internal ring at sustained occupancy. Fault-batch statistics are coarse quantized observations. Future comparisons must retain those scope distinctions and use equivalent builds and conditions.

## Pre-review availability checkpoint at eb40c9b, 2026-11-17

Inspected HEAD is `eb40c9bc5c4faa4d61090060aecd815ba6a7fd11` on `overhaul/widget-app-planning`. Before these documentation edits, `crates/kvm-input-engine/Cargo.toml` was modified and `crates/kvm-input-engine/benches/` was untracked, containing `input_path.rs`. The GLM benchmark delivery remains unaccepted pending coordinator-owned Opus review `62489094`. Root independently ran the benchmark and correctness checks below. Historical GLM-reported benchmark results belong to their own run; the root results below do not replace or independently verify those historical numbers. No GLM raw artifact or exact historical numeric summary was supplied for this documentation update, so none is reconstructed here.

The Opus read-only utility-agent UI is accepted in `eb40c9b` for development use only. Root passed TypeScript checking, 122 frontend tests, production build, 33 Tauri library tests and strict all-target Tauri clippy on Windows. No browser, native GUI, live-window roundtrip or Mac UI validation was performed. Windows is available now; Mac physical access is planned later. Current two-host physical access is not established. Earlier native Mac software tests and process smoke retain their historical revisions in `implementation-progress.md`.

The standalone input engine remains accepted in `207c911`, with 38 focused tests on Windows and Linux. Earlier expanded script results remain 147 Windows tests and 148 Linux tests, formatting and strict clippy, including Apple Silicon cross-clippy on Windows. Cross-clippy provides no native Mac execution evidence. Identity-storage delegation remains cancelled; ADR 0005 is only a contract. Physical latency, jitter, release, resource and energy acceptance remain open, with no physical gate closure or accepted numerical budgets.

## Independent root input-path run at eb40c9b, 2026-11-17

Evidence files are ignored local artifacts, not committed results:

```text
target/performance/input-path-65688360949d4d01871cbe3ea43018f6/metadata.json
target/performance/input-path-65688360949d4d01871cbe3ea43018f6/raw.txt
```

Metadata collection time is `2026-11-17T09:24:44.419Z`. Build identity is HEAD `eb40c9bc5c4faa4d61090060aecd815ba6a7fd11`, branch `overhaul/widget-app-planning`, dirty `true`, with the benchmark manifest/source changes listed above. This is a dirty benchmark build against the accepted committed runtime, not a clean committed benchmark revision. Metadata reports Windows `win32` release `10.0.26200`, x64, Intel Core i7-13700K, 24 logical CPUs and 34,122,776,576 bytes of total machine memory. The probed toolchain is `stable-x86_64-pc-windows-msvc`, rustc `1.97.1 (8bab26f4f 2026-07-14)`, full compiler commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`, host `x86_64-pc-windows-msvc`, LLVM `22.1.6`, and Cargo `1.97.1 (c980f4866 2026-06-30)`. Node is `v24.12.0`, V8 `13.6.233.17-node.37`, Git `2.40.0.windows.1` and rustup `1.29.0 (28d1352db 2026-03-05)`.

Root reports successful commands from the repository root, using Cargo's optimized bench profile for the benchmark:

```text
cargo bench --locked --offline -p kvm-input-engine --bench input_path
cargo test --locked --offline -p kvm-input-engine
cargo clippy --locked --offline -p kvm-input-engine --all-targets -- -D warnings
```

The focused tests passed 38 cases and strict clippy passed. This documentation task reran none of these commands. The collector's benchmark and physical-measurement fields remain `unmeasured`; it does not ingest the separate raw output.

Source inspection confirms a dependency-free `harness = false` benchmark with synthetic events and event-age clock, one thread, three warmup batches and 30 timed samples per scenario. `Instant` times whole loops. Median is the midpoint of the two middle sorted batch durations; p95 is nearest rank, sample 29 of 30. Inputs and mutable state cross `black_box`; outcomes feed asserted checksums. Loop and barrier overhead remain included. Pools and fault-engine construction are outside timing. Outcome checksums and additional FIFO, route, fault and retention assertions pass outside timed batches.

The raw summary below preserves operation units and whole-batch results. The first three scenarios use 4,096 pairs per batch; stale rejection and held-set scenarios use 2,048 pairs. Each pair is one reported operation containing two calls. Each fault scenario uses 512 distinct engines and one terminal fault call per engine. The printed amortized ns/op values divide batch statistics by these operation counts and truncate to two decimals. They are not individual-call or per-event latency percentiles.

This is one unpinned Windows run with uncontrolled scheduling and no repeated-run evidence or accepted budgets. Typical 512-operation fault batches span only 7-10 QPC ticks at 100 ns per tick: full rejection min/median/p95 is 900/900/1,000 ns; expiry min/median is 700/800 ns, with p95 4,100 ns. These coarse durations cannot resolve reliable operation-level differences. No physical capture, network, native injection, encryption, per-event tail or speedup claim follows.

Unchanged raw summary:

```text
input-path microbenchmark: synthetic events, synthetic clock, one thread
timing unit: whole batch; stats: min/median/p95 (nearest-rank p95)
scope: userspace admission data structures only; no physical capture,
network, native injection or encryption is measured or claimed

[ring_fifo_enqueue_consume_pair] 1 op = one push + one pop (capacity 64)
  warmup_batches=3 measured_samples=30 ops_per_batch=4096
  whole_batch_ns: min=7_300 median=7_300 p95=8_600
  amortized_ns_per_op: min 7_300 / 4096 = 1.78
  amortized_ns_per_op: median 7_300 / 4096 = 1.78
  amortized_ns_per_op: p95 8_600 / 4096 = 2.09
[ring_fifo_sustained_wraparound] 1 op = one pop + one push at full occupancy (capacity 8)
  warmup_batches=3 measured_samples=30 ops_per_batch=4096
  whole_batch_ns: min=6_500 median=7_600 p95=7_900
  amortized_ns_per_op: min 6_500 / 4096 = 1.58
  amortized_ns_per_op: median 7_600 / 4096 = 1.85
  amortized_ns_per_op: p95 7_900 / 4096 = 1.92
[engine_enqueue_consume_mixed_pair] 1 op = one enqueue + one consume (capacity 16, mixed families)
  warmup_batches=3 measured_samples=30 ops_per_batch=4096
  whole_batch_ns: min=21_700 median=21_700 p95=21_800
  amortized_ns_per_op: min 21_700 / 4096 = 5.29
  amortized_ns_per_op: median 21_700 / 4096 = 5.29
  amortized_ns_per_op: p95 21_800 / 4096 = 5.32
[engine_stale_epoch_rejection] 1 op = one stale enqueue + one stale consume (valid event, queue holds 1)
  warmup_batches=3 measured_samples=30 ops_per_batch=2048
  whole_batch_ns: min=3_500 median=3_500 p95=4_200
  amortized_ns_per_op: min 3_500 / 2048 = 1.70
  amortized_ns_per_op: median 3_500 / 2048 = 1.70
  amortized_ns_per_op: p95 4_200 / 2048 = 2.05
[engine_full_rejection] 1 op = one overflow enqueue into a full queue (capacity 16)
  warmup_batches=3 measured_samples=30 ops_per_batch=512
  whole_batch_ns: min=900 median=900 p95=1_000
  amortized_ns_per_op: min 900 / 512 = 1.75
  amortized_ns_per_op: median 900 / 512 = 1.75
  amortized_ns_per_op: p95 1_000 / 512 = 1.95
[engine_queued_age_expiry_retention] 1 op = one consume one nanosecond past the age bound (2 entries held)
  warmup_batches=3 measured_samples=30 ops_per_batch=512
  whole_batch_ns: min=700 median=800 p95=4_100
  amortized_ns_per_op: min 700 / 512 = 1.36
  amortized_ns_per_op: median 800 / 512 = 1.56
  amortized_ns_per_op: p95 4_100 / 512 = 8.00
[held_set_press_release_pair] 1 op = one press + one release of a fresh key (capacity 16)
  warmup_batches=3 measured_samples=30 ops_per_batch=2048
  whole_batch_ns: min=7_300 median=7_400 p95=38_900
  amortized_ns_per_op: min 7_300 / 2048 = 3.56
  amortized_ns_per_op: median 7_400 / 2048 = 3.61
  amortized_ns_per_op: p95 38_900 / 2048 = 18.99

done: every semantic check passed outside the timed batches
```

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
| Windows 11 reference desktop/laptop | x86_64 proposed; ARM64 decision pending | Windows available now; reference machine designation, power mode, hardware and physical metrics unmeasured |
| macOS reference Apple Silicon | aarch64 proposed | Mac access planned later for physical validation; reference designation and physical metrics unmeasured. Historical native software evidence is recorded separately. |
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

No supported performance comparison follows from the superseded single-call timing and this batch method. Physical/native metrics, browser/native UI validation and installed-agent acceptance remain unmeasured. At that measurement checkpoint there was no real native agent. Later accepted read-only agent and Mac process-smoke evidence is recorded in `implementation-progress.md`; it does not establish physical input or performance acceptance.

## Historical rebuild correctness checks, 2026-11-17

`scripts/check-rebuild.ps1` and `scripts/check-rebuild.sh` now provide package-focused fmt, locked offline library/integration tests and strict all-target clippy for the three approved rebuild packages. Their defaults do not execute benchmarks. Panel and separately excluded Tauri checks require explicit independent options. Optional macOS cross-clippy uses installed targets only and reports a skip if none exist. These scripts launch no capture, application or server, change no configuration and provide no physical/native input certification. Usage and exact correctness evidence are recorded in `implementation-progress.md` under the rebuild check scripts checkpoint.

Actual Windows script checks passed IPC 12, model 14, foundation 23 unit tests plus one allocator integration test, host strict clippy and Apple Silicon strict cross-clippy. Actual Ubuntu WSL script checks passed IPC 9, model 14, foundation 23 unit tests plus one allocator integration test and Linux strict clippy. WSL skipped the optional macOS check because no Apple target was installed. Its existing isolated Rust installation and output remain under ignored `target/wsl-tools` and `target/wsl-check`; no installation was performed.

Windows uses Rust 1.97.1; Linux uses Rust 1.100.0. These are correctness checks on different toolchains, not controlled same-toolchain performance comparisons. No new performance measurements or benchmarks were run. The historical lifecycle batch measurements above retain their original build identity and interpretation. Hardware measurements, actual macOS execution, native agent integration and physical input acceptance remain pending.
