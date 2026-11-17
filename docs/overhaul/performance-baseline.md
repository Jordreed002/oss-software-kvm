# Performance baseline procedure

Status on 2026-11-17: metadata tooling delivered. Physical and native performance measurements remain unmeasured. No numerical performance budgets have been accepted here.

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

All benchmark entries and physical latency, pointer jitter, energy, release latency, queue age, CPU/memory usage, allocations, wakeups and widget activation remain `unmeasured` with a null value. Total machine memory is inventory, not application memory usage. The CLI does not ingest results or certify release gates.

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
