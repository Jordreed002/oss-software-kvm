# Rebuild implementation progress

Evidence checkpoint: 2026-11-17. This ledger records delivered work and acceptance evidence. It does not estimate completion percentages or close physical gates from software checks.

## Approval and base

The user approved a ground-up Rust rebuild with selective reuse and performance as a primary requirement. ADR `docs/adr/0003-ground-up-rebuild.md` records the accepted direction and ownership. Acceptance supersedes older proposed/planning status text in the recommendation and strategy documents.

Observed branch: `overhaul/widget-app-planning`. Inspected HEAD: `5b1688cbc95af3b23b25fbe5dde48236555def35`. Planning comparison base remains `code-review-remediation` at `9edb5ed`. Only this ledger and `performance-baseline.md` were dirty before this bounded tracking update. Their previous uncommitted evidence is retained below or in the baseline history. This task makes no commits or branch changes.

## Current work lanes

| Lane | Status | Evidence and remaining acceptance |
| --- | --- | --- |
| Sol baseline tooling and progress tracking | Tooling accepted in `7848029`; current lifecycle benchmark integrated in `84b974d` | Earlier collector verification passed seven tests and stdout/file smoke checks. One fresh optimized Cargo benchmark run passed here; exact identity, command and raw batch summary are in `performance-baseline.md`. Tracking edits remain uncommitted. |
| GLM 5.3 Rust foundation | Accepted in `f4ddbf3` after review and coordinator corrections | GLM delivery was conditionally accepted with one `unused_self` lint. Coordinator added the exact allow, redacted debug payloads, corrected the layout doc and added a counting allocator integration test with a positive control. Coordinator reports foundation 17 unit tests plus one integration test and clippy passing. This establishes bounded foundation evidence, not native fast-path acceptance. |
| Opus UI implementation | Development UI accepted in `ef7b213` | Coordinator reports `npm test` with 82 passing tests and `npm run build` passing. No browser or native validation. |
| Lifecycle model | Fixes accepted in `b660e2e`; Opus review `00e5c53c` accepted lifecycle | Fixes follow the Opus high cancellation finding. Current API includes `new(instance: u128)`, `CancelPrepare`, `DrainTicket` and `retry_cleanup`. Coordinator reports 12 tests and clippy passing. |
| GLM new API | Task `214f83f0` in progress | `5b1688c` defines the precision-safe versioned replacement API contract. Implementation is not accepted. All GLM work requires Opus review. |
| Native agent and hardware performance | No real native agent yet; physical metrics unmeasured | No capture/injection adapters, installed lifecycle or physical latency, jitter, release, energy or native resource acceptance established by this evidence. |

Coordinator integration addendum: the lifecycle model now has 14 passing tests, including forged future cleanup attempts and retry during an outstanding preparation fence, plus a `waiting_for_preparation` status accessor. New `kvm-agent-ipc` provides bounded, caller-buffer framing only; its five tests cover fragmented reads, exact boundaries, rejected lengths before body reads, partial frames and rejected writes. Both packages pass actual-workspace strict clippy. The framing layer implements no native endpoint or authorization, so the native-agent gate stays open. These checks extend the earlier checkpoint; they do not retroactively change the recorded benchmark build identity.

Held-control implementation delivery, 2026-11-17: `crates/kvm-foundation/src/held.rs` and minimal `src/lib.rs` exports are delivered in the working tree, awaiting coordinator verification. No acceptance, commit or branch change is claimed. Accepted foundation remains `f4ddbf3`; lifecycle evidence remains 14 tests and IPC framing `453912b` remains five tests. Native transport and capture remain pending.

`HeldSet<T: Copy + Eq, N>` stores device-specific keys/buttons inline without allocation, unsafe code or synchronization. Duplicate presses consume no slot, full insertion preserves existing work, and cleanup freezes press/release mutation. Peek retains work until the owner confirms the exact current token and control. Finish requires an empty ledger. Debug output redacts controls and tokens. The owner must supply fresh tokens across owner/session cleanup generations. Confirmation records the owner's acknowledgement of exact work, not polling, queue admission, native delivery or transport proof. Motion and scroll have no ledger representation.

Actual-workspace checks passed for this delivery:

```text
cargo fmt --all -- --check
cargo test --locked --offline -p kvm-foundation
cargo clippy --locked --offline -p kvm-foundation --all-targets -- -D warnings
```

Tests passed: 23 foundation unit tests, including the six new tests below, one existing queue allocator integration test, and zero doc tests. The existing allocator test covers the queue only; held storage's allocation-free implementation follows directly from its inline array operations.

```text
held::tests::full_duplicate_and_release_are_lossless
held::tests::distinct_devices_and_control_families_have_distinct_slots
held::tests::zero_capacity_can_complete_empty_cleanup
held::tests::cleanup_freezes_mutations_and_failed_send_retains_head
held::tests::stale_acknowledgements_cannot_change_a_new_cleanup
held::tests::debug_redacts_controls_devices_and_opaque_tokens
```

## Phase gates

## Native and held-state integration checkpoint

- `08dac0e`: Sol's bounded held-input ledger accepted after coordinator source review, 23 foundation unit tests plus the allocation integration test, and strict workspace clippy. The ledger itself has six tests covering sealed cleanup, retained pending releases and stale acknowledgements. Native delivery is not established by ledger acknowledgement.
- `d850edf`: Opus native utility preview shell accepted as development-only groundwork. Coordinator reran six Tauri preview tests, all 85 frontend tests and the production build. Runtime flag selects a shell owning no legacy setup/discovery/capture. Native desktop behavior has not been launched/observed and macOS paths have not been compiled. Single-instance and real tray anchoring remain absent.
- `dcd1466`: Windows user-scoped named-pipe listener prototype. Seven IPC tests and strict clippy pass, including actual same-user Windows roundtrip, occupied-name rejection and sequential client rotation. A protected DACL is constructed for the process user and SYSTEM, remote clients are rejected, and listener admission is bounded. Opus native/security review is pending. Installed-agent identity, cross-user authorization tests, cross-session policy, Unix/macOS endpoint implementation and agent-command integration remain incomplete.

These are intermediate implementations, not physical input-path or release acceptance. The serialized API is still in its GLM implementation lane and requires Opus review before acceptance.

## Phase gates continued

| Phase | Actual state | Outstanding evidence |
| --- | --- | --- |
| 0. Baseline, architecture and experience | In progress. Accepted ADR, contracts and metadata tooling exist. | Physical legacy baseline, named machines/support matrix, numeric budgets, complete architecture/reuse register, visual variant approval and installed shell/permission/signing spike. |
| 1. Rust foundation and fast path | Bounded foundation accepted after review; native fast path incomplete. | Native adapters, authenticated two-host slice, both-direction ordered-state/emergency-release and measured budgets. Allocation test evidence covers the tested queue operations only. |
| 2. Agent and control plane | Reviewed pure lifecycle model accepted; new API implementation in progress. No real native agent yet. | Idle agent, authority, identity/enrollment, topology/configuration, implemented authenticated versioned API, confirmed native outcomes and contention evidence. GLM implementation requires Opus review. |
| 3. Tray shell and daily UI | Development UI accepted; native shell incomplete. | Browser validation, reviewed design, native tray/single instance/supervision, accessible setup/settings, 100 open/dismiss cycles, DPI and visible/hidden resource gates. |
| 4. Security and migration | Pending. | Enrollment review, endpoint authorization, transactional settings, credential migration/rollback and release diagnostics validation. |
| 5. Lifecycle and physical acceptance | Pending; physical metrics unmeasured. | Both receiving OSes, 100 combined lifecycle/fault transitions each, no stuck input/duplicate owner, 24-hour soak and full performance matrix. |
| 6. Installed release and cutover | Pending. | Approved packages/signing, clean install/upgrade/interruption/uninstall/rollback and exclusive capture cutover after prior gates. |

## Verification and sources

Git inspection confirmed the branch, full HEAD, two dirty documentation paths and commit sequence through `5b1688c`. This lane read the current benchmark source and ran exactly once:

```text
cargo bench --locked --offline -p kvm-agent-model --bench lifecycle
```

The actual workspace optimized bench passed all batch state/effect assertions. It uses 100 warmup batches, 1,000 measured samples and 128 calls per sample. Output reports whole-batch min/median/p95, not individual-event latency. No benchmark or core code was changed here.

The coordinator supplied the acceptance/review evidence above and these successful actual-workspace checks. This tracking task did not rerun them:

```text
cargo test --locked --offline -p kvm-agent-model -p kvm-foundation
cargo clippy --locked --offline -p kvm-agent-model -p kvm-foundation --all-targets -- -D warnings
```

Reported test counts are 12 lifecycle tests, 17 foundation unit tests and one allocator integration test. UI test/build evidence and review/task identifiers are coordinator-supplied, not independent browser/native validation by this lane.

## Superseded lifecycle benchmark history

The previous bounded delivery inspected `f9f30b1d70a942646baae7e2ca4991829c01164e`. It added a benchmark and manifest entry while UI/foundation work was concurrent. Cargo bench/test/clippy then failed before compilation because the foundation manifest had no target. Direct rustc fallback passed eight lifecycle tests and benchmark assertions. Those blockers and counts are historical and superseded by the integrated Cargo evidence above.

That version used 2,000 warmup calls and 10,000 individually timed samples per operation. All ten operations reported 0/0/100 ns min/median/p95. The baseline retains the exact historical commands and table, labelled superseded. These timer-floor results apply only to the old build and provide no evidence of zero-cost calls. `84b974d` adapted the benchmark to the fenced lifecycle API and clock-resolvable batches. No performance comparison or hardware conclusion follows from these different methods.

Earlier collector verification passed seven tests covering arguments, missing tools, explicit toolchain selection, unmeasured fields, output protection, non-overwrite behavior, symlinked parent protection and CLI behavior without native tools on PATH. Collector smoke checks parsed stdout and a new ignored JSON file and confirmed overwrite rejection. Coordinator reran the seven tests before `7848029` acceptance. This remains historical tooling evidence.

Future updates must attach integrated SHA and actual review/check evidence. Delegation, fixtures and software microbenchmarks do not close native or physical phase gates.

## Windows IPC peer checks delivery, 2026-11-17

Bounded implementation delivered against inspected HEAD `ff80d16c4a3d5cbcb9fa24b4388787ab4a202b53`. Only `crates/kvm-agent-ipc/src/windows.rs`, its Windows dependency features and this ledger changed. No commits or branches were created. The independent GLM API lane remains in progress and was not edited.

Client and server query the named-pipe peer PID, open the process with limited query access, query its token user SID and Windows session, and require both to match the current process. Unknown PID, native query errors and mismatches fail closed. SYSTEM has no peer-validation exception for this per-user agent, although the existing creation DACL still includes SYSTEM. Owned process/token handles and LocalAlloc buffers have narrow RAII lifetimes and explicit unsafe safety comments. The first token-size query now requires ERROR_INSUFFICIENT_BUFFER and preserves other native errors.

Both sides use one deterministic endpoint-name helper containing account SID, Windows session ID and validated channel. The async client connector accepts a caller timeout, retries only ERROR_FILE_NOT_FOUND and ERROR_PIPE_BUSY, retains Tokio's default identification SQOS, and validates the server immediately after opening, before returning the stream. It sends no messages. Its deadline bounds retry waits and checks expiration around native calls; synchronous Windows identity/open calls cannot be preempted by the async timer. Server rejection disconnects the client and retains terminal poison behavior. Cancellation and existing connection admission/rotation behavior remain covered.

Actual native Windows validation passed 12 tests, strict all-target clippy, and the macOS cfg/type check below. The initial shared-workspace command `cargo test --locked --offline -p kvm-agent-ipc --all-targets` stopped before compilation because Cargo required a lockfile update with the concurrent untracked API member present. To preserve ownership and leave the shared lockfile untouched, validation copied the exact IPC crate, root workspace manifest/lints and starting lockfile to `C:\Users\jordr\AppData\Local\Temp\kvm-ipc-validation-66c31927a0394efe971f1cb602f5d184`. Its initial `cargo test --offline --manifest-path <copy>/Cargo.toml -p kvm-agent-ipc --all-targets` resolved that copy's lockfile and passed. Strict clippy initially found three numeric cast warnings; these were fixed before the final successful commands:

```powershell
cargo fmt -p kvm-agent-ipc
cargo test --locked --offline --manifest-path C:\Users\jordr\AppData\Local\Temp\kvm-ipc-validation-66c31927a0394efe971f1cb602f5d184/Cargo.toml -p kvm-agent-ipc --all-targets
cargo clippy --locked --offline --manifest-path C:\Users\jordr\AppData\Local\Temp\kvm-ipc-validation-66c31927a0394efe971f1cb602f5d184/Cargo.toml -p kvm-agent-ipc --all-targets -- -D warnings
cargo check --locked --offline --manifest-path C:\Users\jordr\AppData\Local\Temp\kvm-ipc-validation-66c31927a0394efe971f1cb602f5d184/Cargo.toml -p kvm-agent-ipc --target aarch64-apple-darwin --tests
```

Tests include real current-user/current-session client/server bidirectional frame exchange, collision rejection, missing/busy connector timeout and delayed availability, identity query error propagation, zero PID rejection, mismatched SID/session helpers, endpoint session separation, and native server-rejection disconnect/poison behavior using an intentionally mismatched expected session. Those mismatch cases do not establish second-user, other-session process or LowIL coverage. No users were created, privileges changed or capture launched. The macOS check compiled types/tests only; it did not run on macOS.

Review and integrated workspace rerun remain coordinator work. Signed application identity and exclusion of malicious same-user/same-session processes are not provided. Read-back owner/ACL/label checks, second-user/LowIL and remote adversarial tests, approved integrity/logon policy, protocol authorization/deadlines, installed agent lifecycle and all native capture/injection and physical performance acceptance remain open. No agent command, send success or native input delivery is claimed by this endpoint work.

## Rebuild check scripts checkpoint, 2026-11-17

This checkpoint supersedes the earlier pending delivery/review wording for code now accepted in `08dac0e`, `6ccda8d` and `19f54d8`. Earlier Sol ledger entries and benchmark identities above remain historical evidence. `6ccda8d` contains Windows client/server SID and session validation and endpoint namespacing. `19f54d8` contains the validated Unix client connector. The protected Unix directory and same-UID checks establish a user boundary, not signed application identity. Windows SID/session matching likewise does not exclude malicious processes in the same user/session.

New bounded tooling is delivered in `scripts/check-rebuild.ps1` and `scripts/check-rebuild.sh`. It needs existing Cargo/rustup, rustfmt and clippy, with no script dependencies. Default checks select only `kvm-foundation`, `kvm-agent-model` and `kvm-agent-ipc`: package-focused format checking, locked offline library/integration tests and strict all-target clippy. Tests deliberately omit custom benchmark targets. The scripts stop at the first failing command and reject unknown options. Rustup automatic installation is disabled for their duration. Missing tools/components or unavailable locked offline dependencies fail without installation.

Run from any directory, including paths with spaces:

```powershell
& 'C:\dev\oss-software-kvm\scripts\check-rebuild.ps1'
& 'C:\dev\oss-software-kvm\scripts\check-rebuild.ps1' -MacOS
```

```sh
sh /path/to/oss-software-kvm/scripts/check-rebuild.sh
sh /path/to/oss-software-kvm/scripts/check-rebuild.sh --macos
```

`-MacOS` / `--macos` runs strict all-target clippy for each installed Apple target, or reports an explicit skip. It never installs targets or executes macOS code. `-Panel` / `--panel` explicitly selects existing frontend test/build commands and requires prepared npm dependencies. `-Tauri` / `--tauri` independently selects fmt, locked offline library/integration tests and strict all-target clippy for `apps/control-panel/src-tauri/Cargo.toml`, which is outside the root workspace. Neither optional panel lane was run in this increment. No command launches capture, an application, a server or benchmarks, or changes configuration.

Actual root-workspace script verification in this increment:

- Windows `powershell -NoProfile -File scripts/check-rebuild.ps1 -MacOS` passed focused fmt, IPC 12, model 14, foundation 23 unit tests and one allocator integration test, strict host all-target clippy and strict Apple Silicon all-target cross-clippy. Cargo emitted a nonfatal incremental-cache access-denied note during test compilation; the checks completed successfully.
- Ubuntu WSL `sh /mnt/c/dev/oss-software-kvm/scripts/check-rebuild.sh --macos` passed focused fmt, IPC 9, model 14, foundation 23 unit tests and one allocator integration test, and strict Linux all-target clippy. This is a newly observed Linux clippy pass, independent of the rerun pending at assignment. No Apple target was installed, so that option reported a skip.
- Windows help and unknown-option rejection and POSIX unknown-option rejection were exercised. POSIX syntax and help were checked separately. Core checks resolve the repository from the script location, not the caller's directory.

WSL used only existing isolated `CARGO_HOME=target/wsl-tools/cargo`, `RUSTUP_HOME=target/wsl-tools/rustup` and `CARGO_TARGET_DIR=target/wsl-check`, with absolute `/mnt/c/dev/oss-software-kvm/` prefixes and its Cargo bin directory on PATH. Bootstrap/check helpers and toolchains under ignored `target` are local validation artifacts, not shipped tooling. Windows Rust 1.97.1 and Linux Rust 1.100.0 differ. These correctness checks are not controlled same-toolchain performance comparisons, and no benchmarks were run.

GLM API task `214f83f0` remains in progress and unaccepted, with Opus review required. Its untracked crate and possible shared uncommitted `Cargo.lock` entry were not edited or staged by this lane. No commits, branches, manifests, lockfiles, application code or UI were changed by this increment.

Remaining gates include macOS execution, agent-command integration, native capture/injection, hardware latency/release/energy/resource measurement, adversarial endpoint policy tests, signed application identity, installed lifecycle and release acceptance. These scripts provide no physical or native input certification. Earlier metadata collector and lifecycle benchmark work remains delivered with its recorded scope and limitations.
