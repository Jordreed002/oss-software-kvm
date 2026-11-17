# Rebuild implementation progress

Evidence checkpoint: 2026-11-17. This ledger records delivered work and acceptance evidence. It does not estimate completion percentages or close physical gates from software checks.

## Current acceptance checkpoint, 2026-11-17

The benchmark review and its corrections are complete. Commit `4c392ec` accepts the bounded input microbenchmark implementation after coordinator-owned Opus review. The corrected optimized run and strict all-target clippy passed. Best-case occupancy and head-stage-only engine scope are labelled, short fault batches carry a timer-quantization caveat, and the wraparound assertion uses the total warmup-plus-sample count. The measurements documented below retain their original `eb40c9b` dirty-run identity; no physical gate or numerical release budget is accepted. The development utility remains accepted at `eb40c9b` with live desktop validation outstanding. Windows is available now; Mac physical validation waits for later availability.

## Pre-review checkpoint at eb40c9b, 2026-11-17

This checkpoint supersedes earlier cancelled or pending-clarification status for UI integration and queue benchmarking only. The user explicitly resumed both lanes. Windows is available now; Mac access is planned later for physical validation. Earlier native Mac software tests and process smoke remain valid historical evidence for their recorded revisions. They do not establish current Mac availability or access to two physical hosts.

Git inspection for this update found branch `overhaul/widget-app-planning` and HEAD `eb40c9bc5c4faa4d61090060aecd815ba6a7fd11`. Before these documentation edits, only `crates/kvm-input-engine/Cargo.toml` was modified and `crates/kvm-input-engine/benches/` was untracked. The benchmark source is `benches/input_path.rs`; these benchmark changes remain unaccepted. Commit `207c911` accepted the standalone input engine; `eb40c9b` accepts the Opus development-only read-only utility-agent UI.

| Lane | Current status and scope | Remaining evidence |
| --- | --- | --- |
| Read-only agent UI integration | Accepted in `eb40c9b` as an opt-in development integration. Root independently passed TypeScript checking, 122 frontend tests, production build, 33 Tauri library tests and strict all-target Tauri clippy on Windows. | No browser, native GUI launch, live Tauri window roundtrip or Mac UI compilation/execution validation. Tray state, single instance and installed lifecycle remain unfinished. |
| Bounded queue microbenchmark | GLM delivery changes only the benchmark source and manifest. Root independently ran the locked offline input-path benchmark, 38 focused tests and strict all-target clippy successfully. | Coordinator-owned Opus review `62489094` is pending; delivery and successful checks do not accept the benchmark. |
| Bounded input admission | Accepted in `207c911`; focused tests pass 38 cases each on Windows and Linux. | No native Mac input-engine execution, running-agent integration or physical/performance certification. |
| Native identity storage | Separate delegation remains cancelled. Only `docs/adr/0005-native-identity-storage.md` defines the contract. | No identity-storage implementation or native credential access is delivered. The user's resumption does not include this lane. |

The root benchmark evidence is ignored local storage at `target/performance/input-path-65688360949d4d01871cbe3ea43018f6/{metadata.json,raw.txt}`. Metadata records the full HEAD above, dirty state and collection time `2026-11-17T09:24:44.419Z`. Exact identity, commands, operation units and unchanged raw summary are recorded in `performance-baseline.md`. Each scenario uses three warmup batches and 30 measured whole batches. Pair operations count both calls as one operation. The 512-operation fault batches have typical durations of only 7-10 QPC ticks and are coarse measurements. This is one unpinned Windows run, with no accepted numerical budgets, per-event tail evidence or speedup conclusion. Historical GLM-reported results are separate evidence and are not replaced by the root run.

Recorded coordinator checks for the accepted input-engine source remain `scripts/check-rebuild.ps1 -MacOS` with 147 Windows tests, focused formatting, strict host clippy and Apple Silicon cross-clippy, and `scripts/check-rebuild.sh` with 148 Linux tests, formatting and strict all-target clippy. Apple cross-clippy does not execute native Mac tests. This documentation task read git, artifacts and source and reran no tests, builds or benchmarks.

Windows is available now; Mac physical access is planned later. No physical gate is closed. Native capture/injection, authenticated two-host sharing, installed lifecycle and physical latency, release, resource and energy acceptance remain open.

## Historical checkpoints

The sections below preserve the earlier delivery sequence. Their then-current status, HEAD and dirty-state descriptions are historical; the checkpoint above governs current lane ownership and availability.

## Approval and base

The user approved a ground-up Rust rebuild with selective reuse and performance as a primary requirement. ADR `docs/adr/0003-ground-up-rebuild.md` records the accepted direction and ownership. Acceptance supersedes older proposed/planning status text in the recommendation and strategy documents.

Observed branch: `overhaul/widget-app-planning`. Current inspected HEAD: `b993c2d816b42cae7076545f57195dd59580074a`, which corrects the API bootstrap and safety-command contract. Planning comparison base remains `code-review-remediation` at `9edb5ed`. The earlier checkpoint inspected `5b1688cbc95af3b23b25fbe5dde48236555def35` and recorded only this ledger and `performance-baseline.md` as dirty then. Current git status has modified `Cargo.lock`, Unix IPC source and this ledger, plus untracked API, macOS ACL and agent code. This tracking task edits only this ledger and makes no commits or branch changes.

## Current work lanes

| Lane | Status | Evidence and remaining acceptance |
| --- | --- | --- |
| Sol baseline tooling and progress tracking | Tooling accepted in `7848029`; current lifecycle benchmark integrated in `84b974d` | Earlier collector verification passed seven tests and stdout/file smoke checks. One fresh optimized Cargo benchmark run passed here; exact identity, command and raw batch summary are in `performance-baseline.md`. Tracking edits remain uncommitted. |
| GLM 5.3 Rust foundation | Accepted in `f4ddbf3` after review and coordinator corrections | GLM delivery was conditionally accepted with one `unused_self` lint. Coordinator added the exact allow, redacted debug payloads, corrected the layout doc and added a counting allocator integration test with a positive control. Coordinator reports foundation 17 unit tests plus one integration test and clippy passing. This establishes bounded foundation evidence, not native fast-path acceptance. |
| Opus UI implementation | Development UI accepted in `ef7b213` | Coordinator reports `npm test` with 82 passing tests and `npm run build` passing. No browser or native validation. |
| Lifecycle model | Fixes accepted in `b660e2e`; Opus review `00e5c53c` accepted lifecycle | Fixes follow the Opus high cancellation finding. Current API includes `new(instance: u128)`, `CancelPrepare`, `DrainTicket` and `retry_cleanup`. Coordinator reports 12 tests and clippy passing. |
| GLM new API | Review candidate `214f83f0` complete; corrections `01afd013` active | Frozen GLM API review rejected B1, H1 and H2. HEAD `b993c2d` corrects the contract; implementation remains unaccepted and mandatory Opus delta review remains outstanding. See the dated coordinator checkpoint below. |
| Unix canonical paths and macOS ACLs | Uncommitted; Opus review `45236d86` active | Coordinator Windows/WSL checks passed as recorded below. Native macOS ACL execution and review acceptance remain outstanding. |
| Native agent and hardware performance | Uncommitted library-only idle read-only owner; physical metrics unmeasured | `crates/kvm-agent` is not a running agent or integrated UI. Its API dependency is unaccepted. No capture/injection adapters, installed lifecycle or physical latency, jitter, release, energy or native resource acceptance established by this evidence. |

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
| 2. Agent and control plane | Reviewed pure lifecycle model accepted; API corrections active after rejected review. Uncommitted library-only idle owner exists; no running agent or UI integration. | Corrected API acceptance after mandatory Opus delta review, runtime status, authority, identity/enrollment, topology/configuration, confirmed native outcomes and contention evidence. |
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

At that script checkpoint, GLM API task `214f83f0` was recorded as in progress and unaccepted, with Opus review required. That status is historical: the review candidate is now complete and corrections are underway, as recorded below. Its untracked crate and possible shared uncommitted `Cargo.lock` entry were not edited or staged by that lane. No commits, branches, manifests, lockfiles, application code or UI were changed by that increment.

Remaining gates include macOS execution, agent-command integration, native capture/injection, hardware latency/release/energy/resource measurement, adversarial endpoint policy tests, signed application identity, installed lifecycle and release acceptance. These scripts provide no physical or native input certification. Earlier metadata collector and lifecycle benchmark work remains delivered with its recorded scope and limitations.

## Unix ancestor and Darwin ACL delivery, 2026-11-17

Coordinator acceptance includes `d745128`, the asynchronous Unix bind with lifetime flock and confirmed stale recovery, and `035c768`, the rebuild scripts with actual root Windows and WSL checks passing. This bounded increment was checked at workspace HEAD `a9bf492de4130d7099974a5fd880e0db9ed890b6`. API work still requires Opus review and is not accepted by this delivery.

Only `crates/kvm-agent-ipc/src/unix.rs`, its new `unix/macos_acl.rs` module and this ledger were edited here. The pre-existing modified `Cargo.lock` and untracked API crate were left untouched. No commits, branches, users, system permissions or UI changes were made.

Bind and connect require an absolute directory, reject parent traversal and direct directory symlinks, including trailing-separator spellings, and canonicalize its parent once. They validate canonical ancestors from root before creating or using the runtime directory. Every ancestor must be owned by root or the effective UID; group/other write requires the sticky bit and that same trusted ownership. System ancestor aliases such as `/var` are resolved, then subsequent socket, lock and Drop operations use the canonical absolute path. The immediate directory must be user-owned mode 0700. Existing lifetime lock acquisition, stale-probe await, held-connection admission and cancellation ordering are preserved.

On macOS, the directory, socket and existing stale socket reject every extended ACL entry. The lock ACL is checked through its open file descriptor. Canonical ancestors permit empty or deny-only ACLs and reject every allow or unknown tag, including read-only or inherit-only allow entries. This conservative policy avoids guessing group membership and does not reject normal deny-only system ACLs. It may reject otherwise safe installations with ancestor allow entries. Retrieval failures, unsupported filesystems and unexpected iterator/tag errors fail closed. A non-null empty ACL is accepted by iterating entries, not by testing allocation presence. Darwin's documented iterator exhaustion is `-1/EINVAL`, including FIRST on an empty OS-returned ACL as confirmed in Apple's implementation. Owned ACL allocations are freed through RAII; narrow FFI declarations, constants and safety comments are confined to the macOS module because the current libc dependency lacks these declarations.

Apple primary sources used for the ABI, constants and behavior:

- [Libc sys/acl.h](https://github.com/apple-oss-distributions/Libc/blob/main/include/sys/acl.h)
- [ACL retrieval manual](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_get.3)
- [ACL entry manual](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_get_entry.3)
- [Darwin ACL iterator implementation](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_entry.c)

Actual final root-workspace validation passed:

- `powershell -NoProfile -File scripts/check-rebuild.ps1 -MacOS`: focused format checks, Windows IPC 12 tests, model 14 tests, foundation 23 unit tests and one allocation integration test, strict host clippy and strict aarch64-apple-darwin all-target cross-clippy. Cargo again emitted a nonfatal Windows incremental-cache access-denied note.
- WSL `/bin/sh target/wsl-tools/check-runner.sh`: the root POSIX rebuild script passed focused format checks, Linux IPC 15 tests, model 14 tests, foundation 23 unit tests and one allocation integration test, and strict Linux all-target clippy. It used existing isolated CARGO_HOME/RUSTUP_HOME beneath ignored `target/wsl-tools` and CARGO_TARGET_DIR beneath `target/wsl-check`. No Apple target was installed in WSL, so its macOS option explicitly skipped.
- `cargo check --locked --offline -p kvm-agent-ipc --target aarch64-apple-darwin --tests` passed on Windows. This compiles the macOS private-fixture test but does not execute it.

Three new Linux-executed tests distinguish nonsticky world-writable ancestor rejection before directory creation, direct directory symlink refusal on bind/connect, and accepted trusted canonical paths with absolute socket cleanup after an ancestor alias is removed. Existing lock collision, stale recovery, replacement-file preservation and cancellation tests still pass. A macOS-gated fixture test removes/adds ACLs only on its own private temporary directory and covers empty, deny-only and allow-entry policy. It has not run on physical macOS. The first Linux clippy run rejected the no-op non-macOS ACL wrapper's Result type; a localized allowance documents its shared fallible macOS contract, and the final complete script passed.

These path and ACL checks are snapshots. They do not pin directory handles or prevent a malicious process with the same UID, or root, from renaming/replacing components between validation and use. Flock coordinates compliant owners only. UID authentication does not establish signed application/code identity. Remaining gates include independent security review, actual macOS ACL execution and adversarial filesystem tests, signed/installed agent identity, API Opus review and command integration, and native input, physical performance and release acceptance.

## Coordinator evidence and next milestone, 2026-11-17

This update preserves the earlier delivery and validation checkpoints above. Current source/git inspection confirms HEAD `b993c2d`, the uncommitted Unix canonical-path/macOS ACL changes, and untracked `crates/kvm-agent-api` and `crates/kvm-agent`. The review outcomes, active task identifiers and rerun results below are supplied coordinator evidence. This documentation task ran no builds or tests and claims no additional acceptance.

The original GLM API task `214f83f0` completed its review candidate. The frozen GLM API review rejected B1 for missing agent instance identity in Hello, H1 for missing explicit protocol errors, and H2 for revision-bound Pause/Failsafe. GLM correction task `01afd013` is active. HEAD `b993c2d` corrects the contract, including Hello bootstrap identity, explicit protocol errors and safety commands without revision preconditions. A contract correction does not accept the implementation. Mandatory Opus delta review remains outstanding.

Opus review `45236d86` is active for Sol's uncommitted Unix canonical-path and macOS ACL changes. The coordinator independently reran:

- `scripts/check-rebuild.ps1 -MacOS`: Windows IPC 14, model 14, foundation 23 unit tests and one allocator integration test passed, along with strict host clippy and strict Apple Silicon cross-clippy.
- `target/wsl-tools/check.sh`: Linux IPC 15, model 14, foundation 23 unit tests and one allocator integration test passed, along with strict Linux clippy.

These are later coordinator reruns, distinct from the earlier commands and Windows IPC counts retained above. Cross-clippy does not execute macOS code. Native macOS ACL checks have never been executed.

The new uncommitted `crates/kvm-agent` contains a library-only idle read-only owner. Source inspection shows process-owned lifecycle state and read-only snapshots with unconfirmed prerequisites and unsupported mutation capabilities. It is not a running agent and has no integrated UI. Its dependency on the draft API is not accepted, and this checkpoint claims no agent tests or runtime acceptance.

The next concrete milestone is runtime status after the corrected API passes mandatory Opus delta review. That requires adapting the idle owner to the accepted contract and demonstrating runtime Hello/bootstrap and read-only status before UI integration acceptance. Full rebuild completion, performance acceptance, native input acceptance, macOS execution and installed release acceptance remain open.

### Coordinator process-host draft, 2026-11-17

After Sol's progress refresh, the uncommitted `kvm-agent` crate gained a development `serve` binary. It owns a single-thread Tokio runtime, serves one verified native connection at a time with a two-second total connection budget, handles Ctrl+C, and bounds endpoint recovery attempts. Unix takes an explicit absolute runtime directory; Windows uses the session-scoped control channel. It starts no input capture, injection, discovery or legacy runtime. This is an unaccepted draft, not an observed running agent or UI integration.

Windows `cargo test --offline -p kvm-agent` passed six library tests. Strict all-target host clippy passed. Apple Silicon all-target cross-clippy passed after downloading the already locked signal dependencies, errno and signal-hook-registry. The first offline cross-check failed because those dependencies were not cached. No macOS binary executed. The API is still undergoing GLM correction and mandatory Opus delta review, so the owner and binary remain uncommitted and will need adaptation and renewed checks against the final contract. The earlier library-only description remains historical evidence of the preceding state.

## Opt-in development agent smoke scripts, 2026-11-17

This checkpoint supersedes the earlier statement that the process host has never run. The owner/API draft remains uncommitted and unaccepted. Mandatory Opus final review `466cb308` is pending. No acceptance or native input readiness follows from a development process smoke.

New `scripts/smoke-agent.ps1` and `scripts/smoke-agent.sh` require explicit `-Run` or `--run`. Both accept an optional existing binary path through `-Binary PATH` or `--binary PATH`; defaults are `target/debug/kvm-agent.exe` and `target/debug/kvm-agent`. They do not install, build, launch capture, launch UI, invoke the legacy runtime, change production configuration or change user permissions. Each starts only its own development `serve` child, waits at most ten seconds for that child's redirected readiness marker, checks child liveness before and after each bounded status invocation, and validates two JSON snapshots with the same non-nil instance UUID, idle lifecycle, paused user intent, unknown input destination and unsupported pause/resume/failsafe/quit capabilities. Snapshot capability must be supported. Nonzero status exits, malformed JSON, unexpected state and deadline expiry fail the smoke.

Windows launches hidden processes with redirected output under a unique ignored `target/smoke-agent-*` artifact directory. Its finally block forcibly terminates only its own live serve process and waits at most five seconds. This is process cleanup, not graceful shutdown evidence. Unix uses existing Python 3 for subprocess deadlines and JSON validation. A dedicated mode-0700 temporary directory supplies TMPDIR to both its server and status clients, isolating the default runtime endpoint. Signal handlers and finally cleanup target its own child PID. The success path sends SIGINT and requires exit zero within five seconds. Failure cleanup can forcibly stop that child and explicitly reports that graceful shutdown was not proved. Cleanup validates the created directory identity and ownership, rejects symlinks and unexpected file types, unlinks only named logs/socket/lock artifacts, and removes directories only when empty. It performs no recursive deletion.

Observed in this script increment:

- Windows `powershell -NoProfile -File scripts/smoke-agent.ps1 -Run` passed two queries against the already-built development binary. The successful instance was `7e1a756c-abc9-410b-be8f-e7a4b96611a3`. Own-process forced cleanup completed. Initial script attempts exposed redirected-log sharing and PowerShell process-handle/exit-code retrieval issues; both were corrected before the pass.
- Windows help and unknown-option rejection passed. WSL `sh -n`, help and unknown-option rejection passed for the POSIX script. No WSL agent binary has been built for this increment, so the POSIX process smoke and SIGINT behavior remain unexecuted. No macOS native execution is claimed.

Supplied coordinator evidence, separate from this script execution: an earlier actual Windows process smoke passed two queries after correcting an assertion that used `input_destination.state` instead of `input_destination.destination`. Windows 43 API tests and 10 agent tests plus strict clippy passed. Apple cross-clippy passed before the latest shape-check additions. WSL 43 API and 10 agent tests passed; Rust 1.100 clippy flagged `assert_is_empty` in an API test, and the coordinator has changed that assertion to `assert_eq`. The coordinator is also correcting array/numeric tag shape guards, a fixture's actual escape, duplicate fixtures and owner-policy wording. Those changes need renewed focused checks and the mandatory review. This script task ran no Cargo builds or Rust tests, and the smoke used the existing binary rather than proving it contains those latest source corrections.

Remaining gates include rebuilding and checking the final reviewed owner/API sources, rerunning the Windows smoke on that rebuilt binary, building and running the Unix smoke, final Opus review and acceptance, native macOS execution, UI integration, installed lifecycle, adversarial endpoint policy and native capture/injection plus physical performance/release acceptance. Earlier evidence remains scoped to its recorded source and platform.

## Accepted read-only agent and native Darwin evidence, 2026-11-17

This checkpoint supersedes the preceding pending API/owner review notes. Final Opus review accepted the API shape corrections and owner/client as a read-only prototype. The typed-first JSON-value equality check rejects serde sequence structs and numeric enum tags; removing the guard made the manifest test fail, and restoring it passed. The escaped fixture now contains a literal Unicode escape and its test checks that fact. Shared duplicate-key fixtures cover nested authority and outcome tags. Protocol error correlation presence is explicitly owner policy; decoded mutations use CommandResult, handshake/snapshot failures use Error.

Committed source is `f0a632102168d5f8203f92772f8b7832bb99565f`, pushed to origin/overhaul/widget-app-planning for version-exact Mac validation. It includes the reviewed GLM API, coordinator idle owner/client and development serve/status binary. Coordinator addressed review follow-ups: missing Windows endpoints return NotFound instead of busy timeout; connection setup has a separate 500 ms budget within the two-second query lifetime; successful accepts/rebinds reset recovery failures; malformed pipelining/repeated Hello close-without-reply behavior is documented. Input capture, injection, pairing, sharing and product UI integration remain unavailable.

The standard rebuild scripts now include foundation, model, IPC, API and agent. Coordinator verification against this committed Rust source plus the script/documentation working changes passed:

- Windows `scripts/check-rebuild.ps1 -MacOS`: 105 tests, focused formatting, strict host and Apple Silicon cross-clippy. `cargo build --locked --offline -p kvm-agent` followed by `scripts/smoke-agent.ps1 -Run` passed two matching-instance status queries, with idle/paused, unknown input and all mutations unsupported. Cleanup forcibly stopped only the script's own process; graceful Windows shutdown is unproved.
- Linux WSL `scripts/check-rebuild.sh`: 106 tests, focused formatting and strict all-target clippy. A locked offline agent build and `scripts/smoke-agent.sh --run --binary target/wsl-check/debug/kvm-agent` passed two matching-instance status queries. The owned serve child exited zero after SIGINT. The temporary endpoint and known artifacts were removed through the script's checked non-recursive cleanup. WSL used its existing isolated Cargo/Rustup homes and target directory; no native input was activated.
- Native Apple Silicon Mac, macOS 27.0.1, Rust/Cargo 1.97.1: 107 tests and strict all-target clippy passed with locked offline dependencies. This included `private_fixture_acl_policy` and `status_roundtrip_uses_verified_native_socket`. Source archive SHA-256 was `10a4db911e41b80759ce0ab903dbe992445ab9e2b5f3b102a4c4e08611ec2fd1`; all 413 source artifact files stayed identical. Canonical socket length was 90 bytes. No dependencies downloaded. The original Mac branch, HEAD, status and four dirty files remained byte-identical. No Mac application or serve binary was launched; native process smoke there is still pending.

The linked environment did not support tool-managed worktree isolation. Validation therefore used a Git archive as immutable scratch test input, without .git metadata or switching the Mac checkout. An initially created remote-tracking ref was removed with an expected-SHA guard before a fetch with ref mapping disabled. This changed no working files.

The software status milestone is now accepted within its stated user/session identity boundary. Remaining work includes the real compact UI connection, rebuilt native input and authenticated peer sessions, topology/enrollment/persistence, installed lifecycle and update/release behavior, stronger endpoint policy tests and physical performance acceptance. These test counts are correctness evidence, not latency, energy or memory measurements. No numeric performance budgets or physical-input certification are claimed.

### Native Mac process smoke, 2026-11-17

The exact `b5284d7ef799ad388d311cac185950c574bad9f6` source artifact also passed a locked offline native Mac agent build and `sh scripts/smoke-agent.sh --run --binary ...`. Readiness and two idle/paused snapshots from one instance passed, then the owned process exited zero after SIGINT. No runtime path or ACL failure occurred. The script was invoked through `sh` without changing its execute permission. Original Mac checkout identity and four dirty-file hashes, plus the immutable archive source, remained unchanged. This closes the development read-only process smoke on macOS; installed lifecycle and physical input/performance remain untested.

### Read-only connection boundary regressions, 2026-11-17

Coordinator added four framed-service regression tests for the limits recorded by Opus: EOF before Hello leaves the owner unchanged, repeated Hello closes with Protocol, exactly eight requests complete after client EOF, and a ninth valid request is rejected without changing the owner. The request-limit tests use real bounded duplex framing and an independent outer timeout; they consume each reply in lockstep before sending the next request. Focused `cargo test --locked --offline -p kvm-agent` now passes 14 tests on Windows, and strict all-target clippy passes. No production behavior changed, and these four new tests have not yet executed on macOS.

ADR 0005 defines a fresh native identity-key storage boundary, but its Sol implementation delegation was cancelled before a task started. No credential-store implementation, native credential access or integration is delivered by that contract. The GLM bounded-input admission task remains separate and unaccepted pending delivery and Opus review. Earlier cancelled UI and benchmark assignments remain stopped pending clarification; none of those contracts or pending tasks closes the full rebuild goal.

### Bounded input admission delivery under coordinator review, 2026-11-17

GLM delivered only `crates/kvm-input-engine/**` and the additive seven-line Cargo.lock package node. The crate has one foundation dependency, fixed-capacity inline storage, route epochs, admission/consumption age checks, finite-delta validation, explicit close/discard and terminal fault latching. No running-agent dependency or sharing capability was added.

Coordinator independently ran locked offline focused tests: 36 passed on Windows and 36 on Linux WSL. Strict all-target clippy passed on both hosts and for the installed Apple Silicon target. These are software checks; no new native Mac execution or physical latency evidence was gathered for this crate. The WSL helper is ignored local validation tooling under target/wsl-tools.

The delivery reported its own Opus reviews despite the task's no-subagents instruction. Coordinator acceptance does not rely on those reported verdicts. A new coordinator-owned Opus review is pending for the actual delivered source. Review includes stale epoch isolation, retained release events, zero/one capacity, expiry before dequeue, replacement-engine generation-floor preconditions and owner identity mapping. The engine's u64 instance identity must not be integrated through silent truncation of the agent's UUID. No source or lockfile acceptance commit has been made yet. Benchmark and native callback publication/suppression work remain outside this delivery.

### Bounded input admission accepted after coordinator review, 2026-11-17

Coordinator-owned Opus review conditionally accepted the delivered runtime behavior with one required documentation correction. Coordinator corrected that condition and the three other factual doc comments, added the two missing cases for zero-capacity consumption before admission and enqueue before activation, and compiled non-test crate code with no_std. Focused input-engine tests now pass 38 cases on Windows and Linux; strict all-target clippy passes on both and on the Apple Silicon cross-target.

The standard rebuild scripts now include kvm-input-engine. Expanded Windows checks pass 147 tests, focused formatting, strict host clippy and Apple Silicon cross-clippy. Expanded Linux checks pass 148 tests, formatting and strict all-target clippy. These checks cover the corrected source. Native macOS execution of the input-engine crate is not yet recorded. No benchmark or physical-input claim follows.

Acceptance is for the standalone bounded admission component only. It is not linked into the running agent and does not implement authentication, native suppression, cross-thread publication, held-input delivery or teardown fences. Owners must use fresh nonzero instance identities, preserve a predecessor generation floor on same-identity replacement, and prohibit concurrent engines with the same instance/peer. Agent UUIDs must not be silently truncated into this crate's u64 identity. At this acceptance checkpoint, the cancelled UI, benchmark and identity-storage assignments were stopped pending clarification. The dated superseding checkpoint above records the later resumption of UI integration and queue benchmarking; identity storage remains cancelled.

## Development utility connected to read-only agent, 2026-11-17

Opus delivered --utility-agent mode under apps/control-panel only. It has its own development route/window, registers only agent_status, rejects callers outside utility-agent, and uses the accepted verified native client once per mount/open or manual refresh. Legacy default and fixture-only --utility-preview remain separate. The DTO preserves unknown authority, emits u64 revisions as strings, uses closed error categories and keeps mutations disabled regardless of advertised capabilities. Request sequencing drops stale or unmounted completions; no polling is introduced.

Coordinator reviewed the native command/mode boundary and status projection, then independently reran TypeScript checking, 122 frontend tests, production build, 33 Tauri library tests and strict all-target Tauri clippy. All passed on Windows. This is acceptance as an opt-in development integration, not a production cutover. No browser, native tray/window launch or round-trip through a live Tauri window was performed; placement, opening/focus behavior and real IPC require desktop validation. Mac UI compilation/execution waits for later availability. Tray icon state, single-instance handling and installed lifecycle remain unfinished. GLM benchmark delivery is now recorded in the superseding checkpoint above; coordinator-owned Opus review `62489094` remains pending and the benchmark is unaccepted.

## Windows native utility baseline observed before redesign, 2026-11-17

Coordinator launched only owned Vite, development readonly agent and --utility-agent processes at source7a401f2. Native window inspection confirmed a real agent-connected view, unknown input location, paused intent, idle session, clear safety,0of6 readiness confirmed and disabled Resume/Quit controls with visible reasons. Initial Vite dependency optimization briefly left the page blank before it rendered. This establishes the first live Windows Tauri-window status round trip for the baseline design, not physical input behavior.

The owned agent was then stopped for an unavailable-state check. The attempted Refresh input was rejected by the automation helper because window bounds changed; after reacquiring bounds the state was observed, but no successful Refresh or disconnected-state transition was verified. No tray reopen, native focus return or unavailable/recovery claim follows. All owned development processes were stopped. No capture/injection or legacy runtime started.

The user supplied a screenshot and requested a Linear-inspired redesign. Opus taskc178e808 owns the presentation redesign, retaining the real status/disabled-action behavior. The current baseline visual acceptance is superseded by that request; new appearance and live behavior require validation after delivery.
