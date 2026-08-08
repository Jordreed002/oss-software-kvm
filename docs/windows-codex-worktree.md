# Windows Codex worktree handoff

This runbook splits the next phase between the primary macOS checkout and a dedicated Windows 11
hardware checkout. The two agents work from separate branches and do not edit the same files.

The Windows lane is an observation-only hardware-validation lane. It does not authorize input
suppression, hooks, filter drivers, routing of captured input, or new injection experiments.

## Gate 0: publish the shared baseline

Do not start the Windows agent from the current remote `main` until the complete Milestone 02
workspace has been committed and pushed. A Git clone or worktree can only start from content that
exists in a commit.

From the primary checkout on macOS:

```sh
git status --short
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Review the pending files, create the baseline commit, and push it only after the repository owner
approves those Git operations. Record its commit SHA:

```sh
git rev-parse HEAD
```

The Windows branch must use that SHA, or a later reviewed commit containing it, as its starting
point.

## Work split

| Lane | Owns | Must not change |
| --- | --- | --- |
| Primary macOS checkout | macOS physical evidence; shared protocol, security, network, daemon, tests, CI, and milestone planning; review and integration of the Windows result | `crates/kvm-windows/**`, Windows-specific parts of `crates/kvm-diagnostics/**`, or Windows evidence while the Windows agent is active |
| Windows hardware worktree | Physical Windows 11 observation and lifecycle evidence; reproducible Windows-only fixes; Windows validation report | Shared crates and APIs, root workspace files, lockfile, specifications, CI, macOS code, suppression, routing, or transport/security design |

The primary lane can continue work that does not depend on unproven suppression:

1. Run and document the equivalent macOS observation-only acceptance pass.
2. Specify and build the next platform-neutral secure-transport composition around the existing
   authenticated `SecurePeerConnector` boundary, using simulated/test credentials first.
3. Extend daemon/network/security integration tests for admission, disconnect reconciliation, and
   pressed-state release without connecting native capture to remote routing.
4. Review the two physical-host reports and make a separate go/no-go decision about whether a
   suppression feasibility milestone may even be designed.

Neither lane may claim an operational KVM during this phase.

## Prepare the Windows machine

Install these prerequisites before starting Codex:

- Windows 11 with all normal updates applied;
- Git for Windows;
- Rustup using the MSVC host toolchain;
- Visual Studio Build Tools with the **Desktop development with C++** workload;
- Codex in the ChatGPT desktop app, the Codex IDE extension, or the Codex CLI.

Open a normal, non-administrator PowerShell terminal. Elevated execution is not required for the
observation pass and would make the initial evidence less representative.

Clone the reviewed baseline if the repository is not already present:

```powershell
Set-Location C:\dev
git clone https://github.com/Jordreed002/oss-software-kvm.git
Set-Location .\oss-software-kvm
git fetch origin --prune
git switch main
git pull --ff-only
git rev-parse HEAD
```

Compare the printed SHA with the baseline SHA recorded on macOS. Stop if the expected Milestone 02
files are absent.

## Create the separate worktree

The explicit Git workflow below creates a long-lived, named branch and makes the handoff easy to
review. From the Windows clone:

```powershell
git status --short
git worktree list
git worktree add ..\oss-software-kvm-windows-hw -b codex/windows-m02-hardware origin/main
Set-Location ..\oss-software-kvm-windows-hw
git status --short
git branch --show-current
git rev-parse HEAD
```

If `codex/windows-m02-hardware` already exists locally, use it without `-b`:

```powershell
git worktree add ..\oss-software-kvm-windows-hw codex/windows-m02-hardware
```

Git does not allow the same branch to be checked out in two worktrees. Do not switch the original
Windows clone to `codex/windows-m02-hardware` while the hardware worktree owns it.

The ChatGPT desktop app can also create a Codex-managed worktree by selecting **Worktree** when
starting the chat and choosing the reviewed baseline branch. For this validation, prefer a
permanent worktree or immediately use **Create branch here**, because the result needs to survive
reboots and carry a named evidence branch. OpenAI's worktree documentation is at
<https://developers.openai.com/codex/app/worktrees>.

Whichever method is used, start the new Codex session with
`C:\dev\oss-software-kvm-windows-hw` as its workspace. Do not point it at the original clone.

## Establish the native baseline

Run these commands in the worktree before asking the agent to change anything:

```powershell
rustup show
rustc -vV
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

If the baseline fails, save the exact error and ask the agent to diagnose it. It may fix a
Windows-only issue inside its ownership boundary, but it must not broaden its scope merely to make
the command green.

## Prompt for the Windows Codex agent

Paste the following prompt into the separate Codex session:

```text
You are the Windows hardware-validation agent for OSS Software KVM. You are working in the
codex/windows-m02-hardware branch in a dedicated Windows 11 Git worktree.

First, read these files completely before making changes:
- .spec/spec.md
- .spec/implementation.md
- .spec/milestone-02-capture-transport.md
- docs/windows-codex-worktree.md
- docs/platform-notes.md
- docs/testing.md
- crates/kvm-windows/README.md
- crates/kvm-diagnostics/README.md
- docs/validation/windows/TEMPLATE.md

Your objective is to complete the physical Windows 11 acceptance evidence for Milestone 02 and
fix only reproducible Windows-native defects that prevent that evidence from being collected.

Your write scope is:
- crates/kvm-windows/**
- Windows-specific code/tests in crates/kvm-diagnostics/**, only when necessary
- one new report under docs/validation/windows/** copied from TEMPLATE.md

Do not edit Cargo.toml at the workspace root, Cargo.lock, .spec/**, .github/**, shared crates,
macOS code, or shared documentation. If a shared API or dependency change appears necessary, stop
and report the proposed change to the primary agent instead of making it.

Safety rules:
- Keep capture observation-only and keep every callback result AllowLocal.
- Never add or enable RIDEV_NOLEGACY, low-level suppression hooks, device disabling, filter
  drivers, timing-only Raw Input/hook correlation, or remote routing of captured input.
- Never reinterpret ordinary untagged Raw Input as Physical. The current safe expectation is
  Unknown unless native evidence proves otherwise; the exact KVM marker is InjectedByKvm.
- Do not improvise a SendInput/tag experiment. The diagnostics runner does not inject. Record that
  test as deferred unless the primary agent separately approves a reviewed, non-suppressing probe.
- If local keyboard or pointer behavior is interrupted, stop the command immediately, preserve
  the failure evidence, and make no further native changes until the primary agent reviews it.
- Do not include --show-payload output, physical key values, secrets, or raw event logs in Git.

Begin with read-only inspection and the full native baseline. Then execute the validation matrix
in docs/windows-codex-worktree.md. Use the redacted default diagnostics output. Summarize results
in docs/validation/windows/YYYY-MM-DD-<machine>.md; do not commit raw transcripts.

If you find a defect, reproduce it, add a focused regression test where practical, make the
smallest Windows-only fix, and rerun format, workspace tests, and strict Clippy. Treat queue
transition discontinuity and bounded shutdown errors as explicit safety outcomes, not conditions
to hide or retry silently.

Finish by reporting:
- exact commit SHA and Windows build;
- commands run and their exit status;
- evidence report path;
- files changed;
- tests and Clippy results;
- unresolved hardware, lifecycle, identity, classification, or privacy issues;
- whether you recommend accepting only the observation milestone (never suppression).

Do not push, merge, rebase, or open a pull request unless the repository owner explicitly asks.
```

## Windows validation matrix

Use default redacted output. Store conclusions in the report template, not full console logs.

### 1. Capability and inventory

```powershell
cargo run -p kvm-diagnostics -- probe
cargo run -p kvm-diagnostics -- devices
cargo run -p kvm-diagnostics -- displays
```

Record the Windows build, host model, monitor layout and scaling, and each attached input device.
Device IDs are application identifiers, not security identities.

### 2. Basic observation

```powershell
cargo run -p kvm-diagnostics -- observe --duration-seconds 30
cargo run -p kvm-diagnostics -- all --duration-seconds 30
```

During separate runs, exercise:

- built-in and external keyboards, including press and release;
- relative mouse movement and all available buttons;
- vertical and horizontal wheel input;
- each connected pointing device independently.

Confirm that all input continues to affect the local Windows desktop. Ordinary untagged Raw Input
is expected to remain `Unknown`; do not treat that conservative result as a defect.

### 3. Identity and hot-plug

Capture the device inventory, disconnect and reconnect one external device, then capture it again.
Repeat after moving a USB device to another port if available. Record whether the ID is stable and
whether arrival/removal is observed. A path change may legitimately change an ID; report it rather
than masking it.

After saving the report, reboot Windows, reopen the same worktree and Codex session, and repeat the
inventory. Compare IDs before and after reboot.

### 4. Lifecycle and recovery

Run repeated short start/stop cycles:

```powershell
1..20 | ForEach-Object {
    cargo run --quiet -p kvm-diagnostics -- observe --duration-seconds 1
    if ($LASTEXITCODE -ne 0) { throw "diagnostics iteration $_ failed" }
}
```

Also test Ctrl+C during a 30-second observation, device removal during observation, and one
sleep/wake cycle. Record shutdown time, nonzero exits, stale ownership errors, and whether a fresh
run can start cleanly afterward.

### 5. Load and queue behavior

With redacted output, exercise the highest-report-rate mouse available for 30 seconds while also
pressing and releasing keys and buttons. Record capture counters and any discontinuity. Motion and
scroll drops may be counted under pressure. A key/button transition admission failure must produce
an explicit terminal discontinuity; it must never be silently hidden.

### 6. Display evidence

Run `displays` with the real multi-monitor layout and record logical bounds, pixel bounds, primary
display, and scaling. Repeat after a safe layout or scaling change if practical. Do not change the
shared topology model from this branch.

### 7. Final native gate

```powershell
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
git diff --check
git status --short
git diff --stat origin/main...HEAD
```

An evidence-only branch is a successful outcome when implementation changes are unnecessary.

## Handoff to the primary agent

The Windows agent should leave a clean, reviewable commit on
`codex/windows-m02-hardware`. Before any push, it must show the repository owner:

```powershell
git status --short
git log --oneline origin/main..HEAD
git diff --stat origin/main...HEAD
```

After the owner authorizes publication:

```powershell
git push -u origin codex/windows-m02-hardware
```

The primary agent reviews the branch without editing the Windows evidence in parallel. Acceptance
of the observation milestone requires both physical-host reports plus the automated gates. It does
not automatically approve selective suppression; that requires a new, explicitly reviewed spec.
