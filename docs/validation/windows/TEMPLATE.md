# Windows Milestone 02 validation — YYYY-MM-DD — MACHINE

## Result

- Observation milestone recommendation: `accept` / `do not accept`
- Suppression recommendation: `not evaluated; remains disabled`
- Summary:

## Baseline

- Repository commit:
- Branch:
- Windows edition and build (`winver`):
- Architecture:
- `rustc -vV`:
- Execution integrity: standard user / elevated (explain why):
- Host manufacturer/model:

## Hardware

| Role | Manufacturer/model | Connection | Notes |
| --- | --- | --- | --- |
| Keyboard | | | |
| Pointer | | | |
| Display | | | resolution/scaling |

Do not record serial numbers or other unnecessary unique hardware identifiers.

## Automated gate

| Command | Exit status | Summary |
| --- | --- | --- |
| `cargo fmt --all --check` | | |
| `cargo test --workspace --all-targets` | | |
| `cargo clippy --workspace --all-targets -- -D warnings` | | |

## Capability and inventory

| Check | Result | Notes |
| --- | --- | --- |
| `probe` | | |
| `devices` | | |
| `displays` | | |

## Device identity

Use shortened/non-sensitive application `DeviceId` values only when needed to compare rows.

| Device | Initial | After reconnect | Other USB port | After reboot | Assessment |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

## Observation categories

| Device/test | Keys | Relative motion | Buttons | Vertical wheel | Horizontal wheel | Local input preserved |
| --- | --- | --- | --- | --- | --- | --- |
| | | | | | | |

## Classification

| Classification | Count/observed | Assessment |
| --- | --- | --- |
| `Physical` | | Only valid if native evidence proves it |
| `InjectedByKvm` | | Deferred unless an approved probe exists |
| `Unknown` | | Expected for ordinary untagged Windows Raw Input |

## Lifecycle

| Scenario | Result | Shutdown time | Fresh restart succeeded | Notes |
| --- | --- | --- | --- | --- |
| 20 short cycles | | | | |
| Ctrl+C | | | | |
| Device removal during capture | | | | |
| Sleep/wake | | | | |

## Load and capture health

- Test duration and input load:
- Captured/delivered counters:
- Motion/scroll drops:
- Untranslated events:
- Callback panics:
- Ignored suppression requests:
- Transition discontinuities:
- Observed behavior after a discontinuity:

## Displays

| Display | Logical bounds | Pixel bounds | Scale | Primary | Notes |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

## Privacy review

- Default redacted output used: yes / no
- `--show-payload` used: yes / no
- Raw logs committed: no
- Report checked for physical key values, serial numbers, credentials, and secrets: yes / no

## Defects and changes

For each defect, record reproduction, expected behavior, actual behavior, safety impact, tests, and
the files changed. Write `none` if this is an evidence-only result.

## Deferred checks

- KVM-tag preservation through Raw Input:
- UIPI/integrity-boundary injection:
- Raw Input to suppressible-event correlation:
- Selective suppression:

These checks remain deferred unless a later reviewed specification explicitly authorizes them.

## Conclusion

State whether Windows observation-only capture meets Milestone 02, list blockers, and explain any
follow-up requested from the primary agent. Do not infer that observation acceptance approves
suppression or an operational KVM.
