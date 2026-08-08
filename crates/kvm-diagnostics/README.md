# Native diagnostics runner

`kvm-diagnostics` is a read-only evidence collector for Milestone 02. It probes native
capabilities, enumerates input devices and displays, and observes device-attributed input for a
bounded duration. The capture callback always returns `AllowLocal`; this tool never suppresses,
seizes, injects, routes, or writes configuration.

By default, observation output contains only event classification, stable device ID, payload
category, sequence/timing metadata, and counters. It does not print physical key codes, button
states, pointer deltas, clipboard data, credentials, or secrets. `--show-payload` is an explicit
privacy-sensitive opt-in that reveals physical key codes, button states, and motion values.

## Windows 11

Run from PowerShell in the repository root:

```powershell
cargo run -p kvm-diagnostics -- probe
cargo run -p kvm-diagnostics -- devices
cargo run -p kvm-diagnostics -- displays
cargo run -p kvm-diagnostics -- observe --duration-seconds 30
cargo run -p kvm-diagnostics -- all --duration-seconds 30
```

To deliberately include detailed payload values:

```powershell
cargo run -p kvm-diagnostics -- observe --duration-seconds 30 --show-payload
```

## macOS

Run from Terminal in the repository root. Grant Input Monitoring to the terminal application (or
the built binary) in **System Settings > Privacy & Security > Input Monitoring**. Accessibility is
reported separately and is not required for this observation-only command.

```sh
cargo run -p kvm-diagnostics -- probe
cargo run -p kvm-diagnostics -- devices
cargo run -p kvm-diagnostics -- displays
cargo run -p kvm-diagnostics -- observe --duration-seconds 30
cargo run -p kvm-diagnostics -- all --duration-seconds 30
```

To deliberately include detailed payload values:

```sh
cargo run -p kvm-diagnostics -- observe --duration-seconds 30 --show-payload
```

The observation duration must be 1 through 300 seconds. Normal completion calls the backend's
bounded `stop_capture` lifecycle. A native start, enumeration, permission, or teardown error is
printed to stderr and exits nonzero. Other operating systems receive an explicit unsupported-host
error and a nonzero exit status.

## Physical-host evidence checklist

Record the command, OS build, hardware model, and whether each run succeeded. Do not publish
`--show-payload` logs without reviewing them first.

- Capture device IDs before and after disconnect/reconnect and reboot.
- Identify built-in and external keyboards, mice, and trackpads.
- Exercise key, relative pointer, button, vertical-wheel, and horizontal-wheel categories.
- Confirm all physical input continues to affect the local machine during observation.
- Record `physical`, `injected_by_kvm`, and `unknown` classification counts.
- In a controlled test, inject KVM-tagged events and record whether the capture API observes them.
- Deny and revoke permissions, then record diagnostics and exit status.
- Record native delivered/captured, dropped, untranslated, panic, and ignored-suppression counters.
- Record idle CPU usage and callback-to-observer latency under load with OS-native profiling tools.
- Exercise device arrival/removal and sleep/wake, checking shutdown remains bounded.

Never infer device identity by matching timestamps from unrelated native APIs. Selective
suppression remains outside this tool and outside Milestone 02.
