<!--
Thanks for your contribution! Please read CONTRIBUTING.md before opening this PR.
Keep PRs focused: one logical change per PR. The fail-closed runtime path is sensitive —
call out any behavioral change that affects input capture, suppression, or session safety.
-->

## Summary

<!-- What does this change do, and why? Reference the issue it closes if applicable. -->

Closes #

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Refactor / chore (no behavior change)
- [ ] Docs / spec update
- [ ] Breaking change

## Affected area

<!-- Check the areas this change touches so reviewers know where to focus. -->

- [ ] Platform-neutral crate (e.g. `kvm-input`, `kvm-protocol`, `kvm-router`, `kvm-topology`)
- [ ] Native backend (`kvm-macos`, `kvm-windows`)
- [ ] Runtime / daemon / safety (`kvm-runtime`, `kvm-daemon`)
- [ ] Security / pairing / networking (`kvm-security`, `kvm-network`, `kvm-discovery`)
- [ ] Control panel (`apps/control-panel`)
- [ ] CI / tooling / docs

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace --all-targets` passes
- [ ] New behavior is covered by tests
- [ ] No `unsafe` introduced (the workspace denies `unsafe_code`)
- [ ] Docs / `.spec/` updated where relevant

## Hardware validation (if this touches a native backend or the runtime session pump)

Platform-neutral CI cannot validate native KVM behavior. If this change affects input capture,
suppression, injection, permissions, or the session pump, describe what was tested on real hardware
and what remains to be validated.

- [ ] Validated on physical Windows 11
- [ ] Validated on physical macOS
- [ ] Not applicable — platform-neutral change only

<!-- Notes on what was tested, latency checks, permission prompts, sleep/resume, etc. -->
