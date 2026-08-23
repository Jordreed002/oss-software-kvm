# Windows hardware validation

Physical validation entries for Windows hosts. Platform-neutral CI **cannot**
validate native input capture, suppression, injection, permissions
(UIPI/secure-desktop boundaries), or end-to-end latency — every claim about
native behavior needs an entry here.

## Workflow

1. Copy [TEMPLATE.md](TEMPLATE.md) to `YYYY-MM-DD-machine-or-run.md`.
2. Run the automated gate (`cargo fmt --all --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace --all-targets`) and record the results.
3. Work through every template section; leave deferred checks deferred unless
   a reviewed specification authorizes them.
4. Record the repository commit, OS build, and hardware without serial numbers
   or other unnecessary unique identifiers.
5. State a recommendation (`accept` / `do not accept`) for the milestone under
   test. Observation acceptance never approves suppression or an operational
   KVM.

## Entries

| Date | Entry | Recommendation |
| ---- | ----- | -------------- |
| 2026-08-08 | [Milestone 02 observation run on MS-7D96](2026-08-08-ms-7d96.md) | `do not accept` (physical matrix incomplete) |
