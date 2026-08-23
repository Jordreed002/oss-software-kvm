# macOS hardware validation

Physical validation entries for macOS hosts. There are **no entries yet** —
macOS has not had a structured validation run recorded under this directory.

Until an entry exists, treat native macOS behavior (capture, suppression,
injection, permissions, latency) as unvalidated on hardware.

The per-crate physical validation checklist that a macOS entry must satisfy
lives in [crates/kvm-macos/VALIDATION.md](../../../crates/kvm-macos/VALIDATION.md).
When the first macOS run happens, copy the Windows
[TEMPLATE.md](../windows/TEMPLATE.md) structure, adapt it to the checklist
above, and record the entry here as `YYYY-MM-DD-machine-or-run.md`.
