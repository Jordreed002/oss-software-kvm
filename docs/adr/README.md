# Architecture Decision Records

ADRs capture *why* a significant architectural choice was made, so future
changes can be evaluated against the original forces instead of re-deriving
them from the code. The full engineering designs live in
[../](..); an ADR is the short, stable summary plus the link.

## Process

1. Copy [0000-adr-template.md](0000-adr-template.md) to
   `NNNN-short-name.md` (next free number, zero-padded).
2. Fill in Status (`Proposed` until reviewed, then `Accepted`), the date, and
   the three sections.
3. Add the record to the index below.
4. If a decision is later reversed, do not delete the ADR — mark it
   `Superseded by ADR-XXXX` and link to the successor.

ADRs summarize and link to the detailed documents; they do not duplicate them.

## Index

| ADR | Title | Status | Date |
| --- | --- | --- | --- |
| [0001](0001-udp-pointer-datagram.md) | UDP pointer datagram fast path (transport v3) | Accepted | 2026-08-11 |
| [0002](0002-transport-latency-hardening.md) | Transport latency hardening (transport v4) | Accepted | 2026-08-11 |
