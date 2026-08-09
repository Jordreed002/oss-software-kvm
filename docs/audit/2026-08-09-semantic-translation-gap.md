# Audit: Semantic keyboard translation is a no-op

**Date:** 2026-08-09
**Cycle:** /loop audit cycle 1
**Spec refs:** `.spec/spec.md` §17 (Modifier Mapping), `.spec/implementation.md` §26 (Keyboard Translation)
**Severity:** Medium — feature advertised in config is silently inert

## Summary

The spec requires two keyboard-translation modes when routing input across hosts:

- **Physical** — map by physical key location (`Ctrl→Control`, `Win→Command`, `Alt→Option`).
- **Semantic** — translate a small set of commands by intent so they use the
  destination platform's native convention, e.g.
  `Copy` is `Ctrl+C` on Windows but `Command+C` on macOS.

Cross-platform convention (confirmed via current references): on macOS the
**Command (⌘)** modifier fills the role that **Ctrl** fills on Windows for
application-level shortcuts (Copy, Paste, Undo, etc.). Without semantic
translation, a Windows `Ctrl+C` routed to Mac arrives as `Control+C` (a
different, rarely-used shortcut) instead of `Command+C`, so copy/paste silently
fails for users in semantic mode.

## Current implementation state

- `SemanticCommand` enum exists in `crates/kvm-input/src/semantic.rs`
  (`Copy, Paste, Cut, Undo, Redo, SelectAll, AppSwitch`) and matches the spec
  enum exactly. It is `pub use`'d from the crate root.
- `KeyboardMode { Physical, Semantic }` exists in **two** places:
  `crates/kvm-input/src/semantic.rs` and `crates/kvm-config/src/model.rs`.
- The config layer **persists and migrates** the mode
  (`crates/kvm-config/src/migrate.rs` migrates legacy `keyboard_mode` to the new
  `keyboard.mode` field), and the daemon core **stores** it
  (`crates/kvm-daemon/src/core.rs`, with tests asserting storage).

## Gap (verified)

`SemanticCommand` has **zero** functional references outside its definition.
`KeyboardMode::Semantic` is **never consulted** on the input/routing path. In
other words:

> Selecting `Semantic` mode in configuration changes stored state but has no
> effect on translated output. Semantic mode is a no-op.

Physical modifier-location mapping appears implemented in the platform backends
(e.g. `crates/kvm-windows/src/mapping.rs` `left_and_right_modifiers_preserve_physical_location`),
so the gap is specifically the semantic intent-translation layer.

## Evidence

```
$ rg "SemanticCommand|KeyboardMode::Semantic" crates/
crates/kvm-input/src/semantic.rs:16: pub enum SemanticCommand {        # definition only
crates/kvm-input/src/lib.rs:15:        pub use semantic::{KeyboardMode, SemanticCommand};  # re-export only
crates/kvm-config/src/migrate.rs:179:  keyboard_mode: KeyboardMode::Semantic   # config migration only
crates/kvm-daemon/src/core.rs:2585:   .keyboard.mode = KeyboardMode::Semantic  # storage test only
```

No resolver maps `(modifiers + key, destination platform) -> SemanticCommand`,
and no injector consumes a `SemanticCommand` to emit the platform-native
modifiers.

## Recommended fix (improvement cycle)

1. Add a resolver in `kvm-input` (e.g. `semantic::resolve(modifiers, key,
   source_platform) -> Option<SemanticCommand>`) for the seven commands, keyed
   on the source platform's native shortcut.
2. Add a translator `(SemanticCommand, destination_platform) -> modifier set +
   key` consumed by the Windows/macOS injection paths.
3. Gate translation on `KeyboardMode::Semantic` from the active config.
4. Add unit tests covering Windows→macOS and macOS→Windows for each command,
   including that `Ctrl+C` from Windows resolves to `Command+C` on Mac.
5. Collapse the duplicate `KeyboardMode` definitions (config re-exports the
   domain type rather than redefining it), or document why they diverge.

## Non-goals for this audit

Did not modify code. This is a documented finding; implementation is deferred to
the next improvement cycle.
