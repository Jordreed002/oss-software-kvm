# Audit: Semantic key translation is built & configurable but still unwired (§17/§26)

**Date:** 2026-08-10
**Cycle:** /loop audit cycle 17 (supersedes cycle-1 finding `2026-08-09-semantic-translation-gap.md`)
**Spec refs:** `.spec/implementation.md` §17 (follow-active-host keyboard routing), §26; `.spec/milestone-07-follow-active-host-keyboard-routing.md`
**Severity:** High — this is a headline, user-visible feature of the product category. A user who sets `keyboard.mode = "semantic"` gets byte-identical behavior to `physical`.

## What changed since the cycle-1 finding

Cycle 1 found `KeyboardMode::Semantic` was a no-op. Cycle 2 then **built the translation
library** (`kvm-input::semantic`: `Modifiers`, `ModifierTracker`, `resolve`, `translate`,
`native_binding`, `Shortcut`, 24 tests). Cycle 12 consolidated the duplicate `KeyboardMode`
into `kvm-types`. So the feature is now complete as a *library* and *configurable*.

This audit re-verifies the **remaining** gap and localizes it precisely.

## Current state: still unwired end-to-end

The translation primitives have **zero callers outside `kvm-input`**, and `KeyboardMode`
is **never consulted on the input path**:

```text
$ grep -rn "KeyboardMode" crates/ --include=*.rs   # (excluding the def + tests)
kvm-config/src/model.rs:321      pub mode: KeyboardMode,        # config field only
kvm-config/src/migrate.rs        # legacy on-disk migration only
kvm-input/src/lib.rs             # re-export only

$ grep -rn "resolve\|translate\|ModifierTracker\|native_binding" crates/ --include=*.rs | grep -v kvm-input/
( no matches )
```

The destination-side injection handler confirms it injects the physical key verbatim with
no translation:

```rust
// crates/kvm-daemon/src/session.rs:1247  (inject_received)
if self.injection.inject(&event).is_err() {
    return Err(self.fail_session(CoordinatorError::Injection, now_ns));
}
```

`inject_received` (session.rs:1201–1259) does pressed-state bookkeeping then calls
`OutputInjectionBackend::inject(&event)`. It never reads `config.keyboard.mode`, never
calls `resolve`/`translate`. So a Windows `Ctrl+C` arriving on a macOS destination is
injected as **physical Ctrl+C**, not `Cmd+C`, regardless of `mode: Semantic`. `Physical`
and `Semantic` are observationally indistinguishable.

## Why it's still open: a wire-protocol decision, not just a code gap

This isn't a one-line wiring task — it requires deciding **where** translation happens, and
that decision changes the wire protocol:

1. **Translate at the destination (needs source platform).** The destination must `resolve`
   the incoming physical keys into a `SemanticCommand` using the *source* platform's
   bindings, then `translate` to its own. But `InputEvent` / `InputEventV1` carry
   `source_host` and `source_device`, **not the source platform**. So this path needs the
   source host's platform available to the destination (via host metadata / `HostSnapshot`
   — which does exist per-host, so this is feasible without a new wire variant).

2. **Translate at the source (needs a new wire variant).** The source resolves its own
   keys into a `SemanticCommand` and sends the *intent*; the destination translates to its
   native binding. This needs a new `InputPayload` / wire variant (`SemanticCommand` is
   already `Serialize`/`Deserialize` in kvm-input, but is not a wire type in kvm-protocol).
   Cleaner semantics (intent is unambiguous) but a protocol-versioned change.

Either way it is larger than the other gaps this loop has closed, which is why it has
deferred across cycles. The cycle-2 library was deliberately the "safe, no hot-path risk"
slice; the wiring is the deliberately-later, protocol-touching slice.

## Industry baseline (web-verified)

Cross-platform Ctrl↔Cmd (and Alt↔Cmd, redo Ctrl+Y↔Cmd+Shift+Z) translation is **core,
expected behavior** in this product category: Barrier and Synergy — the canonical
open-source/commercial software KVMs sharing one keyboard across Windows/macOS/Linux —
both ship keyboard-translation layers; users specifically rely on it so muscle memory
survives the host switch. So §17 semantic mode is a load-bearing feature, not a
nice-to-have, and its absence is a real product gap (justifiably deferred behind the
protocol work).

## Recommended path (improvement cycle)

Prefer **option 1 (translate at destination)** as the first wired slice — it avoids a new
wire variant because host platform is already available per-peer via `HostSnapshot`:

1. In `inject_received`, when `config.keyboard.mode == Semantic` and the payload is a
   `Key` press/release, thread the **source platform** (looked up from the peer's host
   metadata) and the **local platform** into a translation step.
2. Use a `ModifierTracker` per inbound device to track held modifiers, `resolve` on an
   ordinary key press, and on a match emit the `translate(...)`-derived physical keys to
   the injector instead of the raw ones. Non-matching keys pass through unchanged (so
   semantic mode is strictly additive).
3. Reuse the existing cycle-2 `ModifierTracker`/`resolve`/`translate` verbatim — no new
   library code, just a caller. Add integration tests with a fake injection backend
   asserting `Ctrl+C` (Windows source) → `Cmd+C` (macOS dest) under Semantic, and
   unchanged under Physical.

This consumes the cycle-2 library exactly as designed and closes the longest-standing gap
in the loop. The wire-protocol (option 2) refinement can follow if intent-at-source proves
cleaner in practice.

## Non-goals for this audit

Did not modify code. Supersedes the cycle-1 finding with the post-cycle-2 reality
(library exists, gap is now "unwired at inject_received:1247 + needs a source-platform
threading decision") and a concrete, wire-variant-free improvement path.
