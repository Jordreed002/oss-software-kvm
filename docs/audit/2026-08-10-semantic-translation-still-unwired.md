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

---

## Closure (partial) — 2026-08-23

**Status: source-side translation is wired end-to-end through the daemon capture path,
up to the wire enqueue boundary. The wire itself still cannot carry a semantic intent,
so `Semantic` mode remains observationally identical to `Physical` on the network by
deliberate fail-open. The remaining work is a `kvm-protocol` extension, which this
remediation was explicitly barred from touching.**

### What is now wired (all inside `kvm-daemon`)

1. **Semantic capture stage** (`crates/kvm-daemon/src/semantic_capture.rs`):
   `SemanticCaptureStage` holds one `kvm-input` `ModifierTracker` per captured device
   (bounded by `MAX_SEMANTIC_TRACKED_DEVICES` = the physical held-device bound; entries
   exist only while a modifier group is held). `observe` folds *every* trusted physical
   key transition — local, gated, quarantined, and failsafe-drain ones included — so the
   held-modifier snapshot mirrors physical reality, and any physical release clears it
   (level-driven `Modifiers::apply`: a release without its press under-counts, it can
   never leave a modifier logically held). `resolve_press` resolves an ordinary-key
   press against the *source* platform and `translate`s the command to the *destination*
   platform's native binding; matching stays exact (`Ctrl+Shift+C` ≠ `Copy`). Every
   degradation (physical mode, unknown destination platform, capacity exhaustion,
   reset mid-chord) fails open to physical passthrough. Capacity exhaustion clears the
   whole stage rather than partially tracking a device.

2. **Capture-path wiring** (`crates/kvm-daemon/src/core.rs`):
   `prepare_captured` feeds the stage immediately after the trusted-physical gate;
   `prepare_remote_effect` — the single choke point where a captured press becomes a
   prepared remote enqueue — consults `semantic_resolution` and attaches the
   `SemanticTranslation` (command + destination binding) to the `RemoteInputEffect`
   (`RemoteInputEffect::semantic_translation()` exposes it). The destination platform
   comes from the paired-host configuration for the endpoint's host; the source platform
   is the new `DaemonCore::new(config, workspace, local_platform)` parameter (main.rs
   derives it from the compiled-in backend target).

3. **Enqueue boundary — fail-open, documented** (`crates/kvm-daemon/src/session.rs`,
   `dispatch_remote_effect`): `WireInputPayloadV1` carries only
   `Key`/`PointerMove`/`PointerButton`/`Scroll`. There is no semantic payload variant,
   and the daemon may not extend `kvm-protocol`. When a translation was resolved, the
   exact physical event is enqueued unchanged (with a coarse debug log), so Semantic
   mode is strictly additive — it can never drop, reorder, or rewrite user input. The
   held-state ledgers, latches, failsafe releases, and route-change cleanup remain
   byte-identical to physical mode *by construction* because the enqueued event is
   never rewritten.

4. **Mode switching** (`core.rs::update_config`): a keyboard-mode change now drains
   every remote hold through the existing retryable route-change cleanup (first
   attempt returns `CleanupPending` until the release barrier settles) and resets the
   translator at commit so the new policy begins from an exact empty snapshot. Mode
   validation itself remains config-layer (`KeyboardMode` serde + `Config::validate`),
   unchanged.

### Tests added (16)

- `semantic_capture` unit tests (10): mapped-shortcut resolution with destination
  binding (Windows `Ctrl+C` → `Copy` → macOS `Cmd+C`), exact-modifier non-matching,
  unmapped passthrough, physical-mode no-op, release/under-count never wedges,
  per-device isolation, non-key payloads, reset, capacity fail-open, Debug redaction.
- `core` tests (5): a mapped shortcut translates onto the prepared remote effect while
  the enqueued event stays the exact physical capture; unmapped keys pass through
  physically (and physical mode resolves nothing); full chord lifecycle with
  modifier-before-key release leaves `remote_held`/latches/tracker exactly empty;
  mode switch blocks on the cleanup barrier, drains, commits, and re-arms from an
  empty snapshot; the failsafe chord still escapes locally in semantic mode and its
  drain window clears the tracker.
- `session` test (1): end-to-end through `route_captured` in Semantic mode, the wire
  receives exactly four `Input` frames carrying the exact physical chord in order —
  pinning the fail-open boundary.

Verification: `cargo fmt --all --package kvm-daemon` (clean), `cargo clippy
--package kvm-daemon --all-targets [--features diagnostics] -- -D warnings` (clean;
workspace lints include `clippy::all` + `clippy::pedantic`), `cargo test --package
kvm-daemon --all-targets` = 224 passed / 0 failed, and with `--features diagnostics`
= 234 passed / 0 failed.

### What remains (needs `kvm-protocol`, out of this remediation's file ownership)

1. Extend the wire so an intent can travel: a semantic variant of the `Input` payload
   (versioned like `ReleaseInputV2`) or a v3 input message, carrying at minimum the
   `SemanticCommand` (kvm-input's `SemanticCommand` is already serde-serializable).
2. Consume it at the destination: `inject_received` currently injects the physical
   event verbatim; it must translate the intent via
   `kvm_input::semantic::native_binding(command, local_platform)` and inject that
   chord through the existing injection backend, with destination-side pressed-state
   bookkeeping for the synthetic chord.
3. Replace the fail-open in `dispatch_remote_effect` with the semantic dispatch once
   (1) and (2) exist; the `RemoteInputEffect.semantic` annotation and its tests are
   the seam for that change.
4. Note for that work: the translator's reset-under-count property (mode switch,
   capacity clear) means a mid-chord reset can only *miss* a translation, never invent
   one — safe under today's fail-open, and the constraint to preserve when the
   semantic payload becomes real.

The audit-recommended alternative (translate at the destination from the source host's
platform metadata) also remains open; this closure deliberately implemented the
source-side variant because it keeps the intent unambiguous and the destination simple,
which is where the audit's option 2 pointed.
