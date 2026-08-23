//! Source-side semantic keyboard translation for the capture→enqueue path.
//!
//! This stage sits in `DaemonCore::prepare_captured` and consumes the trusted
//! physical key stream *before* a remote enqueue is prepared. In
//! [`KeyboardMode::Semantic`] it folds every modifier transition into a
//! per-device [`ModifierTracker`] and, on the press of an ordinary key,
//! resolves the held-modifier snapshot plus that key into a
//! [`SemanticCommand`] using the *local* platform's bindings
//! ([`kvm_input::semantic::resolve`]), then translates the intent into the
//! *destination* platform's native binding ([`kvm_input::semantic::translate`]).
//! The result is the [`SemanticTranslation`] carried on the core's prepared
//! remote effect (`RemoteInputEffect`).
//!
//! # Wire boundary (how the intent travels)
//!
//! `dispatch_remote_effect` sends the resolved intent as a protocol-v4
//! `SemanticInputV1` frame whenever the admitted session negotiated that wire
//! version or newer, carrying the command plus the exact originating physical
//! press (the destination's deterministic fallback). A session negotiated
//! below v4 — a peer on a pre-semantic build — cannot decode the frame, so
//! the enqueue boundary fails open and sends the exact physical event
//! unchanged: `Semantic` mode degrades to physical passthrough on
//! mixed-build pairs and can never drop or reorder user input.
//!
//! # Release exactness
//!
//! A translation can never leave a modifier logically held:
//!
//! - the tracker is fed *every* trusted physical key transition — including
//!   locally delivered, gated, quarantined, and failsafe-drain ones — so the
//!   snapshot mirrors physical reality rather than routing disposition;
//! - a physical release of a tracked modifier position clears it immediately
//!   (`Modifiers::apply` is level-driven, so a release observed without its
//!   press still clears the group — it can only under-count, never over-count);
//! - the source's enqueued event is never rewritten, so the daemon's
//!   held-state ledgers, latches, failsafe releases, and route-change cleanup
//!   stay byte-identical to physical mode. An under-counted snapshot merely
//!   fails to resolve (physical passthrough); it cannot invent a held
//!   modifier. (The *destination* replays the resolved chord as its own
//!   native binding and tracks that synthetic chord in its inbound ledger;
//!   see `session.rs`.)
//!
//! # Fail-open policy
//!
//! Every degradation — physical mode, unknown destination platform, tracker
//! capacity exhaustion, state reset mid-chord — degrades to "no translation",
//! never to altered input. Capacity exhaustion clears the whole stage (rather
//! than partially tracking a device) so a device is never resolved against a
//! subset of its physically held modifiers; the codebase treats exceeding the
//! per-device bound as a pathological anomaly and the stage follows that
//! discipline.

use std::collections::BTreeMap;

use kvm_input::{
    resolve, translate, InputPayload, KeyCode, KeyState, KeyboardMode, ModifierTracker, Modifiers,
    SemanticCommand, Shortcut,
};
use kvm_types::{DeviceId, Platform};
use thiserror::Error;

/// Maximum devices retaining semantic modifier state at one time.
///
/// Deliberately equals the core's physical held-device bound: the semantic
/// tracker is only ever populated for devices with at least one held modifier
/// group, so it can never exceed the ledger the core already bounds.
pub(crate) const MAX_SEMANTIC_TRACKED_DEVICES: usize = crate::core::MAX_PHYSICAL_HELD_DEVICES;

/// Coarse failure of the semantic capture stage. Never gates routing: the
/// caller fails open to physical passthrough and records the condition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SemanticCaptureError {
    #[error("semantic modifier tracking capacity was exceeded; failing open to physical")]
    DeviceCapacityExceeded,
}

/// A resolved semantic intent plus the destination platform's native binding.
///
/// `command` is a coarse intent category (safe for diagnostics); the bindings
/// are fixed per-platform table constants, not user payload. This is the
/// test-provable translation result produced at the source for the enqueue
/// boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SemanticTranslation {
    pub(crate) command: SemanticCommand,
    /// The destination platform's native binding for `command` — what the
    /// destination host must inject once the wire can carry the intent.
    pub(crate) destination_binding: Shortcut,
}

/// Per-device semantic modifier state for the capture path.
#[derive(Debug, Default)]
pub(crate) struct SemanticCaptureStage {
    trackers: BTreeMap<DeviceId, ModifierTracker>,
}

impl SemanticCaptureStage {
    /// Number of devices currently retaining semantic modifier state.
    #[must_use]
    pub(crate) fn tracked_devices(&self) -> usize {
        self.trackers.len()
    }

    /// Clears all translator state.
    ///
    /// Used on keyboard-mode switches so the new policy begins from an exact
    /// empty snapshot. A modifier physically held across the reset is simply
    /// untracked afterwards, which can only under-count (fail open).
    pub(crate) fn reset(&mut self) {
        self.trackers.clear();
    }

    /// Folds one trusted physical payload into the per-device tracker.
    ///
    /// Must be called for **every** trusted physical key transition regardless
    /// of the eventual routing disposition (local, gated, quarantined, remote)
    /// — see the module's release-exactness notes. In [`KeyboardMode::Physical`]
    /// this is a no-op so physical mode retains byte-identical behavior and
    /// zero added state. Non-key payloads are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`SemanticCaptureError::DeviceCapacityExceeded`] after clearing
    /// the stage when a new device would exceed the tracked-device bound. The
    /// caller must treat this as fail-open (physical passthrough), not gate.
    pub(crate) fn observe(
        &mut self,
        mode: KeyboardMode,
        device: DeviceId,
        payload: &InputPayload,
    ) -> Result<(), SemanticCaptureError> {
        if mode != KeyboardMode::Semantic {
            return Ok(());
        }
        let InputPayload::Key { code, state } = payload else {
            return Ok(());
        };
        let pressed = match state {
            KeyState::Pressed | KeyState::Repeated => true,
            KeyState::Released => false,
        };
        if self.trackers.contains_key(&device) {
            // `ModifierTracker::apply` is level-driven: a release observed
            // without its press still clears the modifier group, so state can
            // only under-count (fail open), never hold a modifier logically
            // down. Repeats re-assert the held level.
            let now_idle = self.trackers.get_mut(&device).is_some_and(|tracker| {
                tracker.apply(*code, pressed);
                tracker.current() == Modifiers::none()
            });
            if now_idle {
                // Never retain an entry for a device with no held modifier
                // group: the map stays bounded by *held* modifiers, not by
                // the number of devices ever seen.
                self.trackers.remove(&device);
            }
            return Ok(());
        }
        // No entry: only the press of a tracked modifier position may open
        // one. An unmatched release is a no-op, and non-tracked keys —
        // including `Fn`, which never participates in application shortcuts
        // on any supported platform — retain nothing.
        if !pressed || !is_tracked_modifier(*code) {
            return Ok(());
        }
        if self.trackers.len() >= MAX_SEMANTIC_TRACKED_DEVICES {
            // Pathological device count: clear the whole stage rather than
            // partially track any device (see the fail-open policy). Modifier
            // presses observed afterwards rebuild exact state from that
            // press.
            self.trackers.clear();
            return Err(SemanticCaptureError::DeviceCapacityExceeded);
        }
        self.trackers.entry(device).or_default().apply(*code, true);
        Ok(())
    }

    /// Resolves the press of an ordinary key into a semantic translation.
    ///
    /// Returns `None` (physical passthrough) when the mode is not semantic, the
    /// key is a modifier position, the device holds no tracked modifiers, the
    /// held snapshot is not exactly a binding of `source`, or the destination
    /// platform is unknown. Matching is exact — `Ctrl+Shift+C` is not `Copy`.
    #[must_use]
    pub(crate) fn resolve_press(
        &self,
        mode: KeyboardMode,
        device: DeviceId,
        code: KeyCode,
        source: Platform,
        destination: Platform,
    ) -> Option<SemanticTranslation> {
        if mode != KeyboardMode::Semantic || code.is_modifier() {
            return None;
        }
        let tracker = self.trackers.get(&device)?;
        let command = resolve(tracker.current(), code, source)?;
        Some(SemanticTranslation {
            command,
            destination_binding: translate(command, destination),
        })
    }
}

/// Whether `code` is one of the modifier positions `Modifiers::apply` folds
/// into the held-modifier snapshot. Mirrors the positions in `kvm_input`;
/// `Fn` is deliberately absent (hardware-level on macOS, never part of an
/// application shortcut).
const fn is_tracked_modifier(code: KeyCode) -> bool {
    matches!(
        code,
        KeyCode::ShiftLeft
            | KeyCode::ShiftRight
            | KeyCode::ControlLeft
            | KeyCode::ControlRight
            | KeyCode::AltLeft
            | KeyCode::AltRight
            | KeyCode::MetaLeft
            | KeyCode::MetaRight
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: Platform = Platform::Windows;
    const DESTINATION: Platform = Platform::MacOS;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 16])
    }

    fn stage() -> SemanticCaptureStage {
        SemanticCaptureStage::default()
    }

    fn press(code: KeyCode) -> InputPayload {
        InputPayload::Key {
            code,
            state: KeyState::Pressed,
        }
    }

    fn release(code: KeyCode) -> InputPayload {
        InputPayload::Key {
            code,
            state: KeyState::Released,
        }
    }

    fn ctrl_c(stage: &mut SemanticCaptureStage, device: DeviceId) -> Option<SemanticTranslation> {
        stage
            .observe(KeyboardMode::Semantic, device, &press(KeyCode::ControlLeft))
            .unwrap();
        stage.resolve_press(
            KeyboardMode::Semantic,
            device,
            KeyCode::KeyC,
            SOURCE,
            DESTINATION,
        )
    }

    #[test]
    fn semantic_mode_resolves_a_mapped_shortcut_into_destination_binding() {
        let mut stage = stage();
        let translation =
            ctrl_c(&mut stage, device(1)).expect("windows ctrl+c must resolve to copy");
        assert_eq!(translation.command, SemanticCommand::Copy);
        // Destination is macOS: Copy is Cmd+C, not Ctrl+C.
        assert_eq!(translation.destination_binding.modifiers, Modifiers::meta());
        assert_eq!(translation.destination_binding.key, KeyCode::KeyC);
    }

    #[test]
    fn unmapped_keys_and_extra_modifiers_do_not_resolve() {
        let mut stage = stage();
        let device = device(1);
        stage
            .observe(KeyboardMode::Semantic, device, &press(KeyCode::ControlLeft))
            .unwrap();
        stage
            .observe(KeyboardMode::Semantic, device, &press(KeyCode::ShiftLeft))
            .unwrap();
        // Ctrl+Shift+C is not Copy (exact matching) and K is unmapped.
        assert!(stage
            .resolve_press(
                KeyboardMode::Semantic,
                device,
                KeyCode::KeyC,
                SOURCE,
                DESTINATION
            )
            .is_none());
        assert!(stage
            .resolve_press(
                KeyboardMode::Semantic,
                device,
                KeyCode::KeyK,
                SOURCE,
                DESTINATION
            )
            .is_none());
    }

    #[test]
    fn physical_mode_never_tracks_or_resolves() {
        let mut stage = stage();
        let device = device(1);
        stage
            .observe(KeyboardMode::Physical, device, &press(KeyCode::ControlLeft))
            .unwrap();
        assert_eq!(stage.tracked_devices(), 0);
        assert!(stage
            .resolve_press(
                KeyboardMode::Physical,
                device,
                KeyCode::KeyC,
                SOURCE,
                DESTINATION
            )
            .is_none());
    }

    #[test]
    fn modifier_release_clears_state_and_cannot_wedge() {
        let mut stage = stage();
        let device = device(1);
        // Full chord lifecycle: Ctrl down, C down (translates), C up, Ctrl up.
        assert!(ctrl_c(&mut stage, device).is_some());
        stage
            .observe(
                KeyboardMode::Semantic,
                device,
                &release(KeyCode::ControlLeft),
            )
            .unwrap();
        // Tracker cleared: a following bare C press must not resolve.
        assert!(stage
            .resolve_press(
                KeyboardMode::Semantic,
                device,
                KeyCode::KeyC,
                SOURCE,
                DESTINATION
            )
            .is_none());
        assert_eq!(stage.tracked_devices(), 0);

        // Release-without-press (missed transition) also clears: level-driven
        // state under-counts, it can never hold a modifier logically down.
        stage
            .observe(KeyboardMode::Semantic, device, &press(KeyCode::AltLeft))
            .unwrap();
        stage
            .observe(KeyboardMode::Semantic, device, &release(KeyCode::AltRight))
            .unwrap();
        assert!(stage
            .resolve_press(
                KeyboardMode::Semantic,
                device,
                KeyCode::Tab,
                SOURCE,
                DESTINATION
            )
            .is_none());
    }

    #[test]
    fn per_device_state_is_independent() {
        let mut stage = stage();
        let first = device(1);
        let second = device(2);
        assert!(ctrl_c(&mut stage, first).is_some());
        // Second device never pressed a modifier: no resolution, and the first
        // device's state is untouched.
        assert!(stage
            .resolve_press(
                KeyboardMode::Semantic,
                second,
                KeyCode::KeyC,
                SOURCE,
                DESTINATION
            )
            .is_none());
        assert!(ctrl_c(&mut stage, first).is_some());
    }

    #[test]
    fn non_key_payloads_are_ignored() {
        let mut stage = stage();
        let device = device(1);
        stage
            .observe(
                KeyboardMode::Semantic,
                device,
                &InputPayload::PointerMove { dx: 1.0, dy: 2.0 },
            )
            .unwrap();
        assert_eq!(stage.tracked_devices(), 0);
    }

    #[test]
    fn reset_clears_all_state() {
        let mut stage = stage();
        let device = device(1);
        assert!(ctrl_c(&mut stage, device).is_some());
        stage.reset();
        assert_eq!(stage.tracked_devices(), 0);
        assert!(stage
            .resolve_press(
                KeyboardMode::Semantic,
                device,
                KeyCode::KeyC,
                SOURCE,
                DESTINATION
            )
            .is_none());
    }

    #[test]
    fn capacity_exhaustion_fails_open_by_clearing_the_stage() {
        let mut stage = stage();
        for byte in 1..=u8::try_from(MAX_SEMANTIC_TRACKED_DEVICES).unwrap() {
            stage
                .observe(
                    KeyboardMode::Semantic,
                    device(byte),
                    &press(KeyCode::ControlLeft),
                )
                .unwrap();
        }
        assert_eq!(stage.tracked_devices(), MAX_SEMANTIC_TRACKED_DEVICES);
        // One more device with a held modifier exceeds the bound: the whole
        // stage clears and reports the error; the caller fails open.
        assert_eq!(
            stage.observe(
                KeyboardMode::Semantic,
                device(0),
                &press(KeyCode::ControlLeft)
            ),
            Err(SemanticCaptureError::DeviceCapacityExceeded)
        );
        assert_eq!(stage.tracked_devices(), 0);
    }

    #[test]
    fn idle_device_entries_are_not_retained() {
        let mut stage = stage();
        let device = device(1);
        stage
            .observe(KeyboardMode::Semantic, device, &press(KeyCode::ControlLeft))
            .unwrap();
        assert_eq!(stage.tracked_devices(), 1);
        stage
            .observe(
                KeyboardMode::Semantic,
                device,
                &release(KeyCode::ControlLeft),
            )
            .unwrap();
        assert_eq!(stage.tracked_devices(), 0);
        // Ordinary keys never allocate an entry.
        stage
            .observe(KeyboardMode::Semantic, device, &press(KeyCode::KeyA))
            .unwrap();
        assert_eq!(stage.tracked_devices(), 0);
    }

    #[test]
    fn translation_debug_exposes_intent_but_not_source_identity() {
        let mut stage = stage();
        let translation = ctrl_c(&mut stage, device(0x71)).unwrap();
        let rendered = format!("{translation:?}");
        assert!(rendered.contains("Copy"));
        // Bindings are fixed table constants; no device/host/payload identity
        // exists on the translation to leak.
        assert!(!rendered.contains("113"));
    }
}
