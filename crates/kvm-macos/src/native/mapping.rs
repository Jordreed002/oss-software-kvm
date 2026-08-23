//! Reverse-direction modifier-role translation for a Windows source keyboard.
//!
//! These pure functions mirror `kvm-windows`'s macOS-source mapping so a
//! Mac-to-Windows shortcut chord and its Windows-to-Mac inverse resolve
//! symmetrically. Chord resolution is testable here without posting Quartz
//! events.

use kvm_input::{KeyCode, KeyState};

use crate::capture::quartz_key_is_down;
use crate::keymap::{mac_virtual_key, macos_key_for_windows_source};

/// Translates a Windows keyboard's Control and Windows keys to macOS
/// Command and Control roles by shortcut function. Alt stays untouched:
/// Windows Alt already lands on macOS Option, the correct `AltGr` position.
/// Shift never remaps.
#[must_use]
pub(crate) const fn macos_key_for_windows_functional(key: KeyCode) -> KeyCode {
    match key {
        KeyCode::ControlLeft => KeyCode::MetaLeft,
        KeyCode::ControlRight => KeyCode::MetaRight,
        KeyCode::MetaLeft => KeyCode::ControlLeft,
        KeyCode::MetaRight => KeyCode::ControlRight,
        other => other,
    }
}

/// Modifier-role translation policy applied to keys arriving from a Windows
/// source keyboard. Mirrors the persisted `kvm-config` setting of the same
/// name; the runtime selects the constructor to use, so this stays crate-local.
/// The backend-level default is `Identity` (plain injection); the
/// cross-platform *pair* default is `Functional` and is chosen by the runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ModifierRoleMapping {
    /// Every key injects its own virtual key unchanged.
    #[default]
    Identity,
    /// Legacy physical-position swap (Alt↔Command, Windows key↔Option).
    Positional,
    /// Shortcut-role swap (Control↔Command, Windows key↔Control); the
    /// cross-platform default.
    Functional,
}

impl ModifierRoleMapping {
    /// Translates `key` from a Windows source keyboard according to this policy.
    #[must_use]
    pub(crate) const fn map_windows_source(self, key: KeyCode) -> KeyCode {
        match self {
            Self::Identity => key,
            Self::Positional => macos_key_for_windows_source(key),
            Self::Functional => macos_key_for_windows_functional(key),
        }
    }
}

/// One fully resolved Quartz keyboard event target, before `CGEvent` creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyRecord {
    pub virtual_key: u16,
    pub key_up: bool,
}

/// Resolves a key event from a Windows source keyboard through a
/// modifier-role policy into the Quartz virtual key the injector posts, so
/// chord ordering (which modifier went down first, which comes up first) is
/// testable without posting Quartz events. Returns `None` when the resolved
/// key has no Quartz virtual-key mapping.
#[must_use]
pub(crate) fn key_record_for_windows_source(
    roles: ModifierRoleMapping,
    key: KeyCode,
    state: KeyState,
) -> Option<KeyRecord> {
    let virtual_key = mac_virtual_key(roles.map_windows_source(key))?;
    Some(KeyRecord {
        virtual_key,
        key_up: !quartz_key_is_down(state),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLE_MODIFIERS: [KeyCode; 9] = [
        KeyCode::ShiftLeft,
        KeyCode::ShiftRight,
        KeyCode::ControlLeft,
        KeyCode::ControlRight,
        KeyCode::AltLeft,
        KeyCode::AltRight,
        KeyCode::MetaLeft,
        KeyCode::MetaRight,
        KeyCode::Fn,
    ];

    fn record(roles: ModifierRoleMapping, key: KeyCode, state: KeyState) -> KeyRecord {
        key_record_for_windows_source(roles, key, state).expect("chord keys always resolve")
    }

    #[test]
    fn functional_mode_swaps_control_and_command_roles_only() {
        let roles = ModifierRoleMapping::Functional;
        for (source, destination) in [
            (KeyCode::ControlLeft, KeyCode::MetaLeft),
            (KeyCode::ControlRight, KeyCode::MetaRight),
            (KeyCode::MetaLeft, KeyCode::ControlLeft),
            (KeyCode::MetaRight, KeyCode::ControlRight),
            // Windows Alt already lands on macOS Option (AltGr); untouched.
            (KeyCode::AltLeft, KeyCode::AltLeft),
            (KeyCode::AltRight, KeyCode::AltRight),
            // Shift never remaps.
            (KeyCode::ShiftLeft, KeyCode::ShiftLeft),
            (KeyCode::ShiftRight, KeyCode::ShiftRight),
        ] {
            assert_eq!(roles.map_windows_source(source), destination);
        }
    }

    #[test]
    fn functional_mode_is_the_exact_inverse_of_the_windows_functional_map() {
        // kvm-windows maps Mac Meta→Control and Mac Control→Meta for a macOS
        // source; this table must invert it key by key so a shortcut round-trips.
        let roles = ModifierRoleMapping::Functional;
        for (windows_source, mac_destination) in [
            (KeyCode::MetaLeft, KeyCode::ControlLeft),
            (KeyCode::MetaRight, KeyCode::ControlRight),
            (KeyCode::ControlLeft, KeyCode::MetaLeft),
            (KeyCode::ControlRight, KeyCode::MetaRight),
            (KeyCode::AltLeft, KeyCode::AltLeft),
            (KeyCode::AltRight, KeyCode::AltRight),
        ] {
            assert_eq!(roles.map_windows_source(windows_source), mac_destination);
        }
    }

    #[test]
    fn positional_mode_swaps_alt_and_command_positions_only() {
        let roles = ModifierRoleMapping::Positional;
        for (source, destination) in [
            (KeyCode::AltLeft, KeyCode::MetaLeft),
            (KeyCode::AltRight, KeyCode::MetaRight),
            (KeyCode::MetaLeft, KeyCode::AltLeft),
            (KeyCode::MetaRight, KeyCode::AltRight),
            (KeyCode::ControlLeft, KeyCode::ControlLeft),
            (KeyCode::ControlRight, KeyCode::ControlRight),
            (KeyCode::ShiftLeft, KeyCode::ShiftLeft),
            (KeyCode::ShiftRight, KeyCode::ShiftRight),
        ] {
            assert_eq!(roles.map_windows_source(source), destination);
        }
    }

    #[test]
    fn identity_mode_passes_every_modifier_through() {
        for key in ROLE_MODIFIERS {
            assert_eq!(ModifierRoleMapping::Identity.map_windows_source(key), key);
        }
    }

    #[test]
    fn every_mode_maps_modifiers_without_collision() {
        // A role mapping must be a bijection over the modifier set: if two
        // source modifiers ever landed on one destination key, one of them
        // could no longer be released independently.
        for roles in [
            ModifierRoleMapping::Identity,
            ModifierRoleMapping::Positional,
            ModifierRoleMapping::Functional,
        ] {
            let mut destinations = std::collections::HashSet::new();
            for key in ROLE_MODIFIERS {
                assert!(
                    destinations.insert(roles.map_windows_source(key)),
                    "{roles:?}: two source modifiers collapse onto one destination"
                );
            }
        }
    }

    #[test]
    fn non_modifier_keys_pass_through_untouched_in_every_mode() {
        for key in [KeyCode::Tab, KeyCode::KeyC, KeyCode::Space, KeyCode::Enter] {
            for roles in [
                ModifierRoleMapping::Identity,
                ModifierRoleMapping::Positional,
                ModifierRoleMapping::Functional,
            ] {
                assert_eq!(roles.map_windows_source(key), key);
            }
        }
    }

    #[test]
    fn functional_chord_ctrl_shift_c_presses_and_releases_in_order() {
        let roles = ModifierRoleMapping::Functional;
        let presses = [
            (KeyCode::ControlLeft, KeyState::Pressed),
            (KeyCode::ShiftLeft, KeyState::Pressed),
            (KeyCode::KeyC, KeyState::Pressed),
        ];

        let downs: Vec<_> = presses
            .iter()
            .map(|&(key, state)| record(roles, key, state))
            .collect();
        // Ctrl maps to Command (0x37); Shift and C are untouched (0x38, 0x08).
        assert_eq!(downs[0].virtual_key, 0x37);
        assert_eq!(downs[1].virtual_key, 0x38);
        assert_eq!(downs[2].virtual_key, 0x08);
        assert!(downs.iter().all(|down| !down.key_up));

        // Releases arrive in reverse press order, each as a key-up transition.
        let ups: Vec<_> = presses
            .iter()
            .rev()
            .map(|&(key, _)| record(roles, key, KeyState::Released))
            .collect();
        for (down, up) in downs.iter().zip(ups.iter().rev()) {
            assert_eq!(down.virtual_key, up.virtual_key);
        }
        assert!(ups.iter().all(|up| up.key_up));
    }

    #[test]
    fn functional_chord_releasing_control_before_c_still_releases_c() {
        let roles = ModifierRoleMapping::Functional;
        let ctrl_down = record(roles, KeyCode::ControlLeft, KeyState::Pressed);
        let c_down = record(roles, KeyCode::KeyC, KeyState::Pressed);
        // The user drops the modifier first; the C release must still resolve
        // to the same virtual key as a key-up transition and no error.
        let ctrl_up = record(roles, KeyCode::ControlLeft, KeyState::Released);
        let c_up = record(roles, KeyCode::KeyC, KeyState::Released);

        assert!(!ctrl_down.key_up);
        assert!(!c_down.key_up);
        assert!(ctrl_up.key_up);
        assert!(c_up.key_up);
        assert_eq!(ctrl_down.virtual_key, ctrl_up.virtual_key);
        assert_eq!(c_down.virtual_key, c_up.virtual_key);
        assert_eq!(c_up.virtual_key, 0x08);
    }

    #[test]
    fn functional_dual_modifier_hold_presses_without_collision() {
        let roles = ModifierRoleMapping::Functional;
        let ctrl_down = record(roles, KeyCode::ControlLeft, KeyState::Pressed);
        let win_down = record(roles, KeyCode::MetaLeft, KeyState::Pressed);
        // Ctrl maps to Command (0x37) while the Windows key maps to Control
        // (0x3b): both held keys remain independently addressable.
        assert_eq!(ctrl_down.virtual_key, 0x37);
        assert_eq!(win_down.virtual_key, 0x3b);
        assert_ne!(ctrl_down.virtual_key, win_down.virtual_key);

        let win_up = record(roles, KeyCode::MetaLeft, KeyState::Released);
        let ctrl_up = record(roles, KeyCode::ControlLeft, KeyState::Released);
        assert_eq!(win_up.virtual_key, win_down.virtual_key);
        assert_eq!(ctrl_up.virtual_key, ctrl_down.virtual_key);
        assert!(win_up.key_up && ctrl_up.key_up);
    }
}
