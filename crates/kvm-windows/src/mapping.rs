#[cfg(any(windows, test))]
use kvm_input::KeyState;
#[cfg(any(windows, test))]
use kvm_input::{ButtonState, KeyCode, PointerButton};

/// Translates a macOS keyboard's shortcut modifiers to Windows roles by
/// physical position: Command and Option swap with Alt and the Windows key.
///
/// This was the original cross-platform behavior. It is superseded as the
/// default by the role-based functional mapping (see
/// [`ModifierRoleMapping::Functional`]) because a Mac user's shortcut muscle
/// memory is role-based: Command+C must reach Windows as Ctrl+C. Retained as
/// the `positional` configuration value for users who prefer the legacy swap.
#[cfg(any(windows, test))]
#[must_use]
pub(crate) const fn windows_key_for_macos_source(key: KeyCode) -> KeyCode {
    match key {
        KeyCode::MetaLeft => KeyCode::AltLeft,
        KeyCode::MetaRight => KeyCode::AltRight,
        KeyCode::AltLeft => KeyCode::MetaLeft,
        KeyCode::AltRight => KeyCode::MetaRight,
        other => other,
    }
}

/// Translates a macOS keyboard's shortcut modifiers to Windows roles by
/// shortcut function: Command swaps with Control while Option stays on Alt
/// (Option already occupies the correct `AltGr` position). Shift never remaps.
#[cfg(any(windows, test))]
#[must_use]
pub(crate) const fn windows_key_for_macos_functional(key: KeyCode) -> KeyCode {
    match key {
        KeyCode::MetaLeft => KeyCode::ControlLeft,
        KeyCode::MetaRight => KeyCode::ControlRight,
        KeyCode::ControlLeft => KeyCode::MetaLeft,
        KeyCode::ControlRight => KeyCode::MetaRight,
        other => other,
    }
}

/// Modifier-role translation policy applied to keys arriving from a macOS
/// source keyboard. Mirrors the persisted `kvm-config` setting of the same
/// name; the runtime selects the constructor to use, so this stays crate-local.
/// The backend-level default is `Identity` (plain injection); the
/// cross-platform *pair* default is `Functional` and is chosen by the runtime.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ModifierRoleMapping {
    /// Every key injects its own code unchanged.
    #[default]
    Identity,
    /// Legacy physical-position swap (Command↔Alt, Option↔Windows key).
    Positional,
    /// Shortcut-role swap (Command↔Control, Option/Alt unchanged); the
    /// cross-platform default.
    Functional,
}

#[cfg(any(windows, test))]
impl ModifierRoleMapping {
    /// Translates `key` from a macOS source keyboard according to this policy.
    #[must_use]
    pub(crate) const fn map_macos_source(self, key: KeyCode) -> KeyCode {
        match self {
            Self::Identity => key,
            Self::Positional => windows_key_for_macos_source(key),
            Self::Functional => windows_key_for_macos_functional(key),
        }
    }
}

#[cfg(windows)]
pub(crate) const WHEEL_DELTA: f64 = 120.0;

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScanCode {
    pub code: u16,
    pub extended: bool,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MouseAction {
    LeftDown,
    LeftUp,
    RightDown,
    RightUp,
    MiddleDown,
    MiddleUp,
    XDown(u16),
    XUp(u16),
}

#[cfg(any(windows, test))]
#[allow(clippy::too_many_lines)] // An explicit position table is easier to audit than arithmetic ranges.
pub(crate) fn scan_code(key: KeyCode) -> Option<ScanCode> {
    let (code, extended) = match key {
        KeyCode::Escape => (0x01, false),
        KeyCode::F1 => (0x3b, false),
        KeyCode::F2 => (0x3c, false),
        KeyCode::F3 => (0x3d, false),
        KeyCode::F4 => (0x3e, false),
        KeyCode::F5 => (0x3f, false),
        KeyCode::F6 => (0x40, false),
        KeyCode::F7 => (0x41, false),
        KeyCode::F8 => (0x42, false),
        KeyCode::F9 => (0x43, false),
        KeyCode::F10 => (0x44, false),
        KeyCode::F11 => (0x57, false),
        KeyCode::F12 => (0x58, false),
        KeyCode::F13 => (0x64, false),
        KeyCode::F14 => (0x65, false),
        KeyCode::F15 => (0x66, false),
        KeyCode::F16 => (0x67, false),
        KeyCode::F17 => (0x68, false),
        KeyCode::F18 => (0x69, false),
        KeyCode::F19 => (0x6a, false),
        KeyCode::F20 => (0x6b, false),
        KeyCode::F21 => (0x6c, false),
        KeyCode::F22 => (0x6d, false),
        KeyCode::F23 => (0x6e, false),
        KeyCode::F24 => (0x76, false),
        KeyCode::PrintScreen => (0x37, true),
        KeyCode::ScrollLock => (0x46, false),

        KeyCode::Backquote => (0x29, false),
        KeyCode::Digit1 => (0x02, false),
        KeyCode::Digit2 => (0x03, false),
        KeyCode::Digit3 => (0x04, false),
        KeyCode::Digit4 => (0x05, false),
        KeyCode::Digit5 => (0x06, false),
        KeyCode::Digit6 => (0x07, false),
        KeyCode::Digit7 => (0x08, false),
        KeyCode::Digit8 => (0x09, false),
        KeyCode::Digit9 => (0x0a, false),
        KeyCode::Digit0 => (0x0b, false),
        KeyCode::Minus => (0x0c, false),
        KeyCode::Equal => (0x0d, false),
        KeyCode::Backspace => (0x0e, false),

        KeyCode::Tab => (0x0f, false),
        KeyCode::KeyQ => (0x10, false),
        KeyCode::KeyW => (0x11, false),
        KeyCode::KeyE => (0x12, false),
        KeyCode::KeyR => (0x13, false),
        KeyCode::KeyT => (0x14, false),
        KeyCode::KeyY => (0x15, false),
        KeyCode::KeyU => (0x16, false),
        KeyCode::KeyI => (0x17, false),
        KeyCode::KeyO => (0x18, false),
        KeyCode::KeyP => (0x19, false),
        KeyCode::BracketLeft => (0x1a, false),
        KeyCode::BracketRight => (0x1b, false),
        KeyCode::Backslash => (0x2b, false),

        KeyCode::CapsLock => (0x3a, false),
        KeyCode::KeyA => (0x1e, false),
        KeyCode::KeyS => (0x1f, false),
        KeyCode::KeyD => (0x20, false),
        KeyCode::KeyF => (0x21, false),
        KeyCode::KeyG => (0x22, false),
        KeyCode::KeyH => (0x23, false),
        KeyCode::KeyJ => (0x24, false),
        KeyCode::KeyK => (0x25, false),
        KeyCode::KeyL => (0x26, false),
        KeyCode::Semicolon => (0x27, false),
        KeyCode::Quote => (0x28, false),
        KeyCode::Enter => (0x1c, false),

        KeyCode::ShiftLeft => (0x2a, false),
        KeyCode::IntlBackslash => (0x56, false),
        KeyCode::KeyZ => (0x2c, false),
        KeyCode::KeyX => (0x2d, false),
        KeyCode::KeyC => (0x2e, false),
        KeyCode::KeyV => (0x2f, false),
        KeyCode::KeyB => (0x30, false),
        KeyCode::KeyN => (0x31, false),
        KeyCode::KeyM => (0x32, false),
        KeyCode::Comma => (0x33, false),
        KeyCode::Period => (0x34, false),
        KeyCode::Slash => (0x35, false),
        KeyCode::ShiftRight => (0x36, false),

        KeyCode::ControlLeft => (0x1d, false),
        KeyCode::MetaLeft => (0x5b, true),
        KeyCode::AltLeft => (0x38, false),
        KeyCode::Space => (0x39, false),
        KeyCode::AltRight => (0x38, true),
        KeyCode::MetaRight => (0x5c, true),
        KeyCode::ContextMenu => (0x5d, true),
        KeyCode::ControlRight => (0x1d, true),

        KeyCode::Insert => (0x52, true),
        KeyCode::Home => (0x47, true),
        KeyCode::PageUp => (0x49, true),
        KeyCode::DeleteForward => (0x53, true),
        KeyCode::End => (0x4f, true),
        KeyCode::PageDown => (0x51, true),
        KeyCode::ArrowRight => (0x4d, true),
        KeyCode::ArrowLeft => (0x4b, true),
        KeyCode::ArrowDown => (0x50, true),
        KeyCode::ArrowUp => (0x48, true),

        KeyCode::NumLock => (0x45, true),
        KeyCode::NumpadDivide => (0x35, true),
        KeyCode::NumpadMultiply => (0x37, false),
        KeyCode::NumpadSubtract => (0x4a, false),
        KeyCode::NumpadAdd => (0x4e, false),
        KeyCode::NumpadEnter => (0x1c, true),
        KeyCode::Numpad1 => (0x4f, false),
        KeyCode::Numpad2 => (0x50, false),
        KeyCode::Numpad3 => (0x51, false),
        KeyCode::Numpad4 => (0x4b, false),
        KeyCode::Numpad5 => (0x4c, false),
        KeyCode::Numpad6 => (0x4d, false),
        KeyCode::Numpad7 => (0x47, false),
        KeyCode::Numpad8 => (0x48, false),
        KeyCode::Numpad9 => (0x49, false),
        KeyCode::Numpad0 => (0x52, false),
        KeyCode::NumpadDecimal => (0x53, false),

        KeyCode::IntlRo => (0x73, false),
        KeyCode::IntlYen => (0x7d, false),
        KeyCode::KanaMode => (0x70, false),
        KeyCode::Convert => (0x79, false),
        KeyCode::NonConvert => (0x7b, false),

        KeyCode::Power => (0x5e, true),
        KeyCode::AudioVolumeMute => (0x20, true),
        KeyCode::AudioVolumeDown => (0x2e, true),
        KeyCode::AudioVolumeUp => (0x30, true),
        KeyCode::MediaPlayPause => (0x22, true),
        KeyCode::MediaStop => (0x24, true),
        KeyCode::MediaTrackNext => (0x19, true),
        KeyCode::MediaTrackPrevious => (0x10, true),

        // Pause requires a multi-byte E1 sequence that `SendInput` cannot
        // faithfully represent as one ordinary scan-code record. Fn, several
        // international/numpad positions, unidentified usages, and newer
        // non-exhaustive variants likewise fail closed until given an audited
        // native mapping.
        _ => return None,
    };
    Some(ScanCode { code, extended })
}

#[cfg(any(windows, test))]
pub(crate) fn mouse_action(button: PointerButton, state: ButtonState) -> Option<MouseAction> {
    Some(match (button, state) {
        (PointerButton::Left, ButtonState::Pressed) => MouseAction::LeftDown,
        (PointerButton::Left, ButtonState::Released) => MouseAction::LeftUp,
        (PointerButton::Right, ButtonState::Pressed) => MouseAction::RightDown,
        (PointerButton::Right, ButtonState::Released) => MouseAction::RightUp,
        (PointerButton::Middle, ButtonState::Pressed) => MouseAction::MiddleDown,
        (PointerButton::Middle, ButtonState::Released) => MouseAction::MiddleUp,
        (PointerButton::Back, ButtonState::Pressed) => MouseAction::XDown(1),
        (PointerButton::Back, ButtonState::Released) => MouseAction::XUp(1),
        (PointerButton::Forward, ButtonState::Pressed) => MouseAction::XDown(2),
        (PointerButton::Forward, ButtonState::Released) => MouseAction::XUp(2),
        (PointerButton::Other(_), _) => return None,
    })
}

/// One fully resolved keyboard `SendInput` record, before flag assembly.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyRecord {
    pub mapping: ScanCode,
    pub key_up: bool,
}

/// Resolves a key event from a macOS source keyboard through a modifier-role
/// policy into the scan-code record the injector submits, so chord ordering
/// (which modifier went down first, which comes up first) is testable without
/// Windows. Returns `None` when the resolved key has no reliable `SendInput`
/// scan-code mapping.
#[cfg(any(windows, test))]
#[must_use]
pub(crate) fn key_record_for_macos_source(
    roles: ModifierRoleMapping,
    key: KeyCode,
    state: KeyState,
) -> Option<KeyRecord> {
    let mapping = scan_code(roles.map_macos_source(key))?;
    Some(KeyRecord {
        mapping,
        key_up: key_is_released(state),
    })
}

#[cfg(any(windows, test))]
pub(crate) const fn key_is_released(state: KeyState) -> bool {
    matches!(state, KeyState::Released)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

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
        key_record_for_macos_source(roles, key, state).expect("chord keys always resolve")
    }

    #[test]
    fn functional_mode_swaps_command_and_control_roles_only() {
        let roles = ModifierRoleMapping::Functional;
        for (source, destination) in [
            (KeyCode::MetaLeft, KeyCode::ControlLeft),
            (KeyCode::MetaRight, KeyCode::ControlRight),
            (KeyCode::ControlLeft, KeyCode::MetaLeft),
            (KeyCode::ControlRight, KeyCode::MetaRight),
            // Option already occupies the correct Alt/AltGr position.
            (KeyCode::AltLeft, KeyCode::AltLeft),
            (KeyCode::AltRight, KeyCode::AltRight),
            // Shift never remaps.
            (KeyCode::ShiftLeft, KeyCode::ShiftLeft),
            (KeyCode::ShiftRight, KeyCode::ShiftRight),
        ] {
            assert_eq!(roles.map_macos_source(source), destination);
        }
    }

    #[test]
    fn positional_mode_swaps_command_and_option_positions_only() {
        let roles = ModifierRoleMapping::Positional;
        for (source, destination) in [
            (KeyCode::MetaLeft, KeyCode::AltLeft),
            (KeyCode::MetaRight, KeyCode::AltRight),
            (KeyCode::AltLeft, KeyCode::MetaLeft),
            (KeyCode::AltRight, KeyCode::MetaRight),
            (KeyCode::ControlLeft, KeyCode::ControlLeft),
            (KeyCode::ControlRight, KeyCode::ControlRight),
            (KeyCode::ShiftLeft, KeyCode::ShiftLeft),
            (KeyCode::ShiftRight, KeyCode::ShiftRight),
        ] {
            assert_eq!(roles.map_macos_source(source), destination);
        }
    }

    #[test]
    fn identity_mode_passes_every_modifier_through() {
        for key in ROLE_MODIFIERS {
            assert_eq!(ModifierRoleMapping::Identity.map_macos_source(key), key);
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
            let mut destinations = HashSet::new();
            for key in ROLE_MODIFIERS {
                assert!(
                    destinations.insert(roles.map_macos_source(key)),
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
                assert_eq!(roles.map_macos_source(key), key);
            }
        }
    }

    #[test]
    fn functional_chord_cmd_shift_c_presses_and_releases_in_order() {
        let roles = ModifierRoleMapping::Functional;
        let presses = [
            (KeyCode::MetaLeft, KeyState::Pressed),
            (KeyCode::ShiftLeft, KeyState::Pressed),
            (KeyCode::KeyC, KeyState::Pressed),
        ];

        let downs: Vec<_> = presses
            .iter()
            .map(|&(key, state)| record(roles, key, state))
            .collect();
        // Cmd maps to Ctrl (0x1d, base); Shift and C are untouched.
        assert_eq!(
            downs[0].mapping,
            ScanCode {
                code: 0x1d,
                extended: false
            }
        );
        assert_eq!(
            downs[1].mapping,
            ScanCode {
                code: 0x2a,
                extended: false
            }
        );
        assert_eq!(
            downs[2].mapping,
            ScanCode {
                code: 0x2e,
                extended: false
            }
        );
        assert!(downs.iter().all(|down| !down.key_up));

        // Releases arrive in reverse press order, each with KEYUP set.
        let ups: Vec<_> = presses
            .iter()
            .rev()
            .map(|&(key, _)| record(roles, key, KeyState::Released))
            .collect();
        for (down, up) in downs.iter().zip(ups.iter().rev()) {
            assert_eq!(down.mapping, up.mapping);
        }
        assert!(ups.iter().all(|up| up.key_up));
    }

    #[test]
    fn functional_chord_releasing_command_before_c_still_releases_c() {
        let roles = ModifierRoleMapping::Functional;
        let cmd_down = record(roles, KeyCode::MetaLeft, KeyState::Pressed);
        let c_down = record(roles, KeyCode::KeyC, KeyState::Pressed);
        // The user drops the modifier first; the C release must still resolve
        // to the same scan code with a KEYUP flag and no error.
        let cmd_up = record(roles, KeyCode::MetaLeft, KeyState::Released);
        let c_up = record(roles, KeyCode::KeyC, KeyState::Released);

        assert!(!cmd_down.key_up);
        assert!(!c_down.key_up);
        assert!(cmd_up.key_up);
        assert!(c_up.key_up);
        assert_eq!(cmd_down.mapping, cmd_up.mapping);
        assert_eq!(c_down.mapping, c_up.mapping);
        assert_eq!(
            c_up.mapping,
            ScanCode {
                code: 0x2e,
                extended: false
            }
        );
    }

    #[test]
    fn functional_dual_modifier_hold_presses_without_collision() {
        let roles = ModifierRoleMapping::Functional;
        let cmd_down = record(roles, KeyCode::MetaLeft, KeyState::Pressed);
        let ctrl_down = record(roles, KeyCode::ControlLeft, KeyState::Pressed);
        // Cmd maps to Ctrl (0x1d, base) while Ctrl maps to Win (0x5b,
        // extended): both held keys remain independently addressable.
        assert_eq!(
            cmd_down.mapping,
            ScanCode {
                code: 0x1d,
                extended: false
            }
        );
        assert_eq!(
            ctrl_down.mapping,
            ScanCode {
                code: 0x5b,
                extended: true
            }
        );
        assert_ne!(cmd_down.mapping, ctrl_down.mapping);

        let ctrl_up = record(roles, KeyCode::ControlLeft, KeyState::Released);
        let cmd_up = record(roles, KeyCode::MetaLeft, KeyState::Released);
        assert_eq!(ctrl_up.mapping, ctrl_down.mapping);
        assert_eq!(cmd_up.mapping, cmd_down.mapping);
        assert!(ctrl_up.key_up && cmd_up.key_up);
    }

    #[test]
    fn left_and_right_modifiers_preserve_physical_location() {
        assert_eq!(
            scan_code(KeyCode::ControlLeft),
            Some(ScanCode {
                code: 0x1d,
                extended: false
            })
        );
        assert_eq!(
            scan_code(KeyCode::ControlRight),
            Some(ScanCode {
                code: 0x1d,
                extended: true
            })
        );
        assert!(scan_code(KeyCode::AltRight).unwrap().extended);
    }

    #[test]
    fn macos_shortcut_modifiers_map_to_windows_roles() {
        assert_eq!(
            windows_key_for_macos_source(KeyCode::MetaLeft),
            KeyCode::AltLeft
        );
        assert_eq!(
            windows_key_for_macos_source(KeyCode::MetaRight),
            KeyCode::AltRight
        );
        assert_eq!(
            windows_key_for_macos_source(KeyCode::AltLeft),
            KeyCode::MetaLeft
        );
        assert_eq!(
            windows_key_for_macos_source(KeyCode::AltRight),
            KeyCode::MetaRight
        );
        assert_eq!(windows_key_for_macos_source(KeyCode::Tab), KeyCode::Tab);
    }

    #[test]
    fn navigation_and_numpad_keys_do_not_collapse_together() {
        assert_eq!(scan_code(KeyCode::Home).unwrap().code, 0x47);
        assert_eq!(scan_code(KeyCode::Numpad7).unwrap().code, 0x47);
        assert!(scan_code(KeyCode::Home).unwrap().extended);
        assert!(!scan_code(KeyCode::Numpad7).unwrap().extended);
    }

    #[test]
    fn extra_mouse_buttons_map_to_windows_xbuttons() {
        assert_eq!(
            mouse_action(PointerButton::Back, ButtonState::Pressed),
            Some(MouseAction::XDown(1))
        );
        assert_eq!(
            mouse_action(PointerButton::Forward, ButtonState::Released),
            Some(MouseAction::XUp(2))
        );
        assert_eq!(
            mouse_action(PointerButton::Other(9), ButtonState::Pressed),
            None
        );
    }

    #[test]
    fn keys_without_a_reliable_sendinput_scan_sequence_are_rejected() {
        assert_eq!(scan_code(KeyCode::Fn), None);
        assert_eq!(scan_code(KeyCode::Pause), None);
        assert_eq!(
            scan_code(KeyCode::Unidentified {
                usage_page: 7,
                usage_id: 250
            }),
            None
        );
    }
}
