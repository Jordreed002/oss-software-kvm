#[cfg(windows)]
use kvm_input::KeyState;
#[cfg(any(windows, test))]
use kvm_input::{ButtonState, KeyCode, PointerButton};

/// Translates a macOS keyboard's shortcut modifiers to Windows roles.
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

#[cfg(windows)]
pub(crate) const fn key_is_released(state: KeyState) -> bool {
    matches!(state, KeyState::Released)
}

#[cfg(test)]
mod tests {
    use super::*;

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
