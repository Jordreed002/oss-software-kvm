use kvm_input::KeyCode;

/// Maps a physical key position to the corresponding macOS virtual key code.
///
/// Media keys and PC-only positions intentionally return `None`; synthesizing
/// them requires a separate `NX_SYSDEFINED` path rather than pretending they
/// are ordinary keyboard events.
#[must_use]
#[allow(clippy::too_many_lines)]
pub const fn mac_virtual_key(key: KeyCode) -> Option<u16> {
    Some(match key {
        KeyCode::KeyA => 0x00,
        KeyCode::KeyS => 0x01,
        KeyCode::KeyD => 0x02,
        KeyCode::KeyF => 0x03,
        KeyCode::KeyH => 0x04,
        KeyCode::KeyG => 0x05,
        KeyCode::KeyZ => 0x06,
        KeyCode::KeyX => 0x07,
        KeyCode::KeyC => 0x08,
        KeyCode::KeyV => 0x09,
        KeyCode::IntlBackslash => 0x0a,
        KeyCode::KeyB => 0x0b,
        KeyCode::KeyQ => 0x0c,
        KeyCode::KeyW => 0x0d,
        KeyCode::KeyE => 0x0e,
        KeyCode::KeyR => 0x0f,
        KeyCode::KeyY => 0x10,
        KeyCode::KeyT => 0x11,
        KeyCode::Digit1 => 0x12,
        KeyCode::Digit2 => 0x13,
        KeyCode::Digit3 => 0x14,
        KeyCode::Digit4 => 0x15,
        KeyCode::Digit6 => 0x16,
        KeyCode::Digit5 => 0x17,
        KeyCode::Equal => 0x18,
        KeyCode::Digit9 => 0x19,
        KeyCode::Digit7 => 0x1a,
        KeyCode::Minus => 0x1b,
        KeyCode::Digit8 => 0x1c,
        KeyCode::Digit0 => 0x1d,
        KeyCode::BracketRight => 0x1e,
        KeyCode::KeyO => 0x1f,
        KeyCode::KeyU => 0x20,
        KeyCode::BracketLeft => 0x21,
        KeyCode::KeyI => 0x22,
        KeyCode::KeyP => 0x23,
        KeyCode::Enter => 0x24,
        KeyCode::KeyL => 0x25,
        KeyCode::KeyJ => 0x26,
        KeyCode::Quote => 0x27,
        KeyCode::KeyK => 0x28,
        KeyCode::Semicolon => 0x29,
        KeyCode::Backslash => 0x2a,
        KeyCode::Comma => 0x2b,
        KeyCode::Slash => 0x2c,
        KeyCode::KeyN => 0x2d,
        KeyCode::KeyM => 0x2e,
        KeyCode::Period => 0x2f,
        KeyCode::Tab => 0x30,
        KeyCode::Space => 0x31,
        KeyCode::Backquote => 0x32,
        KeyCode::Backspace => 0x33,
        KeyCode::Escape => 0x35,
        KeyCode::MetaRight => 0x36,
        KeyCode::MetaLeft => 0x37,
        KeyCode::ShiftLeft => 0x38,
        KeyCode::CapsLock => 0x39,
        KeyCode::AltLeft => 0x3a,
        KeyCode::ControlLeft => 0x3b,
        KeyCode::ShiftRight => 0x3c,
        KeyCode::AltRight => 0x3d,
        KeyCode::ControlRight => 0x3e,
        KeyCode::Fn => 0x3f,
        KeyCode::F17 => 0x40,
        KeyCode::NumpadDecimal => 0x41,
        KeyCode::NumpadMultiply => 0x43,
        KeyCode::NumpadAdd => 0x45,
        KeyCode::NumLock => 0x47,
        KeyCode::AudioVolumeUp => 0x48,
        KeyCode::AudioVolumeDown => 0x49,
        KeyCode::AudioVolumeMute => 0x4a,
        KeyCode::NumpadDivide => 0x4b,
        KeyCode::NumpadEnter => 0x4c,
        KeyCode::NumpadSubtract => 0x4e,
        KeyCode::F18 => 0x4f,
        KeyCode::F19 => 0x50,
        KeyCode::NumpadEqual => 0x51,
        KeyCode::Numpad0 => 0x52,
        KeyCode::Numpad1 => 0x53,
        KeyCode::Numpad2 => 0x54,
        KeyCode::Numpad3 => 0x55,
        KeyCode::Numpad4 => 0x56,
        KeyCode::Numpad5 => 0x57,
        KeyCode::Numpad6 => 0x58,
        KeyCode::Numpad7 => 0x59,
        KeyCode::F20 => 0x5a,
        KeyCode::Numpad8 => 0x5b,
        KeyCode::Numpad9 => 0x5c,
        KeyCode::IntlYen => 0x5d,
        KeyCode::IntlRo => 0x5e,
        KeyCode::NumpadComma => 0x5f,
        KeyCode::F5 => 0x60,
        KeyCode::F6 => 0x61,
        KeyCode::F7 => 0x62,
        KeyCode::F3 => 0x63,
        KeyCode::F8 => 0x64,
        KeyCode::F9 => 0x65,
        KeyCode::Lang2 => 0x66,
        KeyCode::F11 => 0x67,
        KeyCode::Lang1 => 0x68,
        KeyCode::F13 | KeyCode::PrintScreen => 0x69,
        KeyCode::F16 => 0x6a,
        KeyCode::F14 | KeyCode::ScrollLock => 0x6b,
        KeyCode::F10 => 0x6d,
        KeyCode::ContextMenu => 0x6e,
        KeyCode::F12 => 0x6f,
        KeyCode::F15 | KeyCode::Pause => 0x71,
        KeyCode::Help | KeyCode::Insert => 0x72,
        KeyCode::Home => 0x73,
        KeyCode::PageUp => 0x74,
        KeyCode::DeleteForward => 0x75,
        KeyCode::F4 => 0x76,
        KeyCode::End => 0x77,
        KeyCode::F2 => 0x78,
        KeyCode::PageDown => 0x79,
        KeyCode::F1 => 0x7a,
        KeyCode::ArrowLeft => 0x7b,
        KeyCode::ArrowRight => 0x7c,
        KeyCode::ArrowDown => 0x7d,
        KeyCode::ArrowUp => 0x7e,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_ansi_positions_and_modifiers() {
        assert_eq!(mac_virtual_key(KeyCode::KeyA), Some(0x00));
        assert_eq!(mac_virtual_key(KeyCode::Digit1), Some(0x12));
        assert_eq!(mac_virtual_key(KeyCode::MetaLeft), Some(0x37));
        assert_eq!(mac_virtual_key(KeyCode::ArrowUp), Some(0x7e));
    }

    #[test]
    fn pc_aliases_match_equivalent_apple_positions() {
        assert_eq!(
            mac_virtual_key(KeyCode::PrintScreen),
            mac_virtual_key(KeyCode::F13)
        );
        assert_eq!(
            mac_virtual_key(KeyCode::ScrollLock),
            mac_virtual_key(KeyCode::F14)
        );
    }

    #[test]
    fn unsupported_system_events_are_not_faked_as_keys() {
        assert_eq!(mac_virtual_key(KeyCode::MediaPlayPause), None);
        assert_eq!(mac_virtual_key(KeyCode::Power), None);
        assert_eq!(
            mac_virtual_key(KeyCode::Unidentified {
                usage_page: 1,
                usage_id: 255,
            }),
            None
        );
    }
}
