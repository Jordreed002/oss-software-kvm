use std::fmt;

use serde::{Deserialize, Serialize};

/// A physical key position, independent of the source keyboard layout.
///
/// Named variants follow USB HID usage positions where possible. `Unidentified`
/// preserves a usage that a backend understands but this version does not yet
/// name, without admitting platform-native scan codes into the shared model.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum KeyCode {
    Escape,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    F13,
    F14,
    F15,
    F16,
    F17,
    F18,
    F19,
    F20,
    F21,
    F22,
    F23,
    F24,
    PrintScreen,
    ScrollLock,
    Pause,

    Backquote,
    Digit1,
    Digit2,
    Digit3,
    Digit4,
    Digit5,
    Digit6,
    Digit7,
    Digit8,
    Digit9,
    Digit0,
    Minus,
    Equal,
    Backspace,

    Tab,
    KeyQ,
    KeyW,
    KeyE,
    KeyR,
    KeyT,
    KeyY,
    KeyU,
    KeyI,
    KeyO,
    KeyP,
    BracketLeft,
    BracketRight,
    Backslash,

    CapsLock,
    KeyA,
    KeyS,
    KeyD,
    KeyF,
    KeyG,
    KeyH,
    KeyJ,
    KeyK,
    KeyL,
    Semicolon,
    Quote,
    Enter,

    ShiftLeft,
    IntlBackslash,
    KeyZ,
    KeyX,
    KeyC,
    KeyV,
    KeyB,
    KeyN,
    KeyM,
    Comma,
    Period,
    Slash,
    ShiftRight,

    ControlLeft,
    MetaLeft,
    AltLeft,
    Space,
    AltRight,
    MetaRight,
    ContextMenu,
    ControlRight,
    Fn,

    Insert,
    Home,
    PageUp,
    DeleteForward,
    End,
    PageDown,
    ArrowRight,
    ArrowLeft,
    ArrowDown,
    ArrowUp,

    NumLock,
    NumpadDivide,
    NumpadMultiply,
    NumpadSubtract,
    NumpadAdd,
    NumpadEnter,
    Numpad1,
    Numpad2,
    Numpad3,
    Numpad4,
    Numpad5,
    Numpad6,
    Numpad7,
    Numpad8,
    Numpad9,
    Numpad0,
    NumpadDecimal,
    NumpadEqual,
    NumpadComma,
    NumpadParenLeft,
    NumpadParenRight,

    IntlRo,
    IntlYen,
    KanaMode,
    Convert,
    NonConvert,
    Lang1,
    Lang2,
    Lang3,
    Lang4,
    Lang5,

    Help,
    Power,
    Eject,
    AudioVolumeMute,
    AudioVolumeDown,
    AudioVolumeUp,
    MediaPlayPause,
    MediaStop,
    MediaTrackNext,
    MediaTrackPrevious,

    /// USB HID usage page and usage identifier not named by this version.
    Unidentified {
        usage_page: u16,
        usage_id: u16,
    },
}

impl fmt::Debug for KeyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyCode([REDACTED])")
    }
}

impl KeyCode {
    #[must_use]
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            Self::ShiftLeft
                | Self::ShiftRight
                | Self::ControlLeft
                | Self::ControlRight
                | Self::AltLeft
                | Self::AltRight
                | Self::MetaLeft
                | Self::MetaRight
                | Self::Fn
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_modifier_positions_are_classified_as_modifiers() {
        assert!(KeyCode::ControlLeft.is_modifier());
        assert!(KeyCode::MetaRight.is_modifier());
        assert!(KeyCode::Fn.is_modifier());
        assert!(!KeyCode::CapsLock.is_modifier());
        assert!(!KeyCode::KeyA.is_modifier());
    }

    #[test]
    fn unidentified_usage_retains_platform_neutral_hid_identity() {
        let key = KeyCode::Unidentified {
            usage_page: 0x0c,
            usage_id: 0x1234,
        };
        assert_eq!(
            key,
            KeyCode::Unidentified {
                usage_page: 0x0c,
                usage_id: 0x1234
            }
        );
    }

    #[test]
    fn key_diagnostics_hide_named_and_unidentified_controls() {
        let rendered = format!(
            "{:?} {:?}",
            KeyCode::KeyA,
            KeyCode::Unidentified {
                usage_page: 54_321,
                usage_id: 12_345,
            }
        );
        for secret in ["KeyA", "Unidentified", "54321", "12345"] {
            assert!(!rendered.contains(secret));
        }
    }
}
