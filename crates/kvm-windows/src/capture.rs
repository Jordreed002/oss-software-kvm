use kvm_daemon::EventClassification;
use kvm_input::{ButtonState, InputPayload, KeyCode, KeyState, PointerButton};

use crate::KVM_INJECTION_TAG;

pub(crate) const RAW_KEY_BREAK: u16 = 0x01;
pub(crate) const RAW_KEY_E0: u16 = 0x02;
pub(crate) const RAW_KEY_E1: u16 = 0x04;

pub(crate) const RAW_MOUSE_MOVE_ABSOLUTE: u16 = 0x01;
pub(crate) const RAW_MOUSE_LEFT_DOWN: u16 = 0x0001;
pub(crate) const RAW_MOUSE_LEFT_UP: u16 = 0x0002;
pub(crate) const RAW_MOUSE_RIGHT_DOWN: u16 = 0x0004;
pub(crate) const RAW_MOUSE_RIGHT_UP: u16 = 0x0008;
pub(crate) const RAW_MOUSE_MIDDLE_DOWN: u16 = 0x0010;
pub(crate) const RAW_MOUSE_MIDDLE_UP: u16 = 0x0020;
pub(crate) const RAW_MOUSE_BACK_DOWN: u16 = 0x0040;
pub(crate) const RAW_MOUSE_BACK_UP: u16 = 0x0080;
pub(crate) const RAW_MOUSE_FORWARD_DOWN: u16 = 0x0100;
pub(crate) const RAW_MOUSE_FORWARD_UP: u16 = 0x0200;
pub(crate) const RAW_MOUSE_WHEEL: u16 = 0x0400;
pub(crate) const RAW_MOUSE_HWHEEL: u16 = 0x0800;

const WINDOWS_WHEEL_DELTA: f64 = 120.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageOrigin {
    Hardware,
    Injected,
    System,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawKeyboardPacket {
    pub scan_code: u16,
    pub flags: u16,
    pub virtual_key: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawMousePacket {
    pub state_flags: u16,
    pub button_flags: u16,
    pub button_data: u16,
    pub dx: i32,
    pub dy: i32,
}

pub(crate) fn classify_raw_input(
    extra_information: u32,
    _origin: MessageOrigin,
    _has_device_handle: bool,
) -> EventClassification {
    if extra_information == KVM_INJECTION_TAG {
        return EventClassification::InjectedByKvm;
    }
    // `IMO_HARDWARE` also includes UIAccess-process injection, and a non-null
    // Raw Input device handle is attribution rather than proof of a physical
    // origin. Until a stronger correlation mechanism is validated, all
    // untagged Raw Input fails closed.
    EventClassification::Unknown
}

pub(crate) fn translate_keyboard(packet: RawKeyboardPacket) -> Option<InputPayload> {
    // Windows emits VKey 0xFF for synthetic prefix records such as the fake
    // Shift surrounding PrintScreen. Forwarding those would create a key the
    // user never physically pressed.
    if packet.virtual_key == 0xff {
        return None;
    }
    let extended = packet.flags & RAW_KEY_E0 != 0;
    let e1 = packet.flags & RAW_KEY_E1 != 0;
    let code = key_from_scan_code(packet.scan_code, extended, e1)?;
    let state = if packet.flags & RAW_KEY_BREAK == 0 {
        KeyState::Pressed
    } else {
        KeyState::Released
    };
    Some(InputPayload::Key { code, state })
}

pub(crate) fn translate_mouse(packet: RawMousePacket) -> Vec<InputPayload> {
    let mut events = Vec::with_capacity(7);

    // Absolute Raw Input coordinates are normalized desktop coordinates, not
    // deltas. Converting them requires per-device prior state and virtual-screen
    // metrics; silently treating them as relative would cause a pointer jump.
    if packet.state_flags & RAW_MOUSE_MOVE_ABSOLUTE == 0 && (packet.dx != 0 || packet.dy != 0) {
        events.push(InputPayload::PointerMove {
            dx: f64::from(packet.dx),
            dy: f64::from(packet.dy),
        });
    }

    push_button(
        &mut events,
        packet.button_flags,
        RAW_MOUSE_LEFT_DOWN,
        RAW_MOUSE_LEFT_UP,
        PointerButton::Left,
    );
    push_button(
        &mut events,
        packet.button_flags,
        RAW_MOUSE_RIGHT_DOWN,
        RAW_MOUSE_RIGHT_UP,
        PointerButton::Right,
    );
    push_button(
        &mut events,
        packet.button_flags,
        RAW_MOUSE_MIDDLE_DOWN,
        RAW_MOUSE_MIDDLE_UP,
        PointerButton::Middle,
    );
    push_button(
        &mut events,
        packet.button_flags,
        RAW_MOUSE_BACK_DOWN,
        RAW_MOUSE_BACK_UP,
        PointerButton::Back,
    );
    push_button(
        &mut events,
        packet.button_flags,
        RAW_MOUSE_FORWARD_DOWN,
        RAW_MOUSE_FORWARD_UP,
        PointerButton::Forward,
    );

    let wheel_delta =
        f64::from(i16::from_ne_bytes(packet.button_data.to_ne_bytes())) / WINDOWS_WHEEL_DELTA;
    if packet.button_flags & RAW_MOUSE_WHEEL != 0 {
        events.push(InputPayload::Scroll {
            horizontal: 0.0,
            vertical: wheel_delta,
        });
    }
    if packet.button_flags & RAW_MOUSE_HWHEEL != 0 {
        events.push(InputPayload::Scroll {
            horizontal: wheel_delta,
            vertical: 0.0,
        });
    }
    events
}

pub(crate) const fn is_state_transition(payload: InputPayload) -> bool {
    matches!(
        payload,
        InputPayload::Key { .. } | InputPayload::PointerButton { .. }
    )
}

fn push_button(
    events: &mut Vec<InputPayload>,
    flags: u16,
    down_flag: u16,
    up_flag: u16,
    button: PointerButton,
) {
    if flags & down_flag != 0 {
        events.push(InputPayload::PointerButton {
            button,
            state: ButtonState::Pressed,
        });
    }
    if flags & up_flag != 0 {
        events.push(InputPayload::PointerButton {
            button,
            state: ButtonState::Released,
        });
    }
}

#[allow(clippy::too_many_lines)] // Explicit scan positions are auditable and avoid layout lookup.
fn key_from_scan_code(scan: u16, extended: bool, e1: bool) -> Option<KeyCode> {
    if e1 && scan == 0x45 {
        return Some(KeyCode::Pause);
    }

    Some(match (scan, extended) {
        (0x01, false) => KeyCode::Escape,
        (0x3b, false) => KeyCode::F1,
        (0x3c, false) => KeyCode::F2,
        (0x3d, false) => KeyCode::F3,
        (0x3e, false) => KeyCode::F4,
        (0x3f, false) => KeyCode::F5,
        (0x40, false) => KeyCode::F6,
        (0x41, false) => KeyCode::F7,
        (0x42, false) => KeyCode::F8,
        (0x43, false) => KeyCode::F9,
        (0x44, false) => KeyCode::F10,
        (0x57, false) => KeyCode::F11,
        (0x58, false) => KeyCode::F12,
        (0x64, false) => KeyCode::F13,
        (0x65, false) => KeyCode::F14,
        (0x66, false) => KeyCode::F15,
        (0x67, false) => KeyCode::F16,
        (0x68, false) => KeyCode::F17,
        (0x69, false) => KeyCode::F18,
        (0x6a, false) => KeyCode::F19,
        (0x6b, false) => KeyCode::F20,
        (0x6c, false) => KeyCode::F21,
        (0x6d, false) => KeyCode::F22,
        (0x6e, false) => KeyCode::F23,
        (0x76, false) => KeyCode::F24,
        (0x37, true) => KeyCode::PrintScreen,
        (0x46, false) => KeyCode::ScrollLock,

        (0x29, false) => KeyCode::Backquote,
        (0x02, false) => KeyCode::Digit1,
        (0x03, false) => KeyCode::Digit2,
        (0x04, false) => KeyCode::Digit3,
        (0x05, false) => KeyCode::Digit4,
        (0x06, false) => KeyCode::Digit5,
        (0x07, false) => KeyCode::Digit6,
        (0x08, false) => KeyCode::Digit7,
        (0x09, false) => KeyCode::Digit8,
        (0x0a, false) => KeyCode::Digit9,
        (0x0b, false) => KeyCode::Digit0,
        (0x0c, false) => KeyCode::Minus,
        (0x0d, false) => KeyCode::Equal,
        (0x0e, false) => KeyCode::Backspace,

        (0x0f, false) => KeyCode::Tab,
        (0x10, false) => KeyCode::KeyQ,
        (0x11, false) => KeyCode::KeyW,
        (0x12, false) => KeyCode::KeyE,
        (0x13, false) => KeyCode::KeyR,
        (0x14, false) => KeyCode::KeyT,
        (0x15, false) => KeyCode::KeyY,
        (0x16, false) => KeyCode::KeyU,
        (0x17, false) => KeyCode::KeyI,
        (0x18, false) => KeyCode::KeyO,
        (0x19, false) => KeyCode::KeyP,
        (0x1a, false) => KeyCode::BracketLeft,
        (0x1b, false) => KeyCode::BracketRight,
        (0x2b, false) => KeyCode::Backslash,

        (0x3a, false) => KeyCode::CapsLock,
        (0x1e, false) => KeyCode::KeyA,
        (0x1f, false) => KeyCode::KeyS,
        (0x20, false) => KeyCode::KeyD,
        (0x21, false) => KeyCode::KeyF,
        (0x22, false) => KeyCode::KeyG,
        (0x23, false) => KeyCode::KeyH,
        (0x24, false) => KeyCode::KeyJ,
        (0x25, false) => KeyCode::KeyK,
        (0x26, false) => KeyCode::KeyL,
        (0x27, false) => KeyCode::Semicolon,
        (0x28, false) => KeyCode::Quote,
        (0x1c, false) => KeyCode::Enter,

        (0x2a, false) => KeyCode::ShiftLeft,
        (0x56, false) => KeyCode::IntlBackslash,
        (0x2c, false) => KeyCode::KeyZ,
        (0x2d, false) => KeyCode::KeyX,
        (0x2e, false) => KeyCode::KeyC,
        (0x2f, false) => KeyCode::KeyV,
        (0x30, false) => KeyCode::KeyB,
        (0x31, false) => KeyCode::KeyN,
        (0x32, false) => KeyCode::KeyM,
        (0x33, false) => KeyCode::Comma,
        (0x34, false) => KeyCode::Period,
        (0x35, false) => KeyCode::Slash,
        (0x36, false) => KeyCode::ShiftRight,

        (0x1d, false) => KeyCode::ControlLeft,
        (0x5b, true) => KeyCode::MetaLeft,
        (0x38, false) => KeyCode::AltLeft,
        (0x39, false) => KeyCode::Space,
        (0x38, true) => KeyCode::AltRight,
        (0x5c, true) => KeyCode::MetaRight,
        (0x5d, true) => KeyCode::ContextMenu,
        (0x1d, true) => KeyCode::ControlRight,

        (0x52, true) => KeyCode::Insert,
        (0x47, true) => KeyCode::Home,
        (0x49, true) => KeyCode::PageUp,
        (0x53, true) => KeyCode::DeleteForward,
        (0x4f, true) => KeyCode::End,
        (0x51, true) => KeyCode::PageDown,
        (0x4d, true) => KeyCode::ArrowRight,
        (0x4b, true) => KeyCode::ArrowLeft,
        (0x50, true) => KeyCode::ArrowDown,
        (0x48, true) => KeyCode::ArrowUp,

        (0x45, true) => KeyCode::NumLock,
        (0x35, true) => KeyCode::NumpadDivide,
        (0x37, false) => KeyCode::NumpadMultiply,
        (0x4a, false) => KeyCode::NumpadSubtract,
        (0x4e, false) => KeyCode::NumpadAdd,
        (0x1c, true) => KeyCode::NumpadEnter,
        (0x4f, false) => KeyCode::Numpad1,
        (0x50, false) => KeyCode::Numpad2,
        (0x51, false) => KeyCode::Numpad3,
        (0x4b, false) => KeyCode::Numpad4,
        (0x4c, false) => KeyCode::Numpad5,
        (0x4d, false) => KeyCode::Numpad6,
        (0x47, false) => KeyCode::Numpad7,
        (0x48, false) => KeyCode::Numpad8,
        (0x49, false) => KeyCode::Numpad9,
        (0x52, false) => KeyCode::Numpad0,
        (0x53, false) => KeyCode::NumpadDecimal,

        (0x73, false) => KeyCode::IntlRo,
        (0x7d, false) => KeyCode::IntlYen,
        (0x70, false) => KeyCode::KanaMode,
        (0x79, false) => KeyCode::Convert,
        (0x7b, false) => KeyCode::NonConvert,

        (0x5e, true) => KeyCode::Power,
        (0x20, true) => KeyCode::AudioVolumeMute,
        (0x2e, true) => KeyCode::AudioVolumeDown,
        (0x30, true) => KeyCode::AudioVolumeUp,
        (0x22, true) => KeyCode::MediaPlayPause,
        (0x24, true) => KeyCode::MediaStop,
        (0x19, true) => KeyCode::MediaTrackNext,
        (0x10, true) => KeyCode::MediaTrackPrevious,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_make_break_and_extended_modifiers() {
        assert_eq!(
            translate_keyboard(RawKeyboardPacket {
                scan_code: 0x1e,
                flags: 0,
                virtual_key: 0x41,
            }),
            Some(InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Pressed,
            })
        );
        assert_eq!(
            translate_keyboard(RawKeyboardPacket {
                scan_code: 0x1d,
                flags: RAW_KEY_E0 | RAW_KEY_BREAK,
                virtual_key: 0xa3,
            }),
            Some(InputPayload::Key {
                code: KeyCode::ControlRight,
                state: KeyState::Released,
            })
        );
    }

    #[test]
    fn navigation_and_numpad_positions_stay_distinct() {
        assert_eq!(
            translate_keyboard(RawKeyboardPacket {
                scan_code: 0x47,
                flags: RAW_KEY_E0,
                virtual_key: 0x24,
            }),
            Some(InputPayload::Key {
                code: KeyCode::Home,
                state: KeyState::Pressed,
            })
        );
        assert_eq!(
            translate_keyboard(RawKeyboardPacket {
                scan_code: 0x47,
                flags: 0,
                virtual_key: 0x67,
            }),
            Some(InputPayload::Key {
                code: KeyCode::Numpad7,
                state: KeyState::Pressed,
            })
        );
    }

    #[test]
    fn translates_combined_mouse_packet_in_native_order() {
        let events = translate_mouse(RawMousePacket {
            state_flags: 0,
            button_flags: RAW_MOUSE_LEFT_DOWN | RAW_MOUSE_WHEEL,
            button_data: 120,
            dx: 4,
            dy: -2,
        });
        assert_eq!(
            events,
            vec![
                InputPayload::PointerMove { dx: 4.0, dy: -2.0 },
                InputPayload::PointerButton {
                    button: PointerButton::Left,
                    state: ButtonState::Pressed,
                },
                InputPayload::Scroll {
                    horizontal: 0.0,
                    vertical: 1.0,
                },
            ]
        );
    }

    #[test]
    fn preserves_signed_horizontal_wheel_delta() {
        let negative_delta = u16::from_ne_bytes((-120_i16).to_ne_bytes());
        assert_eq!(
            translate_mouse(RawMousePacket {
                state_flags: 0,
                button_flags: RAW_MOUSE_HWHEEL,
                button_data: negative_delta,
                dx: 0,
                dy: 0,
            }),
            vec![InputPayload::Scroll {
                horizontal: -1.0,
                vertical: 0.0,
            }]
        );
    }

    #[test]
    fn absolute_motion_is_not_misreported_as_relative() {
        assert!(translate_mouse(RawMousePacket {
            state_flags: RAW_MOUSE_MOVE_ABSOLUTE,
            button_flags: 0,
            button_data: 0,
            dx: 32_000,
            dy: 32_000,
        })
        .is_empty());
    }

    #[test]
    fn only_kvm_tag_gets_a_proven_classification() {
        assert_eq!(
            classify_raw_input(0, MessageOrigin::Hardware, true),
            EventClassification::Unknown
        );
        assert_eq!(
            classify_raw_input(KVM_INJECTION_TAG, MessageOrigin::Injected, false),
            EventClassification::InjectedByKvm
        );
        assert_eq!(
            classify_raw_input(123, MessageOrigin::Injected, false),
            EventClassification::Unknown
        );
        assert_eq!(
            classify_raw_input(0, MessageOrigin::Unavailable, true),
            EventClassification::Unknown
        );
        assert_eq!(
            classify_raw_input(0, MessageOrigin::System, true),
            EventClassification::Unknown
        );
        assert_eq!(
            classify_raw_input(0, MessageOrigin::Hardware, false),
            EventClassification::Unknown
        );
    }

    #[test]
    fn ignores_windows_synthetic_prefix_keyboard_records() {
        assert_eq!(
            translate_keyboard(RawKeyboardPacket {
                scan_code: 0x2a,
                flags: RAW_KEY_E0,
                virtual_key: 0xff,
            }),
            None
        );
    }

    #[test]
    fn only_key_and_button_events_require_lossless_queue_admission() {
        assert!(is_state_transition(InputPayload::Key {
            code: KeyCode::KeyA,
            state: KeyState::Pressed,
        }));
        assert!(is_state_transition(InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Released,
        }));
        assert!(!is_state_transition(InputPayload::PointerMove {
            dx: 1.0,
            dy: 2.0,
        }));
        assert!(!is_state_transition(InputPayload::Scroll {
            horizontal: 0.0,
            vertical: 1.0,
        }));
    }
}
