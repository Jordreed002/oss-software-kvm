#![cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]

use kvm_daemon::EventClassification;
use kvm_input::{ButtonState, InputPayload, KeyCode, KeyState, PointerButton};
use kvm_types::{DeviceCapabilities, DeviceKind};

use crate::KVM_EVENT_TAG;

pub(crate) const CG_EVENT_LEFT_MOUSE_DOWN: u32 = 1;
pub(crate) const CG_EVENT_LEFT_MOUSE_UP: u32 = 2;
pub(crate) const CG_EVENT_RIGHT_MOUSE_DOWN: u32 = 3;
pub(crate) const CG_EVENT_RIGHT_MOUSE_UP: u32 = 4;
pub(crate) const CG_EVENT_MOUSE_MOVED: u32 = 5;
pub(crate) const CG_EVENT_LEFT_MOUSE_DRAGGED: u32 = 6;
pub(crate) const CG_EVENT_RIGHT_MOUSE_DRAGGED: u32 = 7;
pub(crate) const CG_EVENT_KEY_DOWN: u32 = 10;
pub(crate) const CG_EVENT_KEY_UP: u32 = 11;
pub(crate) const CG_EVENT_FLAGS_CHANGED: u32 = 12;
pub(crate) const CG_EVENT_SCROLL_WHEEL: u32 = 22;
pub(crate) const CG_EVENT_OTHER_MOUSE_DOWN: u32 = 25;
pub(crate) const CG_EVENT_OTHER_MOUSE_UP: u32 = 26;
pub(crate) const CG_EVENT_OTHER_MOUSE_DRAGGED: u32 = 27;
pub(crate) const CG_EVENT_TAP_DISABLED_BY_TIMEOUT: u32 = 0xffff_fffe;
pub(crate) const CG_EVENT_TAP_DISABLED_BY_USER_INPUT: u32 = 0xffff_ffff;
pub(crate) const CG_EVENT_SOURCE_STATE_HID_SYSTEM: i64 = 1;

pub(crate) const fn quartz_key_is_down(state: KeyState) -> bool {
    !matches!(state, KeyState::Released)
}

pub(crate) const fn quartz_modifier_pressed(virtual_key: u16, flags: u64) -> Option<bool> {
    // Caps Lock (0x39) intentionally falls through: Quartz exposes its toggle
    // state rather than a reliable held-state transition, so it stays local.
    let mask = match virtual_key {
        0x3b => 0x0000_0001, // left Control
        0x38 => 0x0000_0002, // left Shift
        0x3c => 0x0000_0004, // right Shift
        0x37 => 0x0000_0008, // left Command
        0x36 => 0x0000_0010, // right Command
        0x3a => 0x0000_0020, // left Option
        0x3d => 0x0000_0040, // right Option
        0x3e => 0x0000_2000, // right Control
        0x3f => 0x0080_0000, // Fn
        _ => return None,
    };
    Some(flags & mask != 0)
}

pub(crate) const HID_PAGE_GENERIC_DESKTOP: u32 = 0x01;
pub(crate) const HID_PAGE_KEYBOARD: u32 = 0x07;
pub(crate) const HID_PAGE_BUTTON: u32 = 0x09;
pub(crate) const HID_PAGE_CONSUMER: u32 = 0x0c;

/// Classifies only IOHID observations with positive hardware evidence as
/// physical. A non-virtual element alone is insufficient because third-party
/// drivers can expose devices whose provenance cannot be proven.
pub(crate) const fn classify_iohid_observation(
    element_is_virtual: bool,
    physical_device_evidence: bool,
) -> EventClassification {
    if !element_is_virtual && physical_device_evidence {
        EventClassification::Physical
    } else {
        EventClassification::Unknown
    }
}

/// Classifies the metadata available to a future Quartz event tap.
/// Untagged Quartz events are unknown because Quartz does not prove their
/// physical device of origin.
pub const fn classify_quartz_user_data(user_data: i64) -> EventClassification {
    if user_data == KVM_EVENT_TAG {
        EventClassification::InjectedByKvm
    } else {
        EventClassification::Unknown
    }
}

/// Classifies one event received by the explicitly opted-in whole-host tap.
///
/// A Quartz source-state value is not a device identity. The HID system state
/// is nevertheless positive evidence that the event came from the hardware
/// input state table. Private and combined-session event sources remain
/// unknown, even when they carry no user-data marker.
pub(crate) const fn classify_quartz_capture(
    user_data: i64,
    source_state_id: i64,
) -> EventClassification {
    if user_data == KVM_EVENT_TAG {
        EventClassification::InjectedByKvm
    } else if source_state_id == CG_EVENT_SOURCE_STATE_HID_SYSTEM {
        EventClassification::Physical
    } else {
        EventClassification::Unknown
    }
}

pub(crate) fn translate_quartz_keyboard(
    event_type: u32,
    virtual_key: u16,
    autorepeat: bool,
    modifier_pressed: Option<bool>,
) -> Option<InputPayload> {
    let code = crate::keymap::key_from_mac_virtual_key(virtual_key)?;
    let state = match event_type {
        CG_EVENT_KEY_DOWN if autorepeat => KeyState::Repeated,
        CG_EVENT_KEY_DOWN => KeyState::Pressed,
        CG_EVENT_KEY_UP => KeyState::Released,
        CG_EVENT_FLAGS_CHANGED => {
            if modifier_pressed? {
                KeyState::Pressed
            } else {
                KeyState::Released
            }
        }
        _ => return None,
    };
    Some(InputPayload::Key { code, state })
}

pub(crate) fn translate_quartz_pointer(
    event_type: u32,
    button_number: i64,
    delta_x: f64,
    delta_y: f64,
) -> Option<InputPayload> {
    match event_type {
        CG_EVENT_MOUSE_MOVED
        | CG_EVENT_LEFT_MOUSE_DRAGGED
        | CG_EVENT_RIGHT_MOUSE_DRAGGED
        | CG_EVENT_OTHER_MOUSE_DRAGGED => {
            (delta_x.is_finite() && delta_y.is_finite() && (delta_x != 0.0 || delta_y != 0.0))
                .then_some(InputPayload::PointerMove {
                    dx: delta_x,
                    dy: delta_y,
                })
        }
        CG_EVENT_LEFT_MOUSE_DOWN => Some(InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Pressed,
        }),
        CG_EVENT_LEFT_MOUSE_UP => Some(InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Released,
        }),
        CG_EVENT_RIGHT_MOUSE_DOWN => Some(InputPayload::PointerButton {
            button: PointerButton::Right,
            state: ButtonState::Pressed,
        }),
        CG_EVENT_RIGHT_MOUSE_UP => Some(InputPayload::PointerButton {
            button: PointerButton::Right,
            state: ButtonState::Released,
        }),
        CG_EVENT_OTHER_MOUSE_DOWN | CG_EVENT_OTHER_MOUSE_UP => {
            let button = quartz_pointer_button(button_number)?;
            Some(InputPayload::PointerButton {
                button,
                state: if event_type == CG_EVENT_OTHER_MOUSE_DOWN {
                    ButtonState::Pressed
                } else {
                    ButtonState::Released
                },
            })
        }
        _ => None,
    }
}

pub(crate) fn translate_quartz_scroll(horizontal: f64, vertical: f64) -> Option<InputPayload> {
    (horizontal.is_finite() && vertical.is_finite() && (horizontal != 0.0 || vertical != 0.0))
        .then_some(InputPayload::Scroll {
            horizontal,
            vertical,
        })
}

fn quartz_pointer_button(number: i64) -> Option<PointerButton> {
    match number {
        2 => Some(PointerButton::Middle),
        3 => Some(PointerButton::Back),
        4 => Some(PointerButton::Forward),
        5..=65_535 => u16::try_from(number).ok().map(PointerButton::Other),
        _ => None,
    }
}

/// Converts one scalar IOHID value to the shared input model.
pub(crate) fn translate_hid_value(
    usage_page: u32,
    usage: u32,
    value: i64,
    is_relative: bool,
) -> Option<InputPayload> {
    match usage_page {
        HID_PAGE_KEYBOARD => hid_key_code(usage).map(|code| InputPayload::Key {
            code,
            state: if value == 0 {
                KeyState::Released
            } else {
                KeyState::Pressed
            },
        }),
        HID_PAGE_BUTTON => pointer_button(usage).map(|button| InputPayload::PointerButton {
            button,
            state: if value == 0 {
                ButtonState::Released
            } else {
                ButtonState::Pressed
            },
        }),
        HID_PAGE_GENERIC_DESKTOP => {
            if matches!(usage, 0x30 | 0x31 | 0x38) && !is_relative {
                None
            } else {
                match (usage, value) {
                    (0x30 | 0x31 | 0x38, 0) => None,
                    (0x30, dx) => Some(InputPayload::PointerMove {
                        dx: hid_axis(dx)?,
                        dy: 0.0,
                    }),
                    (0x31, dy) => Some(InputPayload::PointerMove {
                        dx: 0.0,
                        dy: hid_axis(dy)?,
                    }),
                    (0x38, vertical) => Some(InputPayload::Scroll {
                        horizontal: 0.0,
                        vertical: hid_axis(vertical)?,
                    }),
                    _ => None,
                }
            }
        }
        HID_PAGE_CONSUMER if usage == 0x0238 && !is_relative => None,
        HID_PAGE_CONSUMER => match (usage, value) {
            // AC Pan is the HID Consumer-page horizontal wheel usage.
            (0x0238, 0) => None,
            (0x0238, horizontal) => Some(InputPayload::Scroll {
                horizontal: hid_axis(horizontal)?,
                vertical: 0.0,
            }),
            (usage, value) => consumer_key_code(usage).map(|code| InputPayload::Key {
                code,
                state: if value == 0 {
                    KeyState::Released
                } else {
                    KeyState::Pressed
                },
            }),
        },
        _ => None,
    }
}

/// Applies the enumerated collection's coarse capabilities before translating
/// scalar elements. IOHID managers can report joystick and unrelated button
/// collections alongside keyboards and pointing devices.
pub(crate) const fn device_accepts_hid_value(
    kind: DeviceKind,
    capabilities: DeviceCapabilities,
    usage_page: u32,
    usage: u32,
) -> bool {
    match kind {
        DeviceKind::Keyboard => {
            capabilities.keyboard
                && (usage_page == HID_PAGE_KEYBOARD
                    || (usage_page == HID_PAGE_CONSUMER && is_consumer_key(usage)))
        }
        DeviceKind::Mouse | DeviceKind::Trackpad => match (usage_page, usage) {
            (HID_PAGE_GENERIC_DESKTOP, 0x30 | 0x31) | (HID_PAGE_BUTTON, 1..=5) => {
                capabilities.pointer
            }
            (HID_PAGE_GENERIC_DESKTOP, 0x38) => capabilities.vertical_scroll,
            (HID_PAGE_CONSUMER, 0x0238) => capabilities.horizontal_scroll,
            (HID_PAGE_BUTTON, 6..=0x1_0000) => capabilities.extra_buttons,
            _ => false,
        },
        _ => false,
    }
}

/// Only stateless deltas may be discarded under bounded-queue pressure.
pub(crate) const fn overflow_may_drop(payload: InputPayload) -> bool {
    matches!(
        payload,
        InputPayload::PointerMove { .. } | InputPayload::Scroll { .. }
    )
}

/// Positive hardware evidence used in addition to the element's virtual flag.
/// Unknown transport strings deliberately remain unclassified.
pub(crate) fn physical_device_evidence(built_in: bool, transport: Option<&str>) -> bool {
    built_in
        || transport.is_some_and(|value| {
            ["usb", "bluetooth", "bluetooth low energy", "spi", "i2c"]
                .iter()
                .any(|known| value.eq_ignore_ascii_case(known))
        })
}

const fn is_consumer_key(usage: u32) -> bool {
    consumer_key_code(usage).is_some()
}

fn timestamp_ns(raw_timestamp: u64, numerator: u32, denominator: u32) -> u64 {
    if denominator == 0 {
        return 0;
    }
    let nanos =
        u128::from(raw_timestamp).saturating_mul(u128::from(numerator)) / u128::from(denominator);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

pub(crate) fn mach_timestamp_ns(raw_timestamp: u64, numerator: u32, denominator: u32) -> u64 {
    timestamp_ns(raw_timestamp, numerator, denominator)
}

fn hid_axis(value: i64) -> Option<f64> {
    i32::try_from(value).ok().map(f64::from)
}

fn pointer_button(usage: u32) -> Option<PointerButton> {
    match usage {
        1 => Some(PointerButton::Left),
        2 => Some(PointerButton::Right),
        3 => Some(PointerButton::Middle),
        4 => Some(PointerButton::Back),
        5 => Some(PointerButton::Forward),
        6..=0x1_0000 => u16::try_from(usage - 1).ok().map(PointerButton::Other),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
const fn hid_key_code(usage: u32) -> Option<KeyCode> {
    Some(match usage {
        0x04 => KeyCode::KeyA,
        0x05 => KeyCode::KeyB,
        0x06 => KeyCode::KeyC,
        0x07 => KeyCode::KeyD,
        0x08 => KeyCode::KeyE,
        0x09 => KeyCode::KeyF,
        0x0a => KeyCode::KeyG,
        0x0b => KeyCode::KeyH,
        0x0c => KeyCode::KeyI,
        0x0d => KeyCode::KeyJ,
        0x0e => KeyCode::KeyK,
        0x0f => KeyCode::KeyL,
        0x10 => KeyCode::KeyM,
        0x11 => KeyCode::KeyN,
        0x12 => KeyCode::KeyO,
        0x13 => KeyCode::KeyP,
        0x14 => KeyCode::KeyQ,
        0x15 => KeyCode::KeyR,
        0x16 => KeyCode::KeyS,
        0x17 => KeyCode::KeyT,
        0x18 => KeyCode::KeyU,
        0x19 => KeyCode::KeyV,
        0x1a => KeyCode::KeyW,
        0x1b => KeyCode::KeyX,
        0x1c => KeyCode::KeyY,
        0x1d => KeyCode::KeyZ,
        0x1e => KeyCode::Digit1,
        0x1f => KeyCode::Digit2,
        0x20 => KeyCode::Digit3,
        0x21 => KeyCode::Digit4,
        0x22 => KeyCode::Digit5,
        0x23 => KeyCode::Digit6,
        0x24 => KeyCode::Digit7,
        0x25 => KeyCode::Digit8,
        0x26 => KeyCode::Digit9,
        0x27 => KeyCode::Digit0,
        0x28 => KeyCode::Enter,
        0x29 => KeyCode::Escape,
        0x2a => KeyCode::Backspace,
        0x2b => KeyCode::Tab,
        0x2c => KeyCode::Space,
        0x2d => KeyCode::Minus,
        0x2e => KeyCode::Equal,
        0x2f => KeyCode::BracketLeft,
        0x30 => KeyCode::BracketRight,
        0x31 => KeyCode::Backslash,
        0x32 | 0x64 => KeyCode::IntlBackslash,
        0x33 => KeyCode::Semicolon,
        0x34 => KeyCode::Quote,
        0x35 => KeyCode::Backquote,
        0x36 => KeyCode::Comma,
        0x37 => KeyCode::Period,
        0x38 => KeyCode::Slash,
        0x39 => KeyCode::CapsLock,
        0x3a => KeyCode::F1,
        0x3b => KeyCode::F2,
        0x3c => KeyCode::F3,
        0x3d => KeyCode::F4,
        0x3e => KeyCode::F5,
        0x3f => KeyCode::F6,
        0x40 => KeyCode::F7,
        0x41 => KeyCode::F8,
        0x42 => KeyCode::F9,
        0x43 => KeyCode::F10,
        0x44 => KeyCode::F11,
        0x45 => KeyCode::F12,
        0x46 => KeyCode::PrintScreen,
        0x47 => KeyCode::ScrollLock,
        0x48 => KeyCode::Pause,
        0x49 => KeyCode::Insert,
        0x4a => KeyCode::Home,
        0x4b => KeyCode::PageUp,
        0x4c => KeyCode::DeleteForward,
        0x4d => KeyCode::End,
        0x4e => KeyCode::PageDown,
        0x4f => KeyCode::ArrowRight,
        0x50 => KeyCode::ArrowLeft,
        0x51 => KeyCode::ArrowDown,
        0x52 => KeyCode::ArrowUp,
        0x53 => KeyCode::NumLock,
        0x54 => KeyCode::NumpadDivide,
        0x55 => KeyCode::NumpadMultiply,
        0x56 => KeyCode::NumpadSubtract,
        0x57 => KeyCode::NumpadAdd,
        0x58 => KeyCode::NumpadEnter,
        0x59 => KeyCode::Numpad1,
        0x5a => KeyCode::Numpad2,
        0x5b => KeyCode::Numpad3,
        0x5c => KeyCode::Numpad4,
        0x5d => KeyCode::Numpad5,
        0x5e => KeyCode::Numpad6,
        0x5f => KeyCode::Numpad7,
        0x60 => KeyCode::Numpad8,
        0x61 => KeyCode::Numpad9,
        0x62 => KeyCode::Numpad0,
        0x63 => KeyCode::NumpadDecimal,
        0x65 => KeyCode::ContextMenu,
        0x66 => KeyCode::Power,
        0x67 => KeyCode::NumpadEqual,
        0x68 => KeyCode::F13,
        0x69 => KeyCode::F14,
        0x6a => KeyCode::F15,
        0x6b => KeyCode::F16,
        0x6c => KeyCode::F17,
        0x6d => KeyCode::F18,
        0x6e => KeyCode::F19,
        0x6f => KeyCode::F20,
        0x70 => KeyCode::F21,
        0x71 => KeyCode::F22,
        0x72 => KeyCode::F23,
        0x73 => KeyCode::F24,
        0x75 => KeyCode::Help,
        0x85 => KeyCode::NumpadComma,
        0x87 => KeyCode::IntlRo,
        0x88 => KeyCode::KanaMode,
        0x89 => KeyCode::IntlYen,
        0x8a => KeyCode::Convert,
        0x8b => KeyCode::NonConvert,
        0x90 => KeyCode::Lang1,
        0x91 => KeyCode::Lang2,
        0x92 => KeyCode::Lang3,
        0x93 => KeyCode::Lang4,
        0x94 => KeyCode::Lang5,
        0xe0 => KeyCode::ControlLeft,
        0xe1 => KeyCode::ShiftLeft,
        0xe2 => KeyCode::AltLeft,
        0xe3 => KeyCode::MetaLeft,
        0xe4 => KeyCode::ControlRight,
        0xe5 => KeyCode::ShiftRight,
        0xe6 => KeyCode::AltRight,
        0xe7 => KeyCode::MetaRight,
        _ => return None,
    })
}

const fn consumer_key_code(usage: u32) -> Option<KeyCode> {
    match usage {
        0x00b5 => Some(KeyCode::MediaTrackNext),
        0x00b6 => Some(KeyCode::MediaTrackPrevious),
        0x00b7 => Some(KeyCode::MediaStop),
        0x00cd => Some(KeyCode::MediaPlayPause),
        0x00e2 => Some(KeyCode::AudioVolumeMute),
        0x00e9 => Some(KeyCode::AudioVolumeUp),
        0x00ea => Some(KeyCode::AudioVolumeDown),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyboard_translation_covers_one_way_acceptance_keys() {
        assert_eq!(
            translate_hid_value(HID_PAGE_KEYBOARD, 0x04, 1, false),
            Some(InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Pressed,
            })
        );
        assert_eq!(
            translate_hid_value(HID_PAGE_KEYBOARD, 0xe3, 0, false),
            Some(InputPayload::Key {
                code: KeyCode::MetaLeft,
                state: KeyState::Released,
            })
        );
        assert!(matches!(
            translate_hid_value(HID_PAGE_KEYBOARD, 0x2a, 1, false),
            Some(InputPayload::Key {
                code: KeyCode::Backspace,
                ..
            })
        ));
        assert!(matches!(
            translate_hid_value(HID_PAGE_KEYBOARD, 0x52, 1, false),
            Some(InputPayload::Key {
                code: KeyCode::ArrowUp,
                ..
            })
        ));
    }

    #[test]
    fn pointer_buttons_and_both_scroll_axes_translate() {
        assert_eq!(
            translate_hid_value(HID_PAGE_GENERIC_DESKTOP, 0x30, -7, true),
            Some(InputPayload::PointerMove { dx: -7.0, dy: 0.0 })
        );
        assert_eq!(
            translate_hid_value(HID_PAGE_BUTTON, 4, 1, false),
            Some(InputPayload::PointerButton {
                button: PointerButton::Back,
                state: ButtonState::Pressed,
            })
        );
        assert_eq!(
            translate_hid_value(HID_PAGE_GENERIC_DESKTOP, 0x38, 3, true),
            Some(InputPayload::Scroll {
                horizontal: 0.0,
                vertical: 3.0,
            })
        );
        assert_eq!(
            translate_hid_value(HID_PAGE_CONSUMER, 0x0238, -2, true),
            Some(InputPayload::Scroll {
                horizontal: -2.0,
                vertical: 0.0,
            })
        );
    }

    #[test]
    fn unknown_and_zero_delta_values_do_not_emit_events() {
        assert_eq!(translate_hid_value(0xffff, 1, 1, false), None);
        assert_eq!(
            translate_hid_value(HID_PAGE_GENERIC_DESKTOP, 0x30, 0, true),
            None
        );
    }

    #[test]
    fn absolute_pointer_axes_are_not_misreported_as_relative_motion() {
        assert_eq!(
            translate_hid_value(HID_PAGE_GENERIC_DESKTOP, 0x30, 24_000, false),
            None
        );
        assert_eq!(
            translate_hid_value(HID_PAGE_GENERIC_DESKTOP, 0x31, 16_000, false),
            None
        );
        assert_eq!(
            translate_hid_value(HID_PAGE_GENERIC_DESKTOP, 0x38, 120, false),
            None
        );
        assert_eq!(
            translate_hid_value(HID_PAGE_CONSUMER, 0x0238, 120, false),
            None
        );
    }

    #[test]
    fn classification_is_conservative_at_each_native_layer() {
        assert_eq!(
            classify_iohid_observation(false, true),
            EventClassification::Physical
        );
        assert_eq!(
            classify_iohid_observation(true, true),
            EventClassification::Unknown
        );
        assert_eq!(
            classify_iohid_observation(false, false),
            EventClassification::Unknown
        );
        assert_eq!(
            classify_quartz_user_data(KVM_EVENT_TAG),
            EventClassification::InjectedByKvm
        );
        assert_eq!(classify_quartz_user_data(0), EventClassification::Unknown);
    }

    #[test]
    fn collection_kind_and_capabilities_filter_unrelated_elements() {
        let mouse = DeviceCapabilities {
            pointer: true,
            vertical_scroll: true,
            horizontal_scroll: false,
            extra_buttons: false,
            keyboard: false,
        };
        assert!(device_accepts_hid_value(
            DeviceKind::Mouse,
            mouse,
            HID_PAGE_BUTTON,
            1
        ));
        assert!(!device_accepts_hid_value(
            DeviceKind::Mouse,
            mouse,
            HID_PAGE_BUTTON,
            6
        ));
        assert!(!device_accepts_hid_value(
            DeviceKind::Mouse,
            mouse,
            HID_PAGE_CONSUMER,
            0x0238
        ));
        assert!(!device_accepts_hid_value(
            DeviceKind::Other,
            mouse,
            HID_PAGE_BUTTON,
            1
        ));
        assert!(!device_accepts_hid_value(
            DeviceKind::Keyboard,
            DeviceCapabilities::KEYBOARD,
            HID_PAGE_BUTTON,
            1
        ));
        assert!(device_accepts_hid_value(
            DeviceKind::Keyboard,
            DeviceCapabilities::KEYBOARD,
            HID_PAGE_CONSUMER,
            0x00e9
        ));
    }

    #[test]
    fn only_stateless_deltas_are_droppable_on_queue_overflow() {
        assert!(overflow_may_drop(InputPayload::PointerMove {
            dx: 1.0,
            dy: -1.0
        }));
        assert!(overflow_may_drop(InputPayload::Scroll {
            horizontal: 0.0,
            vertical: 1.0
        }));
        assert!(!overflow_may_drop(InputPayload::Key {
            code: KeyCode::KeyA,
            state: KeyState::Pressed
        }));
        assert!(!overflow_may_drop(InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Released
        }));
    }

    #[test]
    fn hardware_evidence_requires_builtin_or_known_physical_transport() {
        assert!(physical_device_evidence(true, None));
        assert!(physical_device_evidence(false, Some("USB")));
        assert!(physical_device_evidence(
            false,
            Some("Bluetooth Low Energy")
        ));
        assert!(!physical_device_evidence(false, None));
        assert!(!physical_device_evidence(false, Some("Virtual")));
    }

    #[test]
    fn mach_timestamp_conversion_is_saturating_and_rejects_zero_denominator() {
        assert_eq!(mach_timestamp_ns(100, 125, 3), 4_166);
        assert_eq!(mach_timestamp_ns(u64::MAX, u32::MAX, 1), u64::MAX);
        assert_eq!(mach_timestamp_ns(100, 1, 0), 0);
    }

    #[test]
    fn whole_host_quartz_classification_requires_hid_source_evidence() {
        assert_eq!(CG_EVENT_SCROLL_WHEEL, 22);
        assert_ne!(
            CG_EVENT_TAP_DISABLED_BY_TIMEOUT,
            CG_EVENT_TAP_DISABLED_BY_USER_INPUT
        );
        assert_eq!(
            classify_quartz_capture(KVM_EVENT_TAG, CG_EVENT_SOURCE_STATE_HID_SYSTEM),
            EventClassification::InjectedByKvm
        );
        assert_eq!(
            classify_quartz_capture(0, CG_EVENT_SOURCE_STATE_HID_SYSTEM),
            EventClassification::Physical
        );
        assert_eq!(classify_quartz_capture(0, 0), EventClassification::Unknown);
        assert_eq!(classify_quartz_capture(0, -1), EventClassification::Unknown);
    }

    #[test]
    fn quartz_keyboard_preserves_press_repeat_release_and_modifiers() {
        assert!(quartz_key_is_down(KeyState::Pressed));
        assert!(quartz_key_is_down(KeyState::Repeated));
        assert!(!quartz_key_is_down(KeyState::Released));
        assert_eq!(
            translate_quartz_keyboard(CG_EVENT_KEY_DOWN, 0x00, false, None),
            Some(InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Pressed,
            })
        );
        assert_eq!(
            translate_quartz_keyboard(CG_EVENT_KEY_DOWN, 0x00, true, None),
            Some(InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Repeated,
            })
        );
        assert_eq!(
            translate_quartz_keyboard(CG_EVENT_KEY_UP, 0x00, true, None),
            Some(InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Released,
            })
        );
        assert_eq!(
            translate_quartz_keyboard(CG_EVENT_FLAGS_CHANGED, 0x38, false, Some(true)),
            Some(InputPayload::Key {
                code: KeyCode::ShiftLeft,
                state: KeyState::Pressed,
            })
        );
        assert_eq!(
            translate_quartz_keyboard(CG_EVENT_FLAGS_CHANGED, 0x38, false, Some(false)),
            Some(InputPayload::Key {
                code: KeyCode::ShiftLeft,
                state: KeyState::Released,
            })
        );
        assert_eq!(quartz_modifier_pressed(0x38, 0x2), Some(true));
        assert_eq!(quartz_modifier_pressed(0x38, 0), Some(false));
        assert_eq!(quartz_modifier_pressed(0x39, 0x0001_0000), None);
        assert_eq!(quartz_modifier_pressed(0x00, u64::MAX), None);
    }

    #[test]
    fn quartz_pointer_and_scroll_translation_is_finite_and_role_correct() {
        assert_eq!(
            translate_quartz_pointer(CG_EVENT_LEFT_MOUSE_DRAGGED, 0, 4.0, -3.0),
            Some(InputPayload::PointerMove { dx: 4.0, dy: -3.0 })
        );
        assert_eq!(
            translate_quartz_pointer(CG_EVENT_OTHER_MOUSE_DOWN, 4, 0.0, 0.0),
            Some(InputPayload::PointerButton {
                button: PointerButton::Forward,
                state: ButtonState::Pressed,
            })
        );
        assert_eq!(
            translate_quartz_pointer(CG_EVENT_OTHER_MOUSE_UP, 7, 0.0, 0.0),
            Some(InputPayload::PointerButton {
                button: PointerButton::Other(7),
                state: ButtonState::Released,
            })
        );
        assert_eq!(
            translate_quartz_scroll(-1.25, 2.5),
            Some(InputPayload::Scroll {
                horizontal: -1.25,
                vertical: 2.5,
            })
        );
        assert_eq!(
            translate_quartz_pointer(CG_EVENT_MOUSE_MOVED, 0, 0.0, 0.0),
            None
        );
        assert_eq!(translate_quartz_scroll(f64::NAN, 1.0), None);
    }
}
