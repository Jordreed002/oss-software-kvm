//! Deliberate conversion between the versioned wire DTOs and daemon input.
//!
//! This module is intentionally kept in the composition crate. Neither the
//! domain model nor the public protocol silently depends on the other.

use kvm_input::{ButtonState, InputEvent, InputPayload, KeyCode, KeyState, PointerButton};
use kvm_protocol::{
    InputEventV1, ReleaseInputV1, ReleaseReasonV1, WireButtonState, WireDeviceId, WireHostId,
    WireInputPayloadV1, WireKeyCode, WireKeyState, WirePointerButton,
};
use kvm_types::{DeviceId, HostId};
use thiserror::Error;

use crate::RemoteRelease;

const KEYBOARD_PAGE: u16 = 0x07;
const CONSUMER_PAGE: u16 = 0x0c;

/// Failure to deliberately translate between protocol and domain input.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WireConversionError {
    #[error("wire input contains a non-finite pointer or scroll value")]
    NonFiniteInput,
    #[error("a key has no v1 HID wire representation")]
    UnsupportedKey,
    #[error("a remote release may contain only a key or pointer-button release")]
    UnsupportedReleasePayload,
}

/// Converts one validated v1 input DTO into the canonical domain event.
///
/// Unknown HID usages remain explicit [`KeyCode::Unidentified`] values. A
/// Repeats remain explicit so session state can reject an unmatched repeat
/// without confusing it with a first press.
///
/// # Errors
///
/// Returns [`WireConversionError::NonFiniteInput`] for unsafe pointer or
/// scrolling values.
pub fn input_from_wire(input: &InputEventV1) -> Result<InputEvent, WireConversionError> {
    let payload = payload_from_wire(&input.payload);
    if !payload.is_finite() {
        return Err(WireConversionError::NonFiniteInput);
    }
    Ok(InputEvent::new(
        input.sequence,
        input.timestamp_ns,
        HostId::from_bytes(input.source_host.0),
        DeviceId::from_bytes(input.source_device.0),
        payload,
    ))
}

/// Converts one canonical event into its explicit protocol-v1 representation.
///
/// # Errors
///
/// Returns an error for non-finite input or a key without a v1 HID usage.
pub fn input_to_wire(input: &InputEvent) -> Result<InputEventV1, WireConversionError> {
    if !input.payload.is_finite() {
        return Err(WireConversionError::NonFiniteInput);
    }
    Ok(InputEventV1 {
        sequence: input.sequence,
        timestamp_ns: input.timestamp_ns,
        source_host: WireHostId(input.source_host.into_bytes()),
        source_device: WireDeviceId(input.source_device.into_bytes()),
        payload: payload_to_wire(input.payload)?,
    })
}

/// Converts one daemon cleanup action into a conservative resynchronization
/// frame. The core currently does not retain the initiating cleanup reason.
///
/// # Errors
///
/// Returns an error unless the payload is a representable key or pointer-button
/// release.
pub fn release_to_wire(
    release: RemoteRelease,
    sequence: u64,
    source_host: HostId,
) -> Result<ReleaseInputV1, WireConversionError> {
    let mut keys = Vec::new();
    let mut buttons = Vec::new();
    match release.payload {
        InputPayload::Key {
            code,
            state: KeyState::Released,
        } => keys.push(key_to_wire(code)?),
        InputPayload::PointerButton {
            button,
            state: ButtonState::Released,
        } => buttons.push(button_to_wire(button)),
        InputPayload::Key { .. }
        | InputPayload::PointerButton { .. }
        | InputPayload::PointerMove { .. }
        | InputPayload::Scroll { .. } => {
            return Err(WireConversionError::UnsupportedReleasePayload);
        }
    }
    Ok(ReleaseInputV1 {
        sequence,
        source_host: WireHostId(source_host.into_bytes()),
        source_device: Some(WireDeviceId(release.source_device.into_bytes())),
        reason: ReleaseReasonV1::StateResynchronization,
        keys,
        buttons,
    })
}

fn payload_from_wire(payload: &WireInputPayloadV1) -> InputPayload {
    match *payload {
        WireInputPayloadV1::Key { code, state } => InputPayload::Key {
            code: key_code_from_wire(code),
            state: match state {
                WireKeyState::Down => KeyState::Pressed,
                WireKeyState::Repeat => KeyState::Repeated,
                WireKeyState::Up => KeyState::Released,
            },
        },
        WireInputPayloadV1::PointerMove { dx, dy } => InputPayload::PointerMove { dx, dy },
        WireInputPayloadV1::PointerButton { button, state } => InputPayload::PointerButton {
            button: pointer_button_from_wire(button),
            state: match state {
                WireButtonState::Down => ButtonState::Pressed,
                WireButtonState::Up => ButtonState::Released,
            },
        },
        WireInputPayloadV1::Scroll {
            horizontal,
            vertical,
        } => InputPayload::Scroll {
            horizontal,
            vertical,
        },
    }
}

fn payload_to_wire(payload: InputPayload) -> Result<WireInputPayloadV1, WireConversionError> {
    Ok(match payload {
        InputPayload::Key { code, state } => WireInputPayloadV1::Key {
            code: key_to_wire(code)?,
            state: match state {
                KeyState::Pressed => WireKeyState::Down,
                KeyState::Repeated => WireKeyState::Repeat,
                KeyState::Released => WireKeyState::Up,
            },
        },
        InputPayload::PointerMove { dx, dy } => WireInputPayloadV1::PointerMove { dx, dy },
        InputPayload::PointerButton { button, state } => WireInputPayloadV1::PointerButton {
            button: button_to_wire(button),
            state: match state {
                ButtonState::Pressed => WireButtonState::Down,
                ButtonState::Released => WireButtonState::Up,
            },
        },
        InputPayload::Scroll {
            horizontal,
            vertical,
        } => WireInputPayloadV1::Scroll {
            horizontal,
            vertical,
        },
    })
}

pub(crate) fn key_code_from_wire(key: WireKeyCode) -> KeyCode {
    if key.usage_page == KEYBOARD_PAGE {
        if let Some(named) = keyboard_key_from_usage(key.usage) {
            return named;
        }
    } else if key.usage_page == CONSUMER_PAGE {
        if let Some(named) = consumer_key_from_usage(key.usage) {
            return named;
        }
    }
    KeyCode::Unidentified {
        usage_page: key.usage_page,
        usage_id: key.usage,
    }
}

#[allow(clippy::too_many_lines)]
fn keyboard_key_from_usage(usage: u16) -> Option<KeyCode> {
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
        0x33 => KeyCode::Semicolon,
        0x34 => KeyCode::Quote,
        0x35 => KeyCode::Backquote,
        0x36 => KeyCode::Comma,
        0x37 => KeyCode::Period,
        0x38 => KeyCode::Slash,
        0x39 => KeyCode::CapsLock,
        value @ 0x3a..=0x45 => function_key(value - 0x39),
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
        value @ 0x59..=0x61 => numpad_digit(value - 0x58),
        0x62 => KeyCode::Numpad0,
        0x63 => KeyCode::NumpadDecimal,
        0x64 => KeyCode::IntlBackslash,
        0x65 => KeyCode::ContextMenu,
        0x66 => KeyCode::Power,
        0x67 => KeyCode::NumpadEqual,
        value @ 0x68..=0x73 => function_key(value - 0x5b),
        0x75 => KeyCode::Help,
        0x7f => KeyCode::AudioVolumeMute,
        0x80 => KeyCode::AudioVolumeUp,
        0x81 => KeyCode::AudioVolumeDown,
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
        0xb6 => KeyCode::NumpadParenLeft,
        0xb7 => KeyCode::NumpadParenRight,
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

fn consumer_key_from_usage(usage: u16) -> Option<KeyCode> {
    Some(match usage {
        0xb5 => KeyCode::MediaTrackNext,
        0xb6 => KeyCode::MediaTrackPrevious,
        0xb7 => KeyCode::MediaStop,
        0xb8 => KeyCode::Eject,
        0xcd => KeyCode::MediaPlayPause,
        0xe2 => KeyCode::AudioVolumeMute,
        0xe9 => KeyCode::AudioVolumeUp,
        0xea => KeyCode::AudioVolumeDown,
        _ => return None,
    })
}

fn function_key(number: u16) -> KeyCode {
    match number {
        1 => KeyCode::F1,
        2 => KeyCode::F2,
        3 => KeyCode::F3,
        4 => KeyCode::F4,
        5 => KeyCode::F5,
        6 => KeyCode::F6,
        7 => KeyCode::F7,
        8 => KeyCode::F8,
        9 => KeyCode::F9,
        10 => KeyCode::F10,
        11 => KeyCode::F11,
        12 => KeyCode::F12,
        13 => KeyCode::F13,
        14 => KeyCode::F14,
        15 => KeyCode::F15,
        16 => KeyCode::F16,
        17 => KeyCode::F17,
        18 => KeyCode::F18,
        19 => KeyCode::F19,
        20 => KeyCode::F20,
        21 => KeyCode::F21,
        22 => KeyCode::F22,
        23 => KeyCode::F23,
        24 => KeyCode::F24,
        _ => unreachable!("function key range is checked by the caller"),
    }
}

fn numpad_digit(number: u16) -> KeyCode {
    match number {
        1 => KeyCode::Numpad1,
        2 => KeyCode::Numpad2,
        3 => KeyCode::Numpad3,
        4 => KeyCode::Numpad4,
        5 => KeyCode::Numpad5,
        6 => KeyCode::Numpad6,
        7 => KeyCode::Numpad7,
        8 => KeyCode::Numpad8,
        9 => KeyCode::Numpad9,
        _ => unreachable!("numpad digit range is checked by the caller"),
    }
}

#[allow(clippy::too_many_lines)]
fn key_to_wire(key: KeyCode) -> Result<WireKeyCode, WireConversionError> {
    let (usage_page, usage) = match key {
        KeyCode::Unidentified {
            usage_page,
            usage_id,
        } => (usage_page, usage_id),
        KeyCode::MediaTrackNext => (CONSUMER_PAGE, 0xb5),
        KeyCode::MediaTrackPrevious => (CONSUMER_PAGE, 0xb6),
        KeyCode::MediaStop => (CONSUMER_PAGE, 0xb7),
        KeyCode::Eject => (CONSUMER_PAGE, 0xb8),
        KeyCode::MediaPlayPause => (CONSUMER_PAGE, 0xcd),
        KeyCode::AudioVolumeMute => (CONSUMER_PAGE, 0xe2),
        KeyCode::AudioVolumeUp => (CONSUMER_PAGE, 0xe9),
        KeyCode::AudioVolumeDown => (CONSUMER_PAGE, 0xea),
        KeyCode::KeyA => (KEYBOARD_PAGE, 0x04),
        KeyCode::KeyB => (KEYBOARD_PAGE, 0x05),
        KeyCode::KeyC => (KEYBOARD_PAGE, 0x06),
        KeyCode::KeyD => (KEYBOARD_PAGE, 0x07),
        KeyCode::KeyE => (KEYBOARD_PAGE, 0x08),
        KeyCode::KeyF => (KEYBOARD_PAGE, 0x09),
        KeyCode::KeyG => (KEYBOARD_PAGE, 0x0a),
        KeyCode::KeyH => (KEYBOARD_PAGE, 0x0b),
        KeyCode::KeyI => (KEYBOARD_PAGE, 0x0c),
        KeyCode::KeyJ => (KEYBOARD_PAGE, 0x0d),
        KeyCode::KeyK => (KEYBOARD_PAGE, 0x0e),
        KeyCode::KeyL => (KEYBOARD_PAGE, 0x0f),
        KeyCode::KeyM => (KEYBOARD_PAGE, 0x10),
        KeyCode::KeyN => (KEYBOARD_PAGE, 0x11),
        KeyCode::KeyO => (KEYBOARD_PAGE, 0x12),
        KeyCode::KeyP => (KEYBOARD_PAGE, 0x13),
        KeyCode::KeyQ => (KEYBOARD_PAGE, 0x14),
        KeyCode::KeyR => (KEYBOARD_PAGE, 0x15),
        KeyCode::KeyS => (KEYBOARD_PAGE, 0x16),
        KeyCode::KeyT => (KEYBOARD_PAGE, 0x17),
        KeyCode::KeyU => (KEYBOARD_PAGE, 0x18),
        KeyCode::KeyV => (KEYBOARD_PAGE, 0x19),
        KeyCode::KeyW => (KEYBOARD_PAGE, 0x1a),
        KeyCode::KeyX => (KEYBOARD_PAGE, 0x1b),
        KeyCode::KeyY => (KEYBOARD_PAGE, 0x1c),
        KeyCode::KeyZ => (KEYBOARD_PAGE, 0x1d),
        KeyCode::Digit1 => (KEYBOARD_PAGE, 0x1e),
        KeyCode::Digit2 => (KEYBOARD_PAGE, 0x1f),
        KeyCode::Digit3 => (KEYBOARD_PAGE, 0x20),
        KeyCode::Digit4 => (KEYBOARD_PAGE, 0x21),
        KeyCode::Digit5 => (KEYBOARD_PAGE, 0x22),
        KeyCode::Digit6 => (KEYBOARD_PAGE, 0x23),
        KeyCode::Digit7 => (KEYBOARD_PAGE, 0x24),
        KeyCode::Digit8 => (KEYBOARD_PAGE, 0x25),
        KeyCode::Digit9 => (KEYBOARD_PAGE, 0x26),
        KeyCode::Digit0 => (KEYBOARD_PAGE, 0x27),
        KeyCode::Enter => (KEYBOARD_PAGE, 0x28),
        KeyCode::Escape => (KEYBOARD_PAGE, 0x29),
        KeyCode::Backspace => (KEYBOARD_PAGE, 0x2a),
        KeyCode::Tab => (KEYBOARD_PAGE, 0x2b),
        KeyCode::Space => (KEYBOARD_PAGE, 0x2c),
        KeyCode::Minus => (KEYBOARD_PAGE, 0x2d),
        KeyCode::Equal => (KEYBOARD_PAGE, 0x2e),
        KeyCode::BracketLeft => (KEYBOARD_PAGE, 0x2f),
        KeyCode::BracketRight => (KEYBOARD_PAGE, 0x30),
        KeyCode::Backslash => (KEYBOARD_PAGE, 0x31),
        KeyCode::Semicolon => (KEYBOARD_PAGE, 0x33),
        KeyCode::Quote => (KEYBOARD_PAGE, 0x34),
        KeyCode::Backquote => (KEYBOARD_PAGE, 0x35),
        KeyCode::Comma => (KEYBOARD_PAGE, 0x36),
        KeyCode::Period => (KEYBOARD_PAGE, 0x37),
        KeyCode::Slash => (KEYBOARD_PAGE, 0x38),
        KeyCode::CapsLock => (KEYBOARD_PAGE, 0x39),
        KeyCode::F1 => (KEYBOARD_PAGE, 0x3a),
        KeyCode::F2 => (KEYBOARD_PAGE, 0x3b),
        KeyCode::F3 => (KEYBOARD_PAGE, 0x3c),
        KeyCode::F4 => (KEYBOARD_PAGE, 0x3d),
        KeyCode::F5 => (KEYBOARD_PAGE, 0x3e),
        KeyCode::F6 => (KEYBOARD_PAGE, 0x3f),
        KeyCode::F7 => (KEYBOARD_PAGE, 0x40),
        KeyCode::F8 => (KEYBOARD_PAGE, 0x41),
        KeyCode::F9 => (KEYBOARD_PAGE, 0x42),
        KeyCode::F10 => (KEYBOARD_PAGE, 0x43),
        KeyCode::F11 => (KEYBOARD_PAGE, 0x44),
        KeyCode::F12 => (KEYBOARD_PAGE, 0x45),
        KeyCode::PrintScreen => (KEYBOARD_PAGE, 0x46),
        KeyCode::ScrollLock => (KEYBOARD_PAGE, 0x47),
        KeyCode::Pause => (KEYBOARD_PAGE, 0x48),
        KeyCode::Insert => (KEYBOARD_PAGE, 0x49),
        KeyCode::Home => (KEYBOARD_PAGE, 0x4a),
        KeyCode::PageUp => (KEYBOARD_PAGE, 0x4b),
        KeyCode::DeleteForward => (KEYBOARD_PAGE, 0x4c),
        KeyCode::End => (KEYBOARD_PAGE, 0x4d),
        KeyCode::PageDown => (KEYBOARD_PAGE, 0x4e),
        KeyCode::ArrowRight => (KEYBOARD_PAGE, 0x4f),
        KeyCode::ArrowLeft => (KEYBOARD_PAGE, 0x50),
        KeyCode::ArrowDown => (KEYBOARD_PAGE, 0x51),
        KeyCode::ArrowUp => (KEYBOARD_PAGE, 0x52),
        KeyCode::NumLock => (KEYBOARD_PAGE, 0x53),
        KeyCode::NumpadDivide => (KEYBOARD_PAGE, 0x54),
        KeyCode::NumpadMultiply => (KEYBOARD_PAGE, 0x55),
        KeyCode::NumpadSubtract => (KEYBOARD_PAGE, 0x56),
        KeyCode::NumpadAdd => (KEYBOARD_PAGE, 0x57),
        KeyCode::NumpadEnter => (KEYBOARD_PAGE, 0x58),
        KeyCode::Numpad1 => (KEYBOARD_PAGE, 0x59),
        KeyCode::Numpad2 => (KEYBOARD_PAGE, 0x5a),
        KeyCode::Numpad3 => (KEYBOARD_PAGE, 0x5b),
        KeyCode::Numpad4 => (KEYBOARD_PAGE, 0x5c),
        KeyCode::Numpad5 => (KEYBOARD_PAGE, 0x5d),
        KeyCode::Numpad6 => (KEYBOARD_PAGE, 0x5e),
        KeyCode::Numpad7 => (KEYBOARD_PAGE, 0x5f),
        KeyCode::Numpad8 => (KEYBOARD_PAGE, 0x60),
        KeyCode::Numpad9 => (KEYBOARD_PAGE, 0x61),
        KeyCode::Numpad0 => (KEYBOARD_PAGE, 0x62),
        KeyCode::NumpadDecimal => (KEYBOARD_PAGE, 0x63),
        KeyCode::IntlBackslash => (KEYBOARD_PAGE, 0x64),
        KeyCode::ContextMenu => (KEYBOARD_PAGE, 0x65),
        KeyCode::Power => (KEYBOARD_PAGE, 0x66),
        KeyCode::NumpadEqual => (KEYBOARD_PAGE, 0x67),
        KeyCode::F13 => (KEYBOARD_PAGE, 0x68),
        KeyCode::F14 => (KEYBOARD_PAGE, 0x69),
        KeyCode::F15 => (KEYBOARD_PAGE, 0x6a),
        KeyCode::F16 => (KEYBOARD_PAGE, 0x6b),
        KeyCode::F17 => (KEYBOARD_PAGE, 0x6c),
        KeyCode::F18 => (KEYBOARD_PAGE, 0x6d),
        KeyCode::F19 => (KEYBOARD_PAGE, 0x6e),
        KeyCode::F20 => (KEYBOARD_PAGE, 0x6f),
        KeyCode::F21 => (KEYBOARD_PAGE, 0x70),
        KeyCode::F22 => (KEYBOARD_PAGE, 0x71),
        KeyCode::F23 => (KEYBOARD_PAGE, 0x72),
        KeyCode::F24 => (KEYBOARD_PAGE, 0x73),
        KeyCode::Help => (KEYBOARD_PAGE, 0x75),
        KeyCode::NumpadComma => (KEYBOARD_PAGE, 0x85),
        KeyCode::IntlRo => (KEYBOARD_PAGE, 0x87),
        KeyCode::KanaMode => (KEYBOARD_PAGE, 0x88),
        KeyCode::IntlYen => (KEYBOARD_PAGE, 0x89),
        KeyCode::Convert => (KEYBOARD_PAGE, 0x8a),
        KeyCode::NonConvert => (KEYBOARD_PAGE, 0x8b),
        KeyCode::Lang1 => (KEYBOARD_PAGE, 0x90),
        KeyCode::Lang2 => (KEYBOARD_PAGE, 0x91),
        KeyCode::Lang3 => (KEYBOARD_PAGE, 0x92),
        KeyCode::Lang4 => (KEYBOARD_PAGE, 0x93),
        KeyCode::Lang5 => (KEYBOARD_PAGE, 0x94),
        KeyCode::NumpadParenLeft => (KEYBOARD_PAGE, 0xb6),
        KeyCode::NumpadParenRight => (KEYBOARD_PAGE, 0xb7),
        KeyCode::ControlLeft => (KEYBOARD_PAGE, 0xe0),
        KeyCode::ShiftLeft => (KEYBOARD_PAGE, 0xe1),
        KeyCode::AltLeft => (KEYBOARD_PAGE, 0xe2),
        KeyCode::MetaLeft => (KEYBOARD_PAGE, 0xe3),
        KeyCode::ControlRight => (KEYBOARD_PAGE, 0xe4),
        KeyCode::ShiftRight => (KEYBOARD_PAGE, 0xe5),
        KeyCode::AltRight => (KEYBOARD_PAGE, 0xe6),
        KeyCode::MetaRight => (KEYBOARD_PAGE, 0xe7),
        _ => return Err(WireConversionError::UnsupportedKey),
    };
    Ok(WireKeyCode { usage_page, usage })
}

pub(crate) fn pointer_button_from_wire(button: WirePointerButton) -> PointerButton {
    match button {
        WirePointerButton::Primary => PointerButton::Left,
        WirePointerButton::Secondary => PointerButton::Right,
        WirePointerButton::Middle => PointerButton::Middle,
        WirePointerButton::Back => PointerButton::Back,
        WirePointerButton::Forward => PointerButton::Forward,
        WirePointerButton::Other(value) => PointerButton::Other(value),
    }
}

fn button_to_wire(button: PointerButton) -> WirePointerButton {
    match button {
        PointerButton::Left => WirePointerButton::Primary,
        PointerButton::Right => WirePointerButton::Secondary,
        PointerButton::Middle => WirePointerButton::Middle,
        PointerButton::Back => WirePointerButton::Back,
        PointerButton::Forward => WirePointerButton::Forward,
        PointerButton::Other(value) => WirePointerButton::Other(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: HostId = HostId::from_bytes([1; 16]);
    const DEVICE: DeviceId = DeviceId::from_bytes([2; 16]);

    #[test]
    fn named_and_unknown_keys_round_trip_deliberately() {
        for key in [
            KeyCode::KeyA,
            KeyCode::ControlRight,
            KeyCode::F24,
            KeyCode::MediaPlayPause,
            KeyCode::IntlYen,
            KeyCode::Unidentified {
                usage_page: 0xff,
                usage_id: 42,
            },
        ] {
            let event = InputEvent::new(
                7,
                8,
                HOST,
                DEVICE,
                InputPayload::Key {
                    code: key,
                    state: KeyState::Pressed,
                },
            );
            let wire = input_to_wire(&event).unwrap();
            assert_eq!(input_from_wire(&wire).unwrap(), event);
        }
    }

    #[test]
    fn wire_repeat_is_bijectively_preserved() {
        let wire = InputEventV1 {
            sequence: 1,
            timestamp_ns: 2,
            source_host: WireHostId(HOST.into_bytes()),
            source_device: WireDeviceId(DEVICE.into_bytes()),
            payload: WireInputPayloadV1::Key {
                code: WireKeyCode {
                    usage_page: KEYBOARD_PAGE,
                    usage: 0x04,
                },
                state: WireKeyState::Repeat,
            },
        };
        assert!(matches!(
            input_from_wire(&wire).unwrap().payload,
            InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Repeated
            }
        ));
        let domain = InputEvent::new(
            3,
            4,
            HOST,
            DEVICE,
            InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Repeated,
            },
        );
        assert!(matches!(
            input_to_wire(&domain).unwrap().payload,
            WireInputPayloadV1::Key {
                state: WireKeyState::Repeat,
                ..
            }
        ));
    }

    #[test]
    fn release_conversion_is_conservative_and_rejects_motion() {
        let release = RemoteRelease {
            target: HostId::from_bytes([3; 16]),
            source_device: DEVICE,
            payload: InputPayload::Key {
                code: KeyCode::ControlLeft,
                state: KeyState::Released,
            },
        };
        let wire = release_to_wire(release, 9, HOST).unwrap();
        assert_eq!(wire.reason, ReleaseReasonV1::StateResynchronization);
        assert_eq!(wire.sequence, 9);
        assert_eq!(wire.keys.len(), 1);

        assert_eq!(
            release_to_wire(
                RemoteRelease {
                    payload: InputPayload::PointerMove { dx: 1.0, dy: 2.0 },
                    ..release
                },
                10,
                HOST,
            ),
            Err(WireConversionError::UnsupportedReleasePayload)
        );
    }

    #[test]
    fn unsupported_key_errors_do_not_echo_key_payloads() {
        let event = InputEvent::new(
            1,
            2,
            HOST,
            DEVICE,
            InputPayload::Key {
                code: KeyCode::Fn,
                state: KeyState::Pressed,
            },
        );
        let error = input_to_wire(&event).unwrap_err();
        assert_eq!(error, WireConversionError::UnsupportedKey);
        assert!(!format!("{error:?}").contains("Fn"));
        assert!(!error.to_string().contains("Fn"));
    }
}
