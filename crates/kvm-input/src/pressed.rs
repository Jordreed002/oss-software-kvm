use std::collections::HashSet;

use crate::{ButtonState, InputPayload, KeyCode, KeyState, PointerButton};

/// Tracks remotely held keys and pointer buttons for safe cleanup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PressedState {
    keys: HashSet<KeyCode>,
    buttons: HashSet<PointerButton>,
}

impl PressedState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len() + self.buttons.len()
    }

    #[must_use]
    pub fn key_is_pressed(&self, code: KeyCode) -> bool {
        self.keys.contains(&code)
    }

    #[must_use]
    pub fn button_is_pressed(&self, button: PointerButton) -> bool {
        self.buttons.contains(&button)
    }

    /// Applies state-bearing payloads, returning true when the held set changed.
    /// Motion and scrolling leave the set unchanged.
    pub fn apply(&mut self, payload: &InputPayload) -> bool {
        match *payload {
            InputPayload::Key { code, state } => match state {
                KeyState::Pressed => self.keys.insert(code),
                KeyState::Released => self.keys.remove(&code),
            },
            InputPayload::PointerButton { button, state } => match state {
                ButtonState::Pressed => self.buttons.insert(button),
                ButtonState::Released => self.buttons.remove(&button),
            },
            InputPayload::PointerMove { .. } | InputPayload::Scroll { .. } => false,
        }
    }

    /// Returns all held keys in deterministic physical-key order.
    pub fn pressed_keys(&self) -> impl ExactSizeIterator<Item = KeyCode> {
        let mut keys: Vec<_> = self.keys.iter().copied().collect();
        // Releasing non-modifiers first avoids turning a held Ctrl+A into a
        // transient unmodified A during failure cleanup.
        keys.sort_unstable_by_key(|key| (key.is_modifier(), *key));
        keys.into_iter()
    }

    /// Returns all held buttons in deterministic order.
    pub fn pressed_buttons(&self) -> impl ExactSizeIterator<Item = PointerButton> {
        let mut buttons: Vec<_> = self.buttons.iter().copied().collect();
        buttons.sort_unstable();
        buttons.into_iter()
    }

    /// Clears the held set and returns the release payloads a backend must inject.
    ///
    /// Keys are released before pointer buttons, each in deterministic order.
    #[must_use]
    pub fn take_release_payloads(&mut self) -> Vec<InputPayload> {
        let mut releases = Vec::with_capacity(self.len());
        releases.extend(self.pressed_keys().map(|code| InputPayload::Key {
            code,
            state: KeyState::Released,
        }));
        releases.extend(
            self.pressed_buttons()
                .map(|button| InputPayload::PointerButton {
                    button,
                    state: ButtonState::Released,
                }),
        );
        self.keys.clear();
        self.buttons.clear();
        releases
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_press_does_not_duplicate_held_state() {
        let mut state = PressedState::new();
        let press = InputPayload::Key {
            code: KeyCode::ControlLeft,
            state: KeyState::Pressed,
        };

        assert!(state.apply(&press));
        assert!(!state.apply(&press));
        assert_eq!(state.len(), 1);
        assert!(state.key_is_pressed(KeyCode::ControlLeft));
    }

    #[test]
    fn unmatched_release_is_safe_and_idempotent() {
        let mut state = PressedState::new();
        let release = InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Released,
        };

        assert!(!state.apply(&release));
        assert!(state.is_empty());
    }

    #[test]
    fn motion_and_scroll_do_not_change_pressed_state() {
        let mut state = PressedState::new();

        assert!(!state.apply(&InputPayload::PointerMove { dx: 1.0, dy: 2.0 }));
        assert!(!state.apply(&InputPayload::Scroll {
            horizontal: 1.0,
            vertical: -1.0,
        }));
        assert!(state.is_empty());
    }

    #[test]
    fn cleanup_releases_everything_and_clears_state() {
        let mut state = PressedState::new();
        state.apply(&InputPayload::Key {
            code: KeyCode::ShiftRight,
            state: KeyState::Pressed,
        });
        state.apply(&InputPayload::Key {
            code: KeyCode::KeyA,
            state: KeyState::Pressed,
        });
        state.apply(&InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Pressed,
        });

        let releases = state.take_release_payloads();

        assert_eq!(releases.len(), 3);
        assert!(releases.contains(&InputPayload::Key {
            code: KeyCode::ShiftRight,
            state: KeyState::Released,
        }));
        assert!(releases.contains(&InputPayload::Key {
            code: KeyCode::KeyA,
            state: KeyState::Released,
        }));
        assert!(releases.contains(&InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Released,
        }));
        assert!(state.is_empty());
        assert!(state.take_release_payloads().is_empty());
    }

    #[test]
    fn iterator_results_are_stable() {
        let mut state = PressedState::new();
        for key in [KeyCode::KeyZ, KeyCode::ControlLeft, KeyCode::KeyA] {
            state.apply(&InputPayload::Key {
                code: key,
                state: KeyState::Pressed,
            });
        }

        let first: Vec<_> = state.pressed_keys().collect();
        let second: Vec<_> = state.pressed_keys().collect();
        assert_eq!(first, second);
        assert_eq!(first.last(), Some(&KeyCode::ControlLeft));
    }
}
