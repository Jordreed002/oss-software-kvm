use std::collections::HashSet;
use std::fmt;

use crate::{ButtonState, InputPayload, KeyCode, KeyState, PointerButton};

/// Tracks remotely held keys and pointer buttons for safe cleanup.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct PressedState {
    keys: HashSet<KeyCode>,
    buttons: HashSet<PointerButton>,
}

impl fmt::Debug for PressedState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PressedState")
            .field("key_count", &self.keys.len())
            .field("button_count", &self.buttons.len())
            .finish_non_exhaustive()
    }
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
                KeyState::Repeated => false,
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
    fn repeat_does_not_mutate_held_state() {
        let mut state = PressedState::new();
        let press = InputPayload::Key {
            code: KeyCode::ControlLeft,
            state: KeyState::Pressed,
        };
        let repeat = InputPayload::Key {
            code: KeyCode::ControlLeft,
            state: KeyState::Repeated,
        };

        assert!(state.apply(&press));
        assert!(!state.apply(&repeat));
        assert_eq!(state.len(), 1);
        assert!(state.key_is_pressed(KeyCode::ControlLeft));

        let mut unmatched = PressedState::new();
        assert!(!unmatched.apply(&repeat));
        assert!(unmatched.is_empty());
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

    #[test]
    fn pressed_state_diagnostics_are_count_only() {
        let mut state = PressedState::new();
        state.apply(&InputPayload::Key {
            code: KeyCode::Unidentified {
                usage_page: 54_321,
                usage_id: 12_345,
            },
            state: KeyState::Pressed,
        });
        state.apply(&InputPayload::PointerButton {
            button: PointerButton::Other(43_210),
            state: ButtonState::Pressed,
        });

        let rendered = format!("{state:?}");
        assert!(rendered.contains("key_count: 1"));
        assert!(rendered.contains("button_count: 1"));
        for secret in ["54321", "12345", "43210", "Unidentified", "Other"] {
            assert!(!rendered.contains(secret));
        }
    }
}
