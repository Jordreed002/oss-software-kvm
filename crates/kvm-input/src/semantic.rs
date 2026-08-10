use kvm_types::Platform;
use serde::{Deserialize, Serialize};

use crate::KeyCode;

/// The intentionally small set of shortcuts translated by user intent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SemanticCommand {
    Copy,
    Paste,
    Cut,
    Undo,
    Redo,
    SelectAll,
    AppSwitch,
}

/// The logical modifier groups relevant to cross-platform shortcut matching.
///
/// Left/right pairs collapse into a single group: a `ControlLeft` press and a
/// `ControlRight` press both set [`Modifiers::control`]. `Fn` is intentionally
/// excluded — on macOS it is a hardware-level modifier that does not participate
/// in application shortcuts.
// Four booleans mirror the canonical keyboard modifier groups; a bitfield or
// state machine would obscure the per-group queries without adding value here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Modifiers {
    pub control: bool,
    pub alt: bool,
    pub shift: bool,
    pub meta: bool,
}

impl Modifiers {
    /// Empty modifier set — no modifiers held.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            control: false,
            alt: false,
            shift: false,
            meta: false,
        }
    }

    #[must_use]
    pub const fn control() -> Self {
        Self {
            control: true,
            ..Self::none()
        }
    }

    #[must_use]
    pub const fn alt() -> Self {
        Self {
            alt: true,
            ..Self::none()
        }
    }

    #[must_use]
    pub const fn meta() -> Self {
        Self {
            meta: true,
            ..Self::none()
        }
    }

    #[must_use]
    pub const fn with_shift(self) -> Self {
        Self {
            shift: true,
            ..self
        }
    }

    /// Fold a physical key position into this modifier snapshot.
    ///
    /// Returns `true` when `code` is one of the tracked modifier positions so
    /// callers can distinguish modifier transitions from ordinary keys.
    pub fn apply(&mut self, code: KeyCode, pressed: bool) -> bool {
        match code {
            KeyCode::ControlLeft | KeyCode::ControlRight => {
                self.control = pressed;
                true
            }
            KeyCode::AltLeft | KeyCode::AltRight => {
                self.alt = pressed;
                true
            }
            KeyCode::ShiftLeft | KeyCode::ShiftRight => {
                self.shift = pressed;
                true
            }
            KeyCode::MetaLeft | KeyCode::MetaRight => {
                self.meta = pressed;
                true
            }
            _ => false,
        }
    }
}

/// A bound key combination: a modifier snapshot plus a physical key position.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Shortcut {
    pub modifiers: Modifiers,
    pub key: KeyCode,
}

/// The platform-native binding for a semantic command.
///
/// Windows uses `Ctrl` for editing commands and `Alt+Tab` for application
/// switching; macOS uses `Command` (and `Command+Shift+Z` for redo). These are
/// the conventions semantic mode translates between so a user's muscle memory
/// keeps working on the destination host.
#[must_use]
pub fn native_binding(command: SemanticCommand, platform: Platform) -> Shortcut {
    match platform {
        // macOS is the lone Command-based platform; every other platform
        // (Windows today, Linux later per spec §3) uses Ctrl-based bindings.
        Platform::MacOS => match command {
            SemanticCommand::Copy => Shortcut {
                modifiers: Modifiers::meta(),
                key: KeyCode::KeyC,
            },
            SemanticCommand::Paste => Shortcut {
                modifiers: Modifiers::meta(),
                key: KeyCode::KeyV,
            },
            SemanticCommand::Cut => Shortcut {
                modifiers: Modifiers::meta(),
                key: KeyCode::KeyX,
            },
            SemanticCommand::Undo => Shortcut {
                modifiers: Modifiers::meta(),
                key: KeyCode::KeyZ,
            },
            SemanticCommand::Redo => Shortcut {
                modifiers: Modifiers::meta().with_shift(),
                key: KeyCode::KeyZ,
            },
            SemanticCommand::SelectAll => Shortcut {
                modifiers: Modifiers::meta(),
                key: KeyCode::KeyA,
            },
            SemanticCommand::AppSwitch => Shortcut {
                modifiers: Modifiers::meta(),
                key: KeyCode::Tab,
            },
        },
        _ => match command {
            SemanticCommand::Copy => Shortcut {
                modifiers: Modifiers::control(),
                key: KeyCode::KeyC,
            },
            SemanticCommand::Paste => Shortcut {
                modifiers: Modifiers::control(),
                key: KeyCode::KeyV,
            },
            SemanticCommand::Cut => Shortcut {
                modifiers: Modifiers::control(),
                key: KeyCode::KeyX,
            },
            SemanticCommand::Undo => Shortcut {
                modifiers: Modifiers::control(),
                key: KeyCode::KeyZ,
            },
            SemanticCommand::Redo => Shortcut {
                modifiers: Modifiers::control(),
                key: KeyCode::KeyY,
            },
            SemanticCommand::SelectAll => Shortcut {
                modifiers: Modifiers::control(),
                key: KeyCode::KeyA,
            },
            SemanticCommand::AppSwitch => Shortcut {
                modifiers: Modifiers::alt(),
                key: KeyCode::Tab,
            },
        },
    }
}

const SEMANTIC_COMMANDS: [SemanticCommand; 7] = [
    SemanticCommand::Copy,
    SemanticCommand::Paste,
    SemanticCommand::Cut,
    SemanticCommand::Undo,
    SemanticCommand::Redo,
    SemanticCommand::SelectAll,
    SemanticCommand::AppSwitch,
];

/// Recognise a semantic command from a held-modifier snapshot and key.
///
/// Matching is exact: the held modifiers must equal the binding's required set.
/// `Ctrl+Shift+C` is therefore not `Copy`, and on macOS `Ctrl+C` (Control, not
/// Command) resolves to nothing. Returns `None` when no command matches.
#[must_use]
pub fn resolve(modifiers: Modifiers, key: KeyCode, source: Platform) -> Option<SemanticCommand> {
    SEMANTIC_COMMANDS.into_iter().find(|&command| {
        let binding = native_binding(command, source);
        binding.modifiers == modifiers && binding.key == key
    })
}

/// Translate a semantic command into the destination platform's native binding.
///
/// This is the inverse of [`resolve`]: given an intent recognised on the source
/// host, produce the modifier/key the destination host expects.
#[must_use]
pub fn translate(command: SemanticCommand, destination: Platform) -> Shortcut {
    native_binding(command, destination)
}

/// Tracks the currently-held logical modifiers across a stream of key events.
///
/// Inert for non-modifier keys. Callers resolve a command on the press of an
/// ordinary key by combining [`ModifierTracker::current`] with that key.
#[derive(Debug, Default)]
pub struct ModifierTracker {
    modifiers: Modifiers,
}

impl ModifierTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            modifiers: Modifiers::none(),
        }
    }

    /// Current held-modifier snapshot.
    #[must_use]
    pub const fn current(&self) -> Modifiers {
        self.modifiers
    }

    /// Returns `true` when the transition was a tracked modifier.
    pub fn apply(&mut self, code: KeyCode, pressed: bool) -> bool {
        self.modifiers.apply(code, pressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_ctrl_c_resolves_to_copy() {
        assert_eq!(
            resolve(Modifiers::control(), KeyCode::KeyC, Platform::Windows),
            Some(SemanticCommand::Copy)
        );
    }

    #[test]
    fn macos_cmd_c_resolves_to_copy() {
        assert_eq!(
            resolve(Modifiers::meta(), KeyCode::KeyC, Platform::MacOS),
            Some(SemanticCommand::Copy)
        );
    }

    #[test]
    fn macos_ctrl_c_is_not_copy() {
        // On macOS Copy is Cmd+C, so bare Ctrl+C must not be misrecognised.
        assert_eq!(
            resolve(Modifiers::control(), KeyCode::KeyC, Platform::MacOS),
            None
        );
    }

    #[test]
    fn extra_modifiers_defeat_a_match() {
        // Ctrl+Shift+C is not Copy — matching is exact.
        assert_eq!(
            resolve(
                Modifiers::control().with_shift(),
                KeyCode::KeyC,
                Platform::Windows
            ),
            None
        );
    }

    #[test]
    fn translate_copy_to_macos_uses_command() {
        assert_eq!(
            translate(SemanticCommand::Copy, Platform::MacOS),
            Shortcut {
                modifiers: Modifiers::meta(),
                key: KeyCode::KeyC
            }
        );
    }

    #[test]
    fn macos_redo_is_command_shift_z() {
        assert_eq!(
            translate(SemanticCommand::Redo, Platform::MacOS),
            Shortcut {
                modifiers: Modifiers::meta().with_shift(),
                key: KeyCode::KeyZ
            }
        );
        // And the reverse: Cmd+Shift+Z on macOS resolves back to Redo.
        assert_eq!(
            resolve(
                Modifiers::meta().with_shift(),
                KeyCode::KeyZ,
                Platform::MacOS
            ),
            Some(SemanticCommand::Redo)
        );
    }

    #[test]
    fn app_switch_uses_each_platforms_switcher() {
        assert_eq!(
            resolve(Modifiers::alt(), KeyCode::Tab, Platform::Windows),
            Some(SemanticCommand::AppSwitch)
        );
        assert_eq!(
            resolve(Modifiers::meta(), KeyCode::Tab, Platform::MacOS),
            Some(SemanticCommand::AppSwitch)
        );
        // Alt+Tab is not the macOS switcher.
        assert_eq!(
            resolve(Modifiers::alt(), KeyCode::Tab, Platform::MacOS),
            None
        );
    }

    #[test]
    fn resolve_and_translate_round_trip_within_a_platform() {
        for platform in [Platform::Windows, Platform::MacOS] {
            for &command in &SEMANTIC_COMMANDS {
                let Shortcut { modifiers, key } = native_binding(command, platform);
                assert_eq!(
                    resolve(modifiers, key, platform),
                    Some(command),
                    "round trip failed for {command:?} on {platform:?}"
                );
            }
        }
    }

    #[test]
    fn tracker_covers_left_and_right_pairs() {
        let mut tracker = ModifierTracker::new();
        assert!(tracker.apply(KeyCode::ControlLeft, true));
        assert!(tracker.apply(KeyCode::MetaRight, true));
        assert!(tracker.current().control && tracker.current().meta);
        assert!(!tracker.current().alt && !tracker.current().shift);

        // Releasing the right control clears the group even though left pressed.
        assert!(tracker.apply(KeyCode::ControlRight, false));
        let after_release = tracker.current();
        assert!(!after_release.control && after_release.meta);

        // Ordinary keys do not affect the tracker.
        assert!(!tracker.apply(KeyCode::KeyA, true));
        assert_eq!(tracker.current(), after_release);
    }
}
