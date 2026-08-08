use serde::{Deserialize, Serialize};

/// Keyboard translation policy for cross-platform routing.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyboardMode {
    #[default]
    Physical,
    Semantic,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_translation_is_the_safe_default() {
        assert_eq!(KeyboardMode::default(), KeyboardMode::Physical);
    }
}
