use serde::{Deserialize, Serialize};

/// Keyboard translation policy for cross-platform input routing.
///
/// This is the single canonical definition shared by the configuration schema
/// (`kvm-config`) and the input domain (`kvm-input`). It previously existed as
/// two identical copies that could silently drift; consolidating it here (next
/// to [`crate::Platform`]) eliminates that hazard. The serde representation is
/// `snake_case` (`"physical"` / `"semantic"`) and must not change — it is the
/// on-disk config format.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyboardMode {
    /// Pass physical key positions through verbatim (no cross-platform
    /// shortcut remapping). The default for predictable, low-surprise typing.
    #[default]
    Physical,
    /// Translate a small set of semantic shortcuts (copy/paste/…) to the
    /// destination platform's native modifier convention.
    Semantic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_physical() {
        assert_eq!(KeyboardMode::default(), KeyboardMode::Physical);
    }

    #[test]
    fn serde_repr_is_stable_snake_case() {
        // This is the on-disk config format; it must not change.
        assert_eq!(
            serde_json::to_string(&KeyboardMode::Physical).unwrap(),
            "\"physical\""
        );
        assert_eq!(
            serde_json::to_string(&KeyboardMode::Semantic).unwrap(),
            "\"semantic\""
        );
        assert_eq!(
            serde_json::from_str::<KeyboardMode>("\"semantic\"").unwrap(),
            KeyboardMode::Semantic
        );
    }
}
