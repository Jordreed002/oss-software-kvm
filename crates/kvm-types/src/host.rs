use serde::{Deserialize, Serialize};

use crate::HostId;

/// An operating-system family supported by a host backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    #[serde(rename = "macos")]
    MacOS,
}

/// A machine participating in a logical workspace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub id: HostId,
    pub name: String,
    pub platform: Platform,
}

impl Host {
    #[must_use]
    pub fn new(id: HostId, name: impl Into<String>, platform: Platform) -> Self {
        Self {
            id,
            name: name.into(),
            platform,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_constructor_accepts_owned_or_borrowed_names() {
        let id = HostId::from_bytes([1; 16]);
        let host = Host::new(id, "desk-pc", Platform::Windows);

        assert_eq!(host.id, id);
        assert_eq!(host.name, "desk-pc");
        assert_eq!(host.platform, Platform::Windows);
    }

    #[test]
    fn macos_has_a_stable_human_readable_serde_name() {
        assert_eq!(
            serde_json::to_string(&Platform::MacOS).unwrap(),
            "\"macos\""
        );
    }
}
