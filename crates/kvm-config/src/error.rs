use std::error::Error;
use std::fmt;
use std::path::PathBuf;

pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    Decode(toml::de::Error),

    Encode(toml::ser::Error),

    SizeLimit,

    FutureVersion {
        found: u16,
        supported: u16,
    },

    UnsupportedVersion(u16),

    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Read { .. } => "could not read configuration",
            Self::Write { .. } => "could not write configuration",
            Self::Decode(_) => "configuration contains invalid TOML",
            Self::Encode(_) => "configuration could not be encoded as TOML",
            Self::SizeLimit => "configuration exceeds the maximum supported size",
            Self::FutureVersion { .. } => "configuration version is newer than supported",
            Self::UnsupportedVersion(_) => "configuration version is not supported",
            Self::Validation(_) => "configuration validation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for ConfigError {}

impl From<toml::de::Error> for ConfigError {
    fn from(error: toml::de::Error) -> Self {
        Self::Decode(error)
    }
}

impl From<toml::ser::Error> for ConfigError {
    fn from(error: toml::ser::Error) -> Self {
        Self::Encode(error)
    }
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Read { .. } => "Read",
            Self::Write { .. } => "Write",
            Self::Decode(_) => "Decode",
            Self::Encode(_) => "Encode",
            Self::SizeLimit => "SizeLimit",
            Self::FutureVersion { .. } => "FutureVersion",
            Self::UnsupportedVersion(_) => "UnsupportedVersion",
            Self::Validation(_) => "Validation",
        };
        formatter
            .debug_struct("ConfigError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Serialize;

    use super::*;

    #[test]
    fn decode_diagnostics_do_not_echo_invalid_configuration_source() {
        const MARKER: &str = "SECRET-PEER-FINGERPRINT-MARKER";
        let source = format!("identity_fingerprint = [{MARKER:?}");
        let error = toml::from_str::<toml::Value>(&source).unwrap_err();
        let error = ConfigError::Decode(error);
        let rendered = format!("{error:?} {error}");

        assert!(!rendered.contains(MARKER));
        assert!(!rendered.contains("identity_fingerprint"));
    }

    #[derive(Serialize)]
    struct UnsupportedMapKey {
        values: BTreeMap<Vec<u8>, String>,
    }

    #[test]
    fn encode_diagnostics_do_not_echo_serializer_details() {
        const MARKER: &str = "SECRET-ENCODE-MARKER";
        let value = UnsupportedMapKey {
            values: BTreeMap::from([(vec![1, 2, 3], MARKER.to_owned())]),
        };
        let error = toml::to_string(&value).unwrap_err();
        let error = ConfigError::Encode(error);
        let rendered = format!("{error:?} {error}");

        assert!(!rendered.contains(MARKER));
        assert!(!rendered.contains("map key"));
    }

    #[test]
    fn io_and_validation_diagnostics_hide_paths_sources_and_details() {
        const MARKER: &str = "SECRET-CONFIG-ERROR-MARKER";
        let io_error = std::io::Error::other(MARKER);
        let read = ConfigError::Read {
            path: PathBuf::from(MARKER),
            source: io_error,
        };
        let validation = ConfigError::Validation(MARKER.to_owned());

        let rendered = format!("{read:?} {read} {validation:?} {validation}");
        assert!(!rendered.contains(MARKER));
        assert!(read.source().is_none());
        assert!(validation.source().is_none());
    }
}
