use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not write configuration at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("configuration is not valid TOML: {0}")]
    Decode(#[from] toml::de::Error),

    #[error("configuration could not be encoded as TOML: {0}")]
    Encode(#[from] toml::ser::Error),

    #[error("configuration version {found} is newer than supported version {supported}")]
    FutureVersion { found: u16, supported: u16 },

    #[error("configuration version {0} is not supported")]
    UnsupportedVersion(u16),

    #[error("invalid configuration: {0}")]
    Validation(String),
}
