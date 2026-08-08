//! Versioned, human-readable daemon configuration.
//!
//! This crate stores public peer metadata and settings only. Private keys,
//! bearer tokens, and other long-term credentials belong in `kvm-security` and
//! the operating system credential store.

mod error;
mod migrate;
mod model;
mod store;

pub use error::ConfigError;
pub use migrate::{decode_config, encode_config};
pub use model::*;
pub use store::{ConfigStore, ConfigStoreAuthority, FileConfigStore, MemoryConfigStore};
