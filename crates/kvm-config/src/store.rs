#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use crate::{decode_config, encode_config, Config, ConfigError};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub trait ConfigStore: Send + Sync {
    /// Loads and migrates a configuration when one is present.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for I/O, parsing, migration, or validation
    /// failures.
    fn load(&self) -> Result<Option<Config>, ConfigError>;

    /// Validates and durably saves a configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for validation, serialization, or I/O failures.
    fn save(&self, config: &Config) -> Result<(), ConfigError>;

    /// Loads the stored value or returns safe defaults when no file exists.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`ConfigStore::load`].
    fn load_or_default(&self) -> Result<Config, ConfigError> {
        Ok(self.load()?.unwrap_or_default())
    }
}

#[derive(Clone, Debug)]
pub struct FileConfigStore {
    path: PathBuf,
}

impl FileConfigStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn backup_path(&self) -> PathBuf {
        sibling_with_suffix(&self.path, ".bak")
    }

    fn read_path(path: &Path) -> Result<Option<String>, ConfigError> {
        match fs::read_to_string(path) {
            Ok(contents) => Ok(Some(contents)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(ConfigError::Read {
                path: path.to_owned(),
                source,
            }),
        }
    }
}

impl ConfigStore for FileConfigStore {
    fn load(&self) -> Result<Option<Config>, ConfigError> {
        if let Some(contents) = Self::read_path(&self.path)? {
            return decode_config(&contents).map(Some);
        }

        // A backup without the primary indicates a process or machine stopped
        // during the narrow replace window. Recover the last complete file.
        let backup = self.backup_path();
        Self::read_path(&backup)?
            .map(|contents| decode_config(&contents))
            .transpose()
    }

    fn save(&self, config: &Config) -> Result<(), ConfigError> {
        // Validate and serialize before touching the existing file.
        let encoded = encode_config(config)?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
            path: parent.to_owned(),
            source,
        })?;

        let temp_path = create_temp_path(&self.path);
        let write_result = (|| {
            let mut temp = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
                .map_err(|source| ConfigError::Write {
                    path: temp_path.clone(),
                    source,
                })?;
            temp.write_all(encoded.as_bytes())
                .and_then(|()| temp.flush())
                .and_then(|()| temp.sync_all())
                .map_err(|source| ConfigError::Write {
                    path: temp_path.clone(),
                    source,
                })?;

            let backup = self.backup_path();
            let had_primary = self.path.exists();
            if had_primary {
                remove_if_exists(&backup)?;
                fs::rename(&self.path, &backup).map_err(|source| ConfigError::Write {
                    path: self.path.clone(),
                    source,
                })?;
            }

            if let Err(source) = fs::rename(&temp_path, &self.path) {
                if had_primary {
                    let _ = fs::rename(&backup, &self.path);
                }
                return Err(ConfigError::Write {
                    path: self.path.clone(),
                    source,
                });
            }

            sync_directory(parent)?;
            if had_primary {
                remove_if_exists(&backup)?;
            }
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }
}

#[derive(Debug, Default)]
pub struct MemoryConfigStore {
    value: RwLock<Option<Config>>,
}

impl MemoryConfigStore {
    #[must_use]
    pub fn with_config(config: Config) -> Self {
        Self {
            value: RwLock::new(Some(config)),
        }
    }
}

impl ConfigStore for MemoryConfigStore {
    fn load(&self) -> Result<Option<Config>, ConfigError> {
        Ok(self.value.read().expect("config lock poisoned").clone())
    }

    fn save(&self, config: &Config) -> Result<(), ConfigError> {
        config.validate()?;
        *self.value.write().expect("config lock poisoned") = Some(config.clone());
        Ok(())
    }
}

fn create_temp_path(destination: &Path) -> PathBuf {
    let suffix = format!(
        ".{}.{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    sibling_with_suffix(destination, &suffix)
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml");
    path.with_file_name(format!(".{file_name}{suffix}"))
}

fn remove_if_exists(path: &Path) -> Result<(), ConfigError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConfigError::Write {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ConfigError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ConfigError::Write {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
// Keep the same fallible cross-platform call site as the Unix implementation.
// Windows has no portable directory-fsync equivalent in `std`.
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_directory(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "software-kvm-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn file_store_round_trips_and_replaces_existing_config() {
        let directory = test_directory("roundtrip");
        let path = directory.join("nested/config.toml");
        let store = FileConfigStore::new(&path);
        assert_eq!(store.load().unwrap(), None);

        store.save(&Config::default()).unwrap();
        let mut updated = Config::default();
        updated.clipboard.enabled = false;
        store.save(&updated).unwrap();

        assert_eq!(store.load().unwrap(), Some(updated));
        assert!(!store.backup_path().exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn invalid_save_never_replaces_the_existing_file() {
        let directory = test_directory("invalid");
        let path = directory.join("config.toml");
        let store = FileConfigStore::new(&path);
        let original = Config::default();
        store.save(&original).unwrap();

        let mut invalid = original.clone();
        invalid.network.listen_port = 0;
        assert!(matches!(
            store.save(&invalid),
            Err(ConfigError::Validation(_))
        ));
        assert_eq!(store.load().unwrap(), Some(original));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn load_recovers_a_complete_backup_left_during_replace() {
        let directory = test_directory("recovery");
        fs::create_dir_all(&directory).unwrap();
        let store = FileConfigStore::new(directory.join("config.toml"));
        fs::write(
            store.backup_path(),
            encode_config(&Config::default()).unwrap(),
        )
        .unwrap();

        assert_eq!(store.load().unwrap(), Some(Config::default()));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn memory_store_validates_values() {
        let store = MemoryConfigStore::default();
        assert_eq!(store.load_or_default().unwrap(), Config::default());
        let mut invalid = Config::default();
        invalid.failsafe.shortcut.clear();
        assert!(store.save(&invalid).is_err());
    }
}
