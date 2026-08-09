use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::{decode_config, encode_config, Config, ConfigError, MAX_CONFIG_FILE_BYTES};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Opaque process-local identity for one durable configuration authority.
#[derive(Clone)]
pub struct ConfigStoreAuthority(Arc<()>);

impl ConfigStoreAuthority {
    fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl PartialEq for ConfigStoreAuthority {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ConfigStoreAuthority {}

impl std::fmt::Debug for ConfigStoreAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfigStoreAuthority([REDACTED])")
    }
}

pub trait ConfigStore: Send + Sync {
    /// Returns the opaque identity shared by clones of this store authority.
    fn authority(&self) -> ConfigStoreAuthority;

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

#[derive(Clone)]
pub struct FileConfigStore {
    path: PathBuf,
    authority: ConfigStoreAuthority,
}

impl std::fmt::Debug for FileConfigStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileConfigStore")
            .field("path", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl FileConfigStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            authority: ConfigStoreAuthority::new(),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn backup_path(&self) -> PathBuf {
        sibling_with_suffix(&self.path, ".bak")
    }

    fn read_path(path: &Path) -> Result<Option<String>, ConfigError> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        let limit = u64::try_from(MAX_CONFIG_FILE_BYTES)
            .expect("maximum configuration size fits in u64")
            + 1;
        let mut contents = String::new();
        file.take(limit)
            .read_to_string(&mut contents)
            .map_err(|source| ConfigError::Read {
                path: path.to_owned(),
                source,
            })?;
        if contents.len() > MAX_CONFIG_FILE_BYTES {
            return Err(ConfigError::SizeLimit);
        }
        Ok(Some(contents))
    }
}

impl ConfigStore for FileConfigStore {
    fn authority(&self) -> ConfigStoreAuthority {
        self.authority.clone()
    }

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
            // F-10: peer metadata (identity fingerprint, last address, host/peer
            // ids) must not be world-readable. Set mode 0o600 on the temp file; the
            // atomic rename carries this mode onto the final config path (mirrors
            // the control panel's setup.rs).
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut temp = options
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

pub struct MemoryConfigStore {
    value: RwLock<Option<Config>>,
    authority: ConfigStoreAuthority,
}

impl Default for MemoryConfigStore {
    fn default() -> Self {
        Self {
            value: RwLock::new(None),
            authority: ConfigStoreAuthority::new(),
        }
    }
}

impl std::fmt::Debug for MemoryConfigStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryConfigStore")
            .field("state", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl MemoryConfigStore {
    /// Creates an initialized memory store after validating the configuration.
    ///
    /// # Errors
    ///
    /// Returns a validation error rather than retaining invalid runtime state.
    pub fn with_config(config: Config) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            value: RwLock::new(Some(config)),
            authority: ConfigStoreAuthority::new(),
        })
    }
}

impl ConfigStore for MemoryConfigStore {
    fn authority(&self) -> ConfigStoreAuthority {
        self.authority.clone()
    }

    fn load(&self) -> Result<Option<Config>, ConfigError> {
        let value = self.value.read().expect("config lock poisoned").clone();
        if let Some(config) = &value {
            config.validate()?;
        }
        Ok(value)
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

    fn padded_default_config(length: usize) -> String {
        let mut encoded = encode_config(&Config::default()).unwrap();
        assert!(encoded.len() < length);
        encoded.push('#');
        encoded.extend(std::iter::repeat_n(' ', length - encoded.len()));
        encoded
    }

    #[test]
    fn file_reads_are_bounded_before_configuration_parsing() {
        let directory = test_directory("bounded-read");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("config.toml");
        let store = FileConfigStore::new(&path);

        fs::write(&path, padded_default_config(MAX_CONFIG_FILE_BYTES)).unwrap();
        assert_eq!(store.load().unwrap(), Some(Config::default()));

        fs::write(&path, padded_default_config(MAX_CONFIG_FILE_BYTES + 1)).unwrap();
        assert!(matches!(store.load(), Err(ConfigError::SizeLimit)));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn file_store_debug_hides_configuration_path() {
        let store = FileConfigStore::new("SECRET-CONFIG-PATH/config.toml");
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("SECRET-CONFIG-PATH"));
    }

    #[test]
    fn memory_store_validates_values() {
        let store = MemoryConfigStore::default();
        assert_eq!(store.load_or_default().unwrap(), Config::default());
        let mut invalid = Config::default();
        invalid.failsafe.shortcut.clear();
        assert!(store.save(&invalid).is_err());
        assert!(MemoryConfigStore::with_config(invalid).is_err());
        assert_eq!(
            format!("{store:?}"),
            "MemoryConfigStore { state: \"[REDACTED]\", .. }"
        );
    }
}
