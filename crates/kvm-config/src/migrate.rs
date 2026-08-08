use kvm_types::{HostId, PeerId, Platform};
use serde::{Deserialize, Serialize};

use crate::{
    Config, ConfigError, DeviceRouteConfig, DisplayPlacement, FailsafeSettings, KeyboardMode,
    KeyboardSettings, NetworkSettings, PairedHostConfig, ShortcutKey, StartupSettings,
    TopologyConfig, CURRENT_CONFIG_VERSION, MAX_CONFIG_FILE_BYTES,
};

#[derive(Deserialize)]
struct VersionProbe {
    version: u16,
}

/// Parses any supported persisted schema and migrates it to the current model.
///
/// # Errors
///
/// Returns [`ConfigError`] when TOML is malformed, its version is unsupported,
/// or the decoded/migrated values fail validation.
pub fn decode_config(source: &str) -> Result<Config, ConfigError> {
    if source.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::SizeLimit);
    }
    let probe: VersionProbe = toml::from_str(source)?;
    let config = match probe.version {
        1 => ConfigV1::migrate(toml::from_str(source)?),
        CURRENT_CONFIG_VERSION => toml::from_str(source)?,
        found if found > CURRENT_CONFIG_VERSION => {
            return Err(ConfigError::FutureVersion {
                found,
                supported: CURRENT_CONFIG_VERSION,
            });
        }
        found => return Err(ConfigError::UnsupportedVersion(found)),
    };
    config.validate()?;
    Ok(config)
}

/// Validates and serializes the current schema as human-readable TOML.
///
/// # Errors
///
/// Returns [`ConfigError`] when validation or TOML serialization fails.
pub fn encode_config(config: &Config) -> Result<String, ConfigError> {
    config.validate()?;
    let encoded = toml::to_string_pretty(config)?;
    if encoded.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::SizeLimit);
    }
    Ok(encoded)
}

/// Original flat settings schema. Kept private so all consumers immediately
/// receive the current, validated representation.
#[derive(Deserialize, Serialize)]
struct ConfigV1 {
    version: u16,
    #[serde(default)]
    paired_hosts: Vec<PairedHostV1>,
    #[serde(default)]
    display_layout: Vec<DisplayPlacement>,
    #[serde(default)]
    device_routes: Vec<DeviceRouteConfig>,
    #[serde(default)]
    keyboard_mode: KeyboardMode,
    #[serde(default = "default_v1_failsafe")]
    failsafe_shortcut: Vec<ShortcutKey>,
    #[serde(default = "default_true")]
    clipboard_enabled: bool,
    #[serde(default = "default_true")]
    startup_enabled: bool,
    #[serde(default = "default_true")]
    discovery_enabled: bool,
    #[serde(default = "default_port")]
    listen_port: u16,
}

impl ConfigV1 {
    fn migrate(old: Self) -> Config {
        let network = NetworkSettings {
            discovery_enabled: old.discovery_enabled,
            listen_port: old.listen_port,
            ..NetworkSettings::default()
        };
        Config {
            version: CURRENT_CONFIG_VERSION,
            paired_hosts: old.paired_hosts.into_iter().map(Into::into).collect(),
            topology: TopologyConfig {
                displays: old.display_layout,
                links: Vec::new(),
            },
            device_routes: old.device_routes,
            device_route_revision: 0,
            keyboard: KeyboardSettings {
                mode: old.keyboard_mode,
            },
            failsafe: FailsafeSettings {
                shortcut: old.failsafe_shortcut,
                ..FailsafeSettings::default()
            },
            clipboard: crate::ClipboardSettings {
                enabled: old.clipboard_enabled,
                ..crate::ClipboardSettings::default()
            },
            startup: StartupSettings {
                enabled: old.startup_enabled,
            },
            network,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct PairedHostV1 {
    host_id: HostId,
    peer_id: PeerId,
    name: String,
    platform: Platform,
    identity_fingerprint: String,
}

impl From<PairedHostV1> for PairedHostConfig {
    fn from(value: PairedHostV1) -> Self {
        Self {
            host_id: value.host_id,
            peer_id: value.peer_id,
            name: value.name,
            platform: value.platform,
            identity_fingerprint: value.identity_fingerprint,
            last_address: None,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_port() -> u16 {
    crate::DEFAULT_KVM_PORT
}

fn default_v1_failsafe() -> Vec<ShortcutKey> {
    FailsafeSettings::default().shortcut
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BindScope, ClipboardSettings, ConfiguredDeviceRoute};
    use kvm_types::{DeviceId, DisplayId};

    #[test]
    fn migrates_flat_v1_to_current_nested_settings() {
        let host = HostId::from_bytes([1; 16]);
        let peer = PeerId::from_bytes([2; 16]);
        let display = DisplayId::from_bytes([3; 16]);
        let device = DeviceId::from_bytes([4; 16]);
        let old = ConfigV1 {
            version: 1,
            paired_hosts: vec![PairedHostV1 {
                host_id: host,
                peer_id: peer,
                name: "MacBook".into(),
                platform: Platform::MacOS,
                identity_fingerprint: "11".repeat(32),
            }],
            display_layout: vec![DisplayPlacement {
                display_id: display,
                x: 100.0,
                y: 200.0,
            }],
            device_routes: vec![DeviceRouteConfig {
                device_id: device,
                route: ConfiguredDeviceRoute::Host { host_id: host },
            }],
            keyboard_mode: KeyboardMode::Semantic,
            failsafe_shortcut: default_v1_failsafe(),
            clipboard_enabled: false,
            startup_enabled: false,
            discovery_enabled: false,
            listen_port: 24_801,
        };

        let migrated = decode_config(&toml::to_string(&old).unwrap()).unwrap();
        assert_eq!(migrated.version, CURRENT_CONFIG_VERSION);
        assert_eq!(migrated.paired_hosts[0].last_address, None);
        assert_eq!(migrated.topology.displays[0].display_id, display);
        assert!(migrated.topology.links.is_empty());
        assert_eq!(migrated.keyboard.mode, KeyboardMode::Semantic);
        assert_eq!(
            migrated.clipboard,
            ClipboardSettings {
                enabled: false,
                ..ClipboardSettings::default()
            }
        );
        assert!(!migrated.startup.enabled);
        assert!(!migrated.network.discovery_enabled);
        assert_eq!(migrated.network.listen_port, 24_801);
        assert_eq!(migrated.network.bind, BindScope::LocalNetwork);
    }

    #[test]
    fn current_config_round_trips_in_human_readable_form() {
        let config = Config {
            device_route_revision: 7,
            ..Config::default()
        };
        let encoded = encode_config(&config).unwrap();
        assert!(encoded.contains("version = 2"));
        assert!(encoded.contains("device_route_revision = 7"));
        assert_eq!(decode_config(&encoded).unwrap(), config);
    }

    #[test]
    fn older_v2_without_route_revision_decodes_at_zero() {
        let decoded = decode_config("version = 2").unwrap();
        assert_eq!(decoded.device_route_revision, 0);
    }

    #[test]
    fn future_versions_are_rejected_without_guessing() {
        let error = decode_config("version = 99").unwrap_err();
        assert!(matches!(
            error,
            ConfigError::FutureVersion {
                found: 99,
                supported: CURRENT_CONFIG_VERSION
            }
        ));
    }

    #[test]
    fn direct_decode_rejects_oversized_input_before_toml_errors() {
        let oversized =
            "SECRET-CONFIG-MARKER".repeat(MAX_CONFIG_FILE_BYTES / "SECRET-CONFIG-MARKER".len() + 1);
        let error = decode_config(&oversized).unwrap_err();
        assert!(matches!(error, ConfigError::SizeLimit));
        assert!(!format!("{error:?} {error}").contains("SECRET-CONFIG-MARKER"));
    }
}
