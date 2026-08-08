use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use kvm_types::{DeviceId, DeviceRoute, DisplayId, Edge, HostId, PeerId, Platform};
use serde::{Deserialize, Serialize};

use crate::ConfigError;

pub const CURRENT_CONFIG_VERSION: u16 = 2;
pub const DEFAULT_KVM_PORT: u16 = 24_800;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub version: u16,
    #[serde(default)]
    pub paired_hosts: Vec<PairedHostConfig>,
    #[serde(default)]
    pub topology: TopologyConfig,
    #[serde(default)]
    pub device_routes: Vec<DeviceRouteConfig>,
    #[serde(default)]
    pub keyboard: KeyboardSettings,
    #[serde(default)]
    pub failsafe: FailsafeSettings,
    #[serde(default)]
    pub clipboard: ClipboardSettings,
    #[serde(default)]
    pub startup: StartupSettings,
    #[serde(default)]
    pub network: NetworkSettings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            paired_hosts: Vec::new(),
            topology: TopologyConfig::default(),
            device_routes: Vec::new(),
            keyboard: KeyboardSettings::default(),
            failsafe: FailsafeSettings::default(),
            clipboard: ClipboardSettings::default(),
            startup: StartupSettings::default(),
            network: NetworkSettings::default(),
        }
    }
}

impl Config {
    /// Checks cross-field invariants before configuration reaches the daemon.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] for invalid versions, duplicate or
    /// dangling identifiers, unsafe limits, and inconsistent timeouts.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CURRENT_CONFIG_VERSION {
            return Err(ConfigError::Validation(format!(
                "expected version {CURRENT_CONFIG_VERSION}, got {}",
                self.version
            )));
        }

        ensure_unique(
            self.paired_hosts.iter().map(|peer| peer.host_id),
            "paired host id",
        )?;
        ensure_unique(
            self.paired_hosts.iter().map(|peer| peer.peer_id),
            "paired peer id",
        )?;
        for peer in &self.paired_hosts {
            if peer.name.trim().is_empty() || peer.name.len() > 255 {
                return invalid("paired host name must contain 1..=255 bytes");
            }
            if peer.identity_fingerprint.trim().is_empty() || peer.identity_fingerprint.len() > 512
            {
                return invalid("peer identity fingerprint must contain 1..=512 bytes");
            }
        }

        ensure_unique(
            self.topology
                .displays
                .iter()
                .map(|placement| placement.display_id),
            "display placement",
        )?;
        let placed: HashSet<_> = self
            .topology
            .displays
            .iter()
            .map(|placement| placement.display_id)
            .collect();
        for placement in &self.topology.displays {
            if !placement.x.is_finite() || !placement.y.is_finite() {
                return invalid("display placement coordinates must be finite");
            }
        }
        ensure_unique(
            self.topology
                .links
                .iter()
                .map(|link| (link.from_display, link.from_edge)),
            "topology source display edge",
        )?;
        for link in &self.topology.links {
            if link.from_display == link.to_display {
                return invalid("a topology link cannot connect a display to itself");
            }
            if !placed.contains(&link.from_display) || !placed.contains(&link.to_display) {
                return invalid("topology links must reference placed displays");
            }
        }

        ensure_unique(
            self.device_routes.iter().map(|route| route.device_id),
            "device route",
        )?;

        if self.failsafe.shortcut.is_empty() || self.failsafe.shortcut.len() > 8 {
            return invalid("failsafe shortcut must contain 1..=8 keys");
        }
        ensure_unique(
            self.failsafe.shortcut.iter().copied(),
            "failsafe shortcut key",
        )?;
        if self.failsafe.routing_suspend_seconds == 0 {
            return invalid("failsafe routing suspension must be at least one second");
        }

        if self.clipboard.max_text_bytes == 0 || self.clipboard.max_text_bytes > 1024 * 1024 {
            return invalid("clipboard text limit must be in 1..=1048576 bytes");
        }
        if self.network.listen_port == 0 {
            return invalid("network listen port cannot be zero");
        }
        if !(100..=60_000).contains(&self.network.heartbeat_interval_ms) {
            return invalid("heartbeat interval must be in 100..=60000 milliseconds");
        }
        if self.network.failure_timeout_ms < self.network.heartbeat_interval_ms * 2 {
            return invalid("failure timeout must be at least two heartbeat intervals");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PairedHostConfig {
    pub host_id: HostId,
    pub peer_id: PeerId,
    pub name: String,
    pub platform: Platform,
    /// Fingerprint of the peer's public identity, never a private credential.
    pub identity_fingerprint: String,
    pub last_address: Option<SocketAddr>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TopologyConfig {
    #[serde(default)]
    pub displays: Vec<DisplayPlacement>,
    #[serde(default)]
    pub links: Vec<TopologyLink>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct DisplayPlacement {
    pub display_id: DisplayId,
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TopologyLink {
    pub from_display: DisplayId,
    pub from_edge: Edge,
    pub to_display: DisplayId,
    pub to_edge: Edge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceRouteConfig {
    pub device_id: DeviceId,
    pub route: ConfiguredDeviceRoute,
}

/// Durable config representation; conversion to the runtime domain route is
/// explicit so a future domain refactor need not silently alter persisted TOML.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfiguredDeviceRoute {
    FollowActiveHost,
    Local,
    Host { host_id: HostId },
}

impl From<ConfiguredDeviceRoute> for DeviceRoute {
    fn from(value: ConfiguredDeviceRoute) -> Self {
        match value {
            ConfiguredDeviceRoute::FollowActiveHost => Self::FollowActiveHost,
            ConfiguredDeviceRoute::Local => Self::Local,
            ConfiguredDeviceRoute::Host { host_id } => Self::Host(host_id),
        }
    }
}

impl From<DeviceRoute> for ConfiguredDeviceRoute {
    fn from(value: DeviceRoute) -> Self {
        match value {
            DeviceRoute::FollowActiveHost => Self::FollowActiveHost,
            DeviceRoute::Local => Self::Local,
            DeviceRoute::Host(host_id) => Self::Host { host_id },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyboardMode {
    #[default]
    Physical,
    Semantic,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyboardSettings {
    #[serde(default)]
    pub mode: KeyboardMode,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShortcutKey {
    Control,
    Alt,
    Shift,
    Meta,
    Backspace,
    Escape,
    Physical { usage_page: u16, usage: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FailsafeSettings {
    pub shortcut: Vec<ShortcutKey>,
    /// Duration during which remote routing remains off after activation.
    pub routing_suspend_seconds: u32,
}

impl Default for FailsafeSettings {
    fn default() -> Self {
        Self {
            shortcut: vec![
                ShortcutKey::Control,
                ShortcutKey::Alt,
                ShortcutKey::Shift,
                ShortcutKey::Backspace,
            ],
            routing_suspend_seconds: 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClipboardSettings {
    pub enabled: bool,
    pub max_text_bytes: usize,
}

impl Default for ClipboardSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_text_bytes: 256 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StartupSettings {
    pub enabled: bool,
}

impl Default for StartupSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum BindScope {
    /// Platform networking must choose private/local interfaces and must not
    /// expose the daemon on a public WAN interface.
    #[default]
    LocalNetwork,
    SpecificAddresses {
        addresses: Vec<IpAddr>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub discovery_enabled: bool,
    pub listen_port: u16,
    #[serde(default)]
    pub bind: BindScope,
    pub auto_reconnect: bool,
    pub heartbeat_interval_ms: u32,
    pub failure_timeout_ms: u32,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            discovery_enabled: true,
            listen_port: DEFAULT_KVM_PORT,
            bind: BindScope::LocalNetwork,
            auto_reconnect: true,
            heartbeat_interval_ms: 1_000,
            failure_timeout_ms: 3_000,
        }
    }
}

fn ensure_unique<T: Eq + std::hash::Hash>(
    values: impl IntoIterator<Item = T>,
    label: &str,
) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return invalid(format!("duplicate {label}"));
        }
    }
    Ok(())
}

fn invalid<T>(detail: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Validation(detail.into()))
}
