use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use kvm_types::{DeviceId, DeviceRoute, DisplayId, Edge, HostId, PeerId, Platform};
use serde::{Deserialize, Serialize};

use crate::ConfigError;

pub use kvm_router::MAX_DEVICE_ROUTES;

pub const CURRENT_CONFIG_VERSION: u16 = 2;
pub const DEFAULT_KVM_PORT: u16 = 24_800;
pub const MAX_CONFIG_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_PAIRED_HOSTS: usize = 256;
pub const MAX_SPECIFIC_BIND_ADDRESSES: usize = 32;

const SHA256_FINGERPRINT_HEX_BYTES: usize = 64;
const MAX_PAIRED_HOST_NAME_BYTES: usize = 128;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub version: u16,
    #[serde(default)]
    pub paired_hosts: Vec<PairedHostConfig>,
    #[serde(default)]
    pub topology: TopologyConfig,
    #[serde(default)]
    pub device_routes: Vec<DeviceRouteConfig>,
    /// Monotonic revision of the durable per-device routing policy.
    ///
    /// This field was added compatibly to schema v2. Older v2 files decode as
    /// revision zero and receive their first checked revision on mutation.
    #[serde(default)]
    pub device_route_revision: u64,
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

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (bind_scope, bind_address_count) = match &self.network.bind {
            BindScope::LocalNetwork => ("local_network", 0),
            BindScope::SpecificAddresses { addresses } => ("specific_addresses", addresses.len()),
        };
        formatter
            .debug_struct("Config")
            .field("version", &self.version)
            .field("paired_host_count", &self.paired_hosts.len())
            .field("display_count", &self.topology.displays.len())
            .field("topology_link_count", &self.topology.links.len())
            .field("device_route_count", &self.device_routes.len())
            .field(
                "has_device_route_revision",
                &(self.device_route_revision != 0),
            )
            .field("failsafe_shortcut_count", &self.failsafe.shortcut.len())
            .field("clipboard_enabled", &self.clipboard.enabled)
            .field("startup_enabled", &self.startup.enabled)
            .field("discovery_enabled", &self.network.discovery_enabled)
            .field("bind_scope", &bind_scope)
            .field("bind_address_count", &bind_address_count)
            .finish_non_exhaustive()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            paired_hosts: Vec::new(),
            topology: TopologyConfig::default(),
            device_routes: Vec::new(),
            device_route_revision: 0,
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

        validate_paired_hosts(&self.paired_hosts)?;

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
            if placement.display_id.into_bytes() == [0; 16] {
                return invalid("display placement display identifier must be non-nil");
            }
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
            if link.from_display.into_bytes() == [0; 16] || link.to_display.into_bytes() == [0; 16]
            {
                return invalid("topology link display identifiers must be non-nil");
            }
            if link.from_display == link.to_display {
                return invalid("a topology link cannot connect a display to itself");
            }
            if !placed.contains(&link.from_display) || !placed.contains(&link.to_display) {
                return invalid("topology links must reference placed displays");
            }
        }

        if self.device_routes.len() > MAX_DEVICE_ROUTES {
            return invalid("device route count exceeds maximum");
        }
        ensure_unique(
            self.device_routes.iter().map(|route| route.device_id),
            "device route",
        )?;
        let paired_hosts: HashSet<_> = self.paired_hosts.iter().map(|peer| peer.host_id).collect();
        for route in &self.device_routes {
            if route.device_id.into_bytes() == [0; 16] {
                return invalid("device route identifier must be non-nil");
            }
            if let ConfiguredDeviceRoute::Host { host_id } = route.route {
                if host_id.into_bytes() == [0; 16] || !paired_hosts.contains(&host_id) {
                    return invalid("device route host target must be paired");
                }
            }
        }

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
        validate_network(&self.network)?;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PairedHostConfig {
    pub host_id: HostId,
    pub peer_id: PeerId,
    pub name: String,
    pub platform: Platform,
    /// Fingerprint of the peer's public identity, never a private credential.
    pub identity_fingerprint: String,
    pub last_address: Option<SocketAddr>,
}

impl fmt::Debug for PairedHostConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedHostConfig")
            .field("identity", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("platform", &self.platform)
            .field("fingerprint", &"[REDACTED]")
            .field("has_last_address", &self.last_address.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TopologyConfig {
    #[serde(default)]
    pub displays: Vec<DisplayPlacement>,
    #[serde(default)]
    pub links: Vec<TopologyLink>,
}

impl fmt::Debug for TopologyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TopologyConfig")
            .field("display_count", &self.displays.len())
            .field("link_count", &self.links.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DisplayPlacement {
    pub display_id: DisplayId,
    pub x: f64,
    pub y: f64,
}

impl fmt::Debug for DisplayPlacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisplayPlacement([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TopologyLink {
    pub from_display: DisplayId,
    pub from_edge: Edge,
    pub to_display: DisplayId,
    pub to_edge: Edge,
}

impl fmt::Debug for TopologyLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TopologyLink([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceRouteConfig {
    pub device_id: DeviceId,
    pub route: ConfiguredDeviceRoute,
}

impl fmt::Debug for DeviceRouteConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceRouteConfig")
            .field("device_id", &"[REDACTED]")
            .field("route", &self.route)
            .finish()
    }
}

/// Durable config representation; conversion to the runtime domain route is
/// explicit so a future domain refactor need not silently alter persisted TOML.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfiguredDeviceRoute {
    FollowActiveHost,
    Local,
    Host { host_id: HostId },
}

impl fmt::Debug for ConfiguredDeviceRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FollowActiveHost => "ConfiguredDeviceRoute::FollowActiveHost",
            Self::Local => "ConfiguredDeviceRoute::Local",
            Self::Host { .. } => "ConfiguredDeviceRoute::Host([REDACTED])",
        })
    }
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

/// Keyboard translation policy. Canonical definition lives in [`kvm_types`];
/// re-exported here so configuration consumers can import it from the config
/// schema as before. The serde representation is unchanged (`snake_case`).
pub use kvm_types::KeyboardMode;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyboardSettings {
    #[serde(default)]
    pub mode: KeyboardMode,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
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

impl fmt::Debug for ShortcutKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShortcutKey([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FailsafeSettings {
    pub shortcut: Vec<ShortcutKey>,
    /// Duration during which remote routing remains off after activation.
    pub routing_suspend_seconds: u32,
}

impl fmt::Debug for FailsafeSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailsafeSettings")
            .field("shortcut_count", &self.shortcut.len())
            .field("routing_suspend_seconds", &self.routing_suspend_seconds)
            .finish_non_exhaustive()
    }
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

#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
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

impl fmt::Debug for BindScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalNetwork => formatter.write_str("BindScope::LocalNetwork"),
            Self::SpecificAddresses { addresses } => formatter
                .debug_struct("BindScope::SpecificAddresses")
                .field("address_count", &addresses.len())
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub discovery_enabled: bool,
    pub listen_port: u16,
    #[serde(default)]
    pub bind: BindScope,
    pub auto_reconnect: bool,
    pub heartbeat_interval_ms: u32,
    pub failure_timeout_ms: u32,
}

impl fmt::Debug for NetworkSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkSettings")
            .field("discovery_enabled", &self.discovery_enabled)
            .field("listen_port", &self.listen_port)
            .field("bind", &self.bind)
            .field("auto_reconnect", &self.auto_reconnect)
            .field("heartbeat_interval_ms", &self.heartbeat_interval_ms)
            .field("failure_timeout_ms", &self.failure_timeout_ms)
            .finish()
    }
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

fn validate_paired_hosts(peers: &[PairedHostConfig]) -> Result<(), ConfigError> {
    if peers.len() > MAX_PAIRED_HOSTS {
        return invalid("paired host count exceeds 256");
    }
    ensure_unique(peers.iter().map(|peer| peer.host_id), "paired host id")?;
    ensure_unique(peers.iter().map(|peer| peer.peer_id), "paired peer id")?;
    for peer in peers {
        if peer.host_id.into_bytes() == [0; 16] || peer.peer_id.into_bytes() == [0; 16] {
            return invalid("paired host and peer identifiers must be non-nil");
        }
        if peer.name.trim().is_empty()
            || peer.name.len() > MAX_PAIRED_HOST_NAME_BYTES
            || peer.name.chars().any(char::is_control)
        {
            return invalid("paired host name must contain 1..=128 non-control UTF-8 bytes");
        }
        if !is_canonical_sha256_fingerprint(&peer.identity_fingerprint) {
            return invalid("peer identity fingerprint must contain 64 lowercase hex characters");
        }
        if peer
            .last_address
            .is_some_and(|address| !is_lan_socket_address(address))
        {
            return invalid("paired last address must be a private LAN endpoint");
        }
    }
    Ok(())
}

fn validate_network(network: &NetworkSettings) -> Result<(), ConfigError> {
    if network.listen_port == 0 {
        return invalid("network listen port cannot be zero");
    }
    if let BindScope::SpecificAddresses { addresses } = &network.bind {
        if addresses.is_empty() || addresses.len() > MAX_SPECIFIC_BIND_ADDRESSES {
            return invalid("specific bind address count must be in 1..=32");
        }
        ensure_unique(addresses.iter().copied(), "specific bind address")?;
        if addresses.iter().copied().any(|address| !is_lan_ip(address)) {
            return invalid("specific bind addresses must be private LAN addresses");
        }
    }
    if !(100..=60_000).contains(&network.heartbeat_interval_ms) {
        return invalid("heartbeat interval must be in 100..=60000 milliseconds");
    }
    if network.failure_timeout_ms < network.heartbeat_interval_ms * 2 {
        return invalid("failure timeout must be at least two heartbeat intervals");
    }
    Ok(())
}

fn is_canonical_sha256_fingerprint(value: &str) -> bool {
    value.len() == SHA256_FINGERPRINT_HEX_BYTES
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_lan_socket_address(address: SocketAddr) -> bool {
    address.port() != 0 && is_lan_ip(address.ip())
}

fn is_lan_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.segments()[0] & 0xfe00 == 0xfc00,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn paired(index: u16) -> PairedHostConfig {
        let mut host_id = [0_u8; 16];
        host_id[..2].copy_from_slice(&index.to_be_bytes());
        let mut peer_id = host_id;
        peer_id[15] = 1;
        PairedHostConfig {
            host_id: HostId::from_bytes(host_id),
            peer_id: PeerId::from_bytes(peer_id),
            name: format!("peer-{index}"),
            platform: Platform::Windows,
            identity_fingerprint: "ab".repeat(32),
            last_address: None,
        }
    }

    #[test]
    fn paired_identity_metadata_is_strictly_bounded_and_canonical() {
        for fingerprint in [
            "AB".repeat(32),
            "ab".repeat(31),
            format!("{}gg", "ab".repeat(31)),
            format!("sha256:{}", "ab".repeat(32)),
        ] {
            let mut config = Config::default();
            let mut peer = paired(1);
            peer.identity_fingerprint = fingerprint;
            config.paired_hosts.push(peer);
            assert!(config.validate().is_err());
        }

        for (host, peer) in [([0; 16], [2; 16]), ([1; 16], [0; 16])] {
            let mut config = Config::default();
            let mut paired = paired(1);
            paired.host_id = HostId::from_bytes(host);
            paired.peer_id = PeerId::from_bytes(peer);
            config.paired_hosts.push(paired);
            assert!(config.validate().is_err());
        }

        let mut config = Config::default();
        for index in 1..=u16::try_from(MAX_PAIRED_HOSTS).unwrap() {
            config.paired_hosts.push(paired(index));
        }
        config
            .paired_hosts
            .push(paired(u16::try_from(MAX_PAIRED_HOSTS + 1).unwrap()));
        assert!(config.validate().is_err());
    }

    #[test]
    fn last_known_addresses_are_untrusted_private_lan_hints_only() {
        for address in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, 24_800)),
            SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 24_800)),
            SocketAddr::from((Ipv4Addr::new(192, 168, 1, 2), 0)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 24_800)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 24_800)),
        ] {
            let mut config = Config::default();
            let mut peer = paired(1);
            peer.last_address = Some(address);
            config.paired_hosts.push(peer);
            assert!(config.validate().is_err());
        }

        for address in [
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 24_800)),
            SocketAddr::from(("fd00::2".parse::<Ipv6Addr>().unwrap(), 24_800)),
        ] {
            let mut config = Config::default();
            let mut peer = paired(1);
            peer.last_address = Some(address);
            config.paired_hosts.push(peer);
            config.validate().unwrap();
        }
    }

    #[test]
    fn explicit_bind_addresses_are_nonempty_unique_bounded_and_private() {
        for addresses in [
            Vec::new(),
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            (1..=MAX_SPECIFIC_BIND_ADDRESSES + 1)
                .map(|index| IpAddr::V4(Ipv4Addr::new(10, 0, 0, u8::try_from(index).unwrap())))
                .collect(),
        ] {
            let mut config = Config::default();
            config.network.bind = BindScope::SpecificAddresses { addresses };
            assert!(config.validate().is_err());
        }

        let mut config = Config::default();
        config.network.bind = BindScope::SpecificAddresses {
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)),
                IpAddr::V6("fd00::2".parse().unwrap()),
            ],
        };
        config.validate().unwrap();
    }

    #[test]
    fn configuration_debug_redacts_peer_controlled_identity_and_addresses() {
        let marker = "SECRET-PEER-NAME";
        let fingerprint = "ab".repeat(32);
        let address: SocketAddr = "10.23.45.67:24800".parse().unwrap();
        let mut config = Config::default();
        let mut peer = paired(1);
        peer.name = marker.into();
        peer.identity_fingerprint = fingerprint.clone();
        peer.last_address = Some(address);
        let host_id = peer.host_id.to_string();
        let peer_id = peer.peer_id.to_string();
        config.paired_hosts.push(peer.clone());
        let first_display = DisplayId::from_bytes([0x41; 16]);
        let second_display = DisplayId::from_bytes([0x42; 16]);
        let placement = DisplayPlacement {
            display_id: first_display,
            x: 1234.5,
            y: -678.25,
        };
        let link = TopologyLink {
            from_display: first_display,
            from_edge: Edge::Right,
            to_display: second_display,
            to_edge: Edge::Left,
        };
        config.topology.displays.push(placement);
        config.topology.displays.push(DisplayPlacement {
            display_id: second_display,
            x: 2345.5,
            y: -678.25,
        });
        config.topology.links.push(link);
        let device_route = DeviceRouteConfig {
            device_id: DeviceId::from_bytes([0x43; 16]),
            route: ConfiguredDeviceRoute::Host {
                host_id: peer.host_id,
            },
        };
        config.device_routes.push(device_route);
        config.network.bind = BindScope::SpecificAddresses {
            addresses: vec![address.ip()],
        };

        let rendered = format!(
            "{config:?} {peer:?} {:?} {placement:?} {link:?} {device_route:?} {:?} {:?}",
            config.topology, config.network.bind, config.network
        );
        let first_display_id = first_display.to_string();
        let second_display_id = second_display.to_string();
        let device_id = device_route.device_id.to_string();
        for secret in [
            marker,
            fingerprint.as_str(),
            host_id.as_str(),
            peer_id.as_str(),
            "10.23.45.67",
            first_display_id.as_str(),
            second_display_id.as_str(),
            device_id.as_str(),
            "1234.5",
            "-678.25",
        ] {
            assert!(!rendered.contains(secret));
        }
        assert!(rendered.len() < 1_024);
    }

    #[test]
    fn failsafe_diagnostics_hide_exact_shortcut_keys_and_physical_usages() {
        let settings = FailsafeSettings {
            shortcut: vec![
                ShortcutKey::Escape,
                ShortcutKey::Physical {
                    usage_page: 54_321,
                    usage: 12_345,
                },
            ],
            routing_suspend_seconds: 17,
        };

        let rendered = format!(
            "{settings:?} {:?} {:?}",
            settings.shortcut[0], settings.shortcut[1]
        );
        for marker in ["Escape", "Physical", "54321", "12345"] {
            assert!(!rendered.contains(marker));
        }
        assert!(rendered.contains("shortcut_count"));
        assert!(rendered.contains("[REDACTED]"));
    }

    fn indexed_device(index: usize) -> DeviceId {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
        DeviceId::from_bytes(bytes)
    }

    #[test]
    fn device_routes_are_bounded_unique_and_non_nil() {
        let maximum = Config {
            device_routes: (0..MAX_DEVICE_ROUTES)
                .map(|index| DeviceRouteConfig {
                    device_id: indexed_device(index),
                    route: ConfiguredDeviceRoute::FollowActiveHost,
                })
                .collect(),
            ..Config::default()
        };
        maximum.validate().unwrap();

        let mut oversized = maximum.clone();
        oversized.device_routes.push(DeviceRouteConfig {
            device_id: indexed_device(MAX_DEVICE_ROUTES),
            route: ConfiguredDeviceRoute::Local,
        });
        assert!(oversized.validate().is_err());

        let duplicate = Config {
            device_routes: vec![maximum.device_routes[0], maximum.device_routes[0]],
            ..Config::default()
        };
        assert!(duplicate.validate().is_err());

        let mut nil = Config::default();
        nil.device_routes.push(DeviceRouteConfig {
            device_id: DeviceId::from_bytes([0; 16]),
            route: ConfiguredDeviceRoute::Local,
        });
        assert!(nil.validate().is_err());
    }

    #[test]
    fn explicit_host_routes_require_an_exact_paired_target() {
        let allowed = paired(7);
        let mut config = Config::default();
        config.paired_hosts.push(allowed.clone());
        config.device_routes.push(DeviceRouteConfig {
            device_id: indexed_device(0),
            route: ConfiguredDeviceRoute::Host {
                host_id: allowed.host_id,
            },
        });
        config.validate().unwrap();

        let before = config.clone();
        config.device_routes[0].route = ConfiguredDeviceRoute::Host {
            host_id: HostId::from_bytes([0x77; 16]),
        };
        let error = config.validate().unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert_eq!(before.device_routes.len(), config.device_routes.len());
        assert!(!rendered.contains(&HostId::from_bytes([0x77; 16]).to_string()));

        config.device_routes[0].route = ConfiguredDeviceRoute::Host {
            host_id: HostId::from_bytes([0; 16]),
        };
        assert!(config.validate().is_err());
    }
}
