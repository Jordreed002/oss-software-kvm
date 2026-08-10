//! Static, fail-closed preparation for the two-host alpha runtime.

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

#[cfg(unix)]
use std::io::Read;

use kvm_config::Config;
#[cfg(any(unix, windows))]
use kvm_config::{decode_config, ConfiguredDeviceRoute, MAX_CONFIG_FILE_BYTES};
#[cfg(any(unix, windows))]
use kvm_network::{
    RustlsAcceptorConfig, RustlsClientCredentials, RustlsClientTrust, RustlsConnectorConfig,
    RustlsServerCredentials, RustlsServerTrust, TransportPeerIdentity,
};
use kvm_network::{RustlsTcpAcceptor, RustlsTcpConnector};
#[cfg(any(unix, windows))]
use kvm_protocol::{
    HelloV1, WireHostId, WirePeerId, WirePlatform, CURRENT_PROTOCOL_VERSION,
    MIN_SUPPORTED_PROTOCOL_VERSION,
};
#[cfg(any(unix, windows))]
use kvm_security::{IdentityFingerprint, PairedPeer, PairedPeerAllowlist, PairedPeerStore};
use kvm_security::{
    MemoryPairedPeerStore, PairedClientResolverSnapshot, PairedSessionAdmission, PeerIdentity,
};
#[cfg(any(unix, windows))]
use sha2::{Digest, Sha256};
#[cfg(any(unix, windows))]
use zeroize::Zeroizing;

#[cfg(any(unix, windows))]
use crate::{RuntimeProfileErrorKind, TwoHostAlphaProfile, MAX_PROFILE_BYTES};

#[cfg(windows)]
mod windows_secure_file;

/// Positive upper bound for each single DER certificate file.
pub const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
/// Positive upper bound for the single PKCS#8 DER private-key file.
pub const MAX_PRIVATE_KEY_DER_BYTES: usize = 16 * 1024;
/// Positive upper bound for the selected peer's single DER trust certificate.
pub const MAX_TRUST_DER_BYTES: usize = 64 * 1024;

pub(crate) type PreparedAdmission = PairedSessionAdmission<MemoryPairedPeerStore>;
pub(crate) type PreparedAcceptor = RustlsTcpAcceptor<PairedClientResolverSnapshot>;

pub(crate) struct PreparedAdmissionFactory {
    local_identity: PeerIdentity,
    remote_identity: PeerIdentity,
}

impl PreparedAdmissionFactory {
    fn new(local_identity: PeerIdentity, remote_identity: PeerIdentity) -> Self {
        Self {
            local_identity,
            remote_identity,
        }
    }

    pub(crate) fn build(&self) -> Result<PreparedAdmission, RuntimePreparationError> {
        let paired = PairedPeer::from_persisted_public_identity(self.remote_identity.clone());
        let mut store = MemoryPairedPeerStore::default();
        store.upsert(paired).map_err(|_| identity_error())?;
        PairedSessionAdmission::new(
            self.local_identity.clone(),
            local_hello(&self.local_identity),
            PairedPeerAllowlist::new(store),
        )
        .map_err(|_| identity_error())
    }
}

impl fmt::Debug for PreparedAdmissionFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedAdmissionFactory([REDACTED])")
    }
}

/// Fully validated static material for later runtime composition.
///
/// Construction does not bind, connect, start capture, or create a session.
/// Fields remain private so later composition has a single explicit ownership
/// transfer instead of being able to mix prepared and unprepared material.
pub struct PreparedTwoHostAlpha {
    parts: PreparedTwoHostAlphaParts,
}

impl PreparedTwoHostAlpha {
    /// Whether the profile's master activation gate was enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.parts.enabled
    }

    /// Number of explicitly provisioned listener addresses.
    #[must_use]
    pub fn listen_address_count(&self) -> usize {
        self.parts.listen_addresses.len()
    }

    #[cfg(any(target_os = "macos", windows))]
    pub(crate) const fn local_host_id(&self) -> kvm_types::HostId {
        self.parts.local_identity.host_id()
    }

    #[cfg(any(target_os = "macos", windows))]
    pub(crate) fn selected_peer_platform(&self) -> Option<kvm_types::Platform> {
        self.parts
            .config
            .paired_hosts
            .first()
            .map(|peer| peer.platform)
    }

    /// Transfers all validated components to the later runtime composer.
    #[must_use]
    pub fn into_parts(self) -> PreparedTwoHostAlphaParts {
        self.parts
    }
}

impl fmt::Debug for PreparedTwoHostAlpha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedTwoHostAlpha")
            .field("enabled", &self.parts.enabled)
            .field("identity_count", &2)
            .field("paired_peer_count", &1)
            .field("listen_address_count", &self.parts.listen_addresses.len())
            .field("credential_category_count", &3)
            .finish_non_exhaustive()
    }
}

/// Opaque ownership bundle consumed by the later active runtime composer.
///
/// Its fields are crate-private deliberately. The public type makes the
/// preparation/composition transition explicit without exposing credentials.
pub struct PreparedTwoHostAlphaParts {
    pub(crate) enabled: bool,
    pub(crate) config: Config,
    pub(crate) local_identity: PeerIdentity,
    pub(crate) remote_identity: PeerIdentity,
    pub(crate) listen_addresses: Vec<SocketAddr>,
    pub(crate) selected_address: SocketAddr,
    pub(crate) admission_factory: PreparedAdmissionFactory,
    pub(crate) connector: RustlsTcpConnector,
    pub(crate) acceptor: PreparedAcceptor,
}

impl fmt::Debug for PreparedTwoHostAlphaParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let component_category_count = [
            std::mem::size_of_val(&self.config),
            std::mem::size_of_val(&self.local_identity),
            std::mem::size_of_val(&self.remote_identity),
            std::mem::size_of_val(&self.selected_address),
            std::mem::size_of_val(&self.admission_factory),
            std::mem::size_of_val(&self.connector),
            std::mem::size_of_val(&self.acceptor),
        ]
        .into_iter()
        .filter(|size| *size != 0)
        .count()
        .saturating_add(1);
        formatter
            .debug_struct("PreparedTwoHostAlphaParts")
            .field("enabled", &self.enabled)
            .field("identity_count", &2)
            .field("paired_peer_count", &1)
            .field("listen_address_count", &self.listen_addresses.len())
            .field("component_category_count", &component_category_count)
            .finish_non_exhaustive()
    }
}

/// Loads and validates all static material needed by the selected two-host
/// alpha while starting no I/O or native capture.
///
/// On Unix, every file is opened with `O_NOFOLLOW`, checked from the opened
/// descriptor, and bounded while reading. On Windows, traversal is restricted
/// to local drive paths and opens each component relative to its checked parent
/// with `FILE_OPEN_REPARSE_POINT`. Profile, main config, and private key must be
/// owned by the process user and private under the platform's permission model.
/// Other platforms fail closed.
///
/// # Errors
///
/// Returns only coarse, path- and content-redacted failure categories.
pub fn prepare(profile_path: &Path) -> Result<PreparedTwoHostAlpha, RuntimePreparationError> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = profile_path;
        Err(RuntimePreparationError::new(
            RuntimePreparationErrorKind::UnsupportedPlatform,
        ))
    }

    #[cfg(unix)]
    {
        prepare_unix(profile_path)
    }

    #[cfg(windows)]
    {
        prepare_windows(profile_path)
    }
}

#[cfg(windows)]
fn prepare_windows(profile_path: &Path) -> Result<PreparedTwoHostAlpha, RuntimePreparationError> {
    let profile_bytes = windows_secure_file::secure_read(
        profile_path,
        MAX_PROFILE_BYTES,
        windows_secure_file::FilePolicy::OwnerPrivate,
    )?;
    let profile_source = std::str::from_utf8(&profile_bytes).map_err(|_| decode_error())?;
    let profile = TwoHostAlphaProfile::parse(profile_source).map_err(|error| {
        RuntimePreparationError::new(match error.kind() {
            RuntimeProfileErrorKind::SizeLimit => RuntimePreparationErrorKind::SizeLimit,
            RuntimeProfileErrorKind::Read
            | RuntimeProfileErrorKind::Decode
            | RuntimeProfileErrorKind::Validation => RuntimePreparationErrorKind::Profile,
        })
    })?;

    let config_bytes = windows_secure_file::secure_read(
        &profile.kvm_config_path,
        MAX_CONFIG_FILE_BYTES,
        windows_secure_file::FilePolicy::OwnerPrivate,
    )?;
    let config_source = std::str::from_utf8(&config_bytes).map_err(|_| decode_error())?;
    let config = decode_config(config_source).map_err(|_| config_error())?;
    validate_config_matches_profile(&config, &profile)?;

    let certificate = windows_secure_file::secure_read(
        &profile.tls.certificate,
        MAX_CERTIFICATE_DER_BYTES,
        windows_secure_file::FilePolicy::PublicRegular,
    )?;
    let private_key = windows_secure_file::secure_read(
        &profile.tls.private_key,
        MAX_PRIVATE_KEY_DER_BYTES,
        windows_secure_file::FilePolicy::OwnerPrivate,
    )?;
    let peer_trust = windows_secure_file::secure_read(
        &profile.tls.peer_trust,
        MAX_TRUST_DER_BYTES,
        windows_secure_file::FilePolicy::PublicRegular,
    )?;

    build_prepared(profile, config, &certificate, &private_key, &peer_trust)
}

#[cfg(unix)]
fn prepare_unix(profile_path: &Path) -> Result<PreparedTwoHostAlpha, RuntimePreparationError> {
    let profile_bytes = secure_read(profile_path, MAX_PROFILE_BYTES, FilePolicy::OwnerPrivate)?;
    let profile_source = std::str::from_utf8(&profile_bytes).map_err(|_| decode_error())?;
    let profile = TwoHostAlphaProfile::parse(profile_source).map_err(|error| {
        RuntimePreparationError::new(match error.kind() {
            RuntimeProfileErrorKind::SizeLimit => RuntimePreparationErrorKind::SizeLimit,
            RuntimeProfileErrorKind::Read
            | RuntimeProfileErrorKind::Decode
            | RuntimeProfileErrorKind::Validation => RuntimePreparationErrorKind::Profile,
        })
    })?;

    let config_bytes = secure_read(
        &profile.kvm_config_path,
        MAX_CONFIG_FILE_BYTES,
        FilePolicy::OwnerPrivate,
    )?;
    let config_source = std::str::from_utf8(&config_bytes).map_err(|_| decode_error())?;
    let config = decode_config(config_source).map_err(|_| config_error())?;
    validate_config_matches_profile(&config, &profile)?;

    let certificate = secure_read(
        &profile.tls.certificate,
        MAX_CERTIFICATE_DER_BYTES,
        FilePolicy::PublicRegular,
    )?;
    let private_key = secure_read(
        &profile.tls.private_key,
        MAX_PRIVATE_KEY_DER_BYTES,
        FilePolicy::OwnerPrivate,
    )?;
    let peer_trust = secure_read(
        &profile.tls.peer_trust,
        MAX_TRUST_DER_BYTES,
        FilePolicy::PublicRegular,
    )?;

    build_prepared(profile, config, &certificate, &private_key, &peer_trust)
}

#[cfg(any(unix, windows))]
fn validate_config_matches_profile(
    config: &Config,
    profile: &TwoHostAlphaProfile,
) -> Result<(), RuntimePreparationError> {
    if config.paired_hosts.len() != 1
        || config.network.discovery_enabled
        || config.network.listen_port != profile.selected_peer.socket_address.port()
        || profile
            .listen_addresses
            .iter()
            .any(|address| address.port() != config.network.listen_port)
        || config
            .device_routes
            .iter()
            .any(|route| route.route != ConfiguredDeviceRoute::FollowActiveHost)
    {
        return Err(config_error());
    }

    let configured = &config.paired_hosts[0];
    if configured.host_id != profile.selected_peer.host_id
        || configured.peer_id != profile.selected_peer.peer_id
        || configured.identity_fingerprint != profile.selected_peer.identity_fingerprint
        || configured.last_address != Some(profile.selected_peer.socket_address)
    {
        return Err(config_error());
    }

    Ok(())
}

#[cfg(any(unix, windows))]
fn build_prepared(
    profile: TwoHostAlphaProfile,
    config: Config,
    certificate: &Zeroizing<Vec<u8>>,
    private_key: &Zeroizing<Vec<u8>>,
    peer_trust: &Zeroizing<Vec<u8>>,
) -> Result<PreparedTwoHostAlpha, RuntimePreparationError> {
    let configured = config.paired_hosts.first().ok_or_else(config_error)?;
    let local_fingerprint = IdentityFingerprint::from_sha256(Sha256::digest(certificate).into());
    let remote_fingerprint = profile
        .selected_peer
        .identity_fingerprint
        .parse::<IdentityFingerprint>()
        .map_err(|_| identity_error())?;
    let trust_fingerprint: [u8; 32] = Sha256::digest(peer_trust).into();
    if remote_fingerprint.as_bytes() != &trust_fingerprint {
        return Err(identity_error());
    }

    let local_identity = PeerIdentity::new(
        profile.local.peer_id,
        profile.local.host_id,
        profile.local.display_name.clone(),
        local_fingerprint,
    )
    .map_err(|_| identity_error())?;
    let remote_identity = PeerIdentity::new(
        configured.peer_id,
        configured.host_id,
        configured.name.clone(),
        remote_fingerprint,
    )
    .map_err(|_| identity_error())?;
    let paired = PairedPeer::from_persisted_public_identity(remote_identity.clone());

    let admission_factory =
        PreparedAdmissionFactory::new(local_identity.clone(), remote_identity.clone());
    let _ = admission_factory.build()?;

    let resolver =
        PairedClientResolverSnapshot::from_paired_peers([paired]).map_err(|_| identity_error())?;
    let expected_peer = transport_identity(&remote_identity);
    let connector = RustlsTcpConnector::new(
        RustlsClientCredentials::new(vec![certificate.to_vec()], private_key.to_vec()),
        RustlsServerTrust::new(vec![peer_trust.to_vec()]),
        profile.selected_peer.server_name.clone(),
        expected_peer,
        RustlsConnectorConfig::default(),
    )
    .map_err(|_| credential_error())?;
    let acceptor = RustlsTcpAcceptor::new(
        RustlsServerCredentials::new(vec![certificate.to_vec()], private_key.to_vec()),
        RustlsClientTrust::new(vec![peer_trust.to_vec()]),
        resolver,
        RustlsAcceptorConfig::default(),
    )
    .map_err(|_| credential_error())?;

    Ok(PreparedTwoHostAlpha {
        parts: PreparedTwoHostAlphaParts {
            enabled: profile.enabled,
            config,
            local_identity,
            remote_identity,
            listen_addresses: profile.listen_addresses,
            selected_address: profile.selected_peer.socket_address,
            admission_factory,
            connector,
            acceptor,
        },
    })
}

#[cfg(any(unix, windows))]
fn local_hello(identity: &PeerIdentity) -> HelloV1 {
    HelloV1 {
        host_id: WireHostId(identity.host_id().into_bytes()),
        peer_id: WirePeerId(identity.peer_id().into_bytes()),
        host_name: identity.display_name().to_owned(),
        platform: target_wire_platform(),
        minimum_protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION,
        maximum_protocol_version: CURRENT_PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        nonce: [0; 32],
    }
}

#[cfg(any(unix, windows))]
const fn target_wire_platform() -> WirePlatform {
    #[cfg(target_os = "windows")]
    return WirePlatform::Windows;
    #[cfg(target_os = "macos")]
    return WirePlatform::MacOs;
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    WirePlatform::Linux
}

#[cfg(any(unix, windows))]
fn transport_identity(identity: &PeerIdentity) -> TransportPeerIdentity {
    TransportPeerIdentity {
        host_id: WireHostId(identity.host_id().into_bytes()),
        peer_id: WirePeerId(identity.peer_id().into_bytes()),
        credential_fingerprint: *identity.fingerprint().as_bytes(),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum FilePolicy {
    OwnerPrivate,
    PublicRegular,
}

#[cfg(unix)]
fn secure_read(
    path: &Path,
    maximum: usize,
    policy: FilePolicy,
) -> Result<Zeroizing<Vec<u8>>, RuntimePreparationError> {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{open, openat, Mode, OFlags};

    let mut components = path.components().peekable();
    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = open(
        start,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| file_security_error())?;
    let descriptor = loop {
        let component = components.next().ok_or_else(file_security_error)?;
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) if components.peek().is_none() => {
                break openat(
                    &directory,
                    name,
                    OFlags::RDONLY
                        | OFlags::CLOEXEC
                        | OFlags::NOFOLLOW
                        | OFlags::NONBLOCK
                        | OFlags::NOCTTY,
                    Mode::empty(),
                )
                .map_err(|_| file_security_error())?;
            }
            std::path::Component::Normal(name) => {
                directory = openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| file_security_error())?;
            }
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::Prefix(_) => return Err(file_security_error()),
        }
    };
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| file_security_error())?;
    if !metadata.is_file() {
        return Err(file_security_error());
    }
    if matches!(policy, FilePolicy::OwnerPrivate)
        && (metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0)
    {
        return Err(file_security_error());
    }
    let maximum_u64 = u64::try_from(maximum).map_err(|_| size_error())?;
    if metadata.len() == 0 || metadata.len() > maximum_u64 {
        return Err(size_error());
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(maximum),
    ));
    file.take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| file_security_error())?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(size_error());
    }
    Ok(bytes)
}

/// Coarse static-preparation failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePreparationErrorKind {
    UnsupportedPlatform,
    FileSecurity,
    SizeLimit,
    Profile,
    Config,
    Identity,
    Credentials,
}

/// Path-, endpoint-, identity-, parser-, and credential-redacted failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RuntimePreparationError {
    kind: RuntimePreparationErrorKind,
}

impl RuntimePreparationError {
    const fn new(kind: RuntimePreparationErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RuntimePreparationErrorKind {
        self.kind
    }
}

impl fmt::Debug for RuntimePreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePreparationError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimePreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RuntimePreparationErrorKind::UnsupportedPlatform => {
                "secure runtime preparation is unavailable on this platform"
            }
            RuntimePreparationErrorKind::FileSecurity => {
                "runtime material failed secure file validation"
            }
            RuntimePreparationErrorKind::SizeLimit => {
                "runtime material failed its bounded-size requirement"
            }
            RuntimePreparationErrorKind::Profile => "runtime profile validation failed",
            RuntimePreparationErrorKind::Config => "runtime configuration validation failed",
            RuntimePreparationErrorKind::Identity => "runtime identity validation failed",
            RuntimePreparationErrorKind::Credentials => "runtime credential validation failed",
        })
    }
}

impl std::error::Error for RuntimePreparationError {}

#[cfg(any(unix, windows))]
const fn file_security_error() -> RuntimePreparationError {
    RuntimePreparationError::new(RuntimePreparationErrorKind::FileSecurity)
}

#[cfg(any(unix, windows))]
const fn size_error() -> RuntimePreparationError {
    RuntimePreparationError::new(RuntimePreparationErrorKind::SizeLimit)
}

#[cfg(any(unix, windows))]
const fn decode_error() -> RuntimePreparationError {
    RuntimePreparationError::new(RuntimePreparationErrorKind::Profile)
}

#[cfg(any(unix, windows))]
const fn config_error() -> RuntimePreparationError {
    RuntimePreparationError::new(RuntimePreparationErrorKind::Config)
}

#[cfg(any(unix, windows))]
const fn identity_error() -> RuntimePreparationError {
    RuntimePreparationError::new(RuntimePreparationErrorKind::Identity)
}

#[cfg(any(unix, windows))]
const fn credential_error() -> RuntimePreparationError {
    RuntimePreparationError::new(RuntimePreparationErrorKind::Credentials)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use kvm_config::{
        encode_config, Config, ConfiguredDeviceRoute, DeviceRouteConfig, NetworkSettings,
        PairedHostConfig,
    };
    use kvm_types::{DeviceId, HostId, PeerId, Platform};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use tempfile::TempDir;

    use super::*;

    const LOCAL_HOST: HostId = HostId::from_bytes([1; 16]);
    const LOCAL_PEER: PeerId = PeerId::from_bytes([2; 16]);
    const REMOTE_HOST: HostId = HostId::from_bytes([3; 16]);
    const REMOTE_PEER: PeerId = PeerId::from_bytes([4; 16]);
    const ADDRESS: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 7, 20)),
        24_800,
    );

    struct Fixture {
        directory: TempDir,
        profile_path: std::path::PathBuf,
        config_path: std::path::PathBuf,
        certificate_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
        trust_path: std::path::PathBuf,
        trust: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            // macOS exposes its default temporary root through `/var`, which
            // is itself a symlink. The production loader intentionally rejects
            // every symlink component, so keep the fixture beneath the real
            // checked-out workspace instead of weakening that invariant.
            let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let profile_path = directory.path().join("runtime.toml");
            let config_path = directory.path().join("config.toml");
            let certificate_path = directory.path().join("local.der");
            let key_path = directory.path().join("local.pkcs8.der");
            let trust_path = directory.path().join("remote.der");

            let local_key = KeyPair::generate().unwrap();
            let mut local_params =
                CertificateParams::new(vec!["local.kvm.test".to_owned()]).unwrap();
            local_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let local_certificate = local_params.self_signed(&local_key).unwrap();

            let remote_key = KeyPair::generate().unwrap();
            let mut remote_params =
                CertificateParams::new(vec!["selected-peer.kvm.test".to_owned()]).unwrap();
            remote_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let remote_certificate = remote_params.self_signed(&remote_key).unwrap();
            let trust = remote_certificate.der().to_vec();

            fs::write(&certificate_path, local_certificate.der()).unwrap();
            fs::write(&key_path, local_key.serialize_der()).unwrap();
            fs::write(&trust_path, &trust).unwrap();
            set_private(&key_path);

            let fixture = Self {
                directory,
                profile_path,
                config_path,
                certificate_path,
                key_path,
                trust_path,
                trust,
            };
            fixture.write_config(&fixture.valid_config());
            fixture.write_profile("selected-peer.kvm.test");
            fixture
        }

        fn fingerprint(&self) -> String {
            let digest: [u8; 32] = Sha256::digest(&self.trust).into();
            IdentityFingerprint::from_sha256(digest).to_string()
        }

        fn valid_config(&self) -> Config {
            Config {
                paired_hosts: vec![PairedHostConfig {
                    host_id: REMOTE_HOST,
                    peer_id: REMOTE_PEER,
                    name: "REMOTE-MARKER".to_owned(),
                    platform: Platform::Windows,
                    identity_fingerprint: self.fingerprint(),
                    last_address: Some(ADDRESS),
                }],
                network: NetworkSettings {
                    discovery_enabled: false,
                    listen_port: ADDRESS.port(),
                    ..NetworkSettings::default()
                },
                ..Config::default()
            }
        }

        fn write_config(&self, config: &Config) {
            fs::write(&self.config_path, encode_config(config).unwrap()).unwrap();
            set_private(&self.config_path);
        }

        fn write_profile(&self, server_name: &str) {
            let source = format!(
                r#"version = 2
enabled = true
whole_host_alpha = true
kvm_config_path = "{}"
topology = "selected_only"
routing = "selected_only"
listen_addresses = ["192.168.7.10:24800"]

[local]
host_id = "{}"
peer_id = "{}"
display_name = "LOCAL-MARKER"

[selected_peer]
host_id = "{}"
peer_id = "{}"
identity_fingerprint = "{}"
socket_address = "{}"
server_name = "{}"

[tls]
certificate = "{}"
private_key = "{}"
peer_trust = "{}"
"#,
                self.config_path.display(),
                LOCAL_HOST,
                LOCAL_PEER,
                REMOTE_HOST,
                REMOTE_PEER,
                self.fingerprint(),
                ADDRESS,
                server_name,
                self.certificate_path.display(),
                self.key_path.display(),
                self.trust_path.display(),
            );
            fs::write(&self.profile_path, source).unwrap();
            set_private(&self.profile_path);
        }
    }

    fn set_private(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn assert_kind(fixture: &Fixture, kind: RuntimePreparationErrorKind) {
        assert_eq!(prepare(&fixture.profile_path).unwrap_err().kind(), kind);
    }

    #[test]
    fn prepares_selected_static_material_without_starting_io() {
        let fixture = Fixture::new();
        let prepared = prepare(&fixture.profile_path).unwrap();
        assert!(prepared.enabled());
        assert_eq!(prepared.listen_address_count(), 1);
        let rendered = format!("{prepared:?}");
        for marker in [
            "LOCAL-MARKER",
            "REMOTE-MARKER",
            "192.168.7",
            fixture.directory.path().to_str().unwrap(),
            &fixture.fingerprint(),
        ] {
            assert!(!rendered.contains(marker));
        }

        let parts = prepared.into_parts();
        let rendered = format!("{parts:?}");
        assert!(rendered.contains("listen_address_count: 1"));
        assert!(!rendered.contains("192.168.7"));
    }

    #[test]
    fn rejects_symlinks_and_non_regular_files() {
        let fixture = Fixture::new();
        let profile_link = fixture.directory.path().join("profile-link");
        symlink(&fixture.profile_path, &profile_link).unwrap();
        assert_eq!(
            prepare(&profile_link).unwrap_err().kind(),
            RuntimePreparationErrorKind::FileSecurity
        );

        let parent_link = fixture.directory.path().with_extension("parent-link");
        symlink(fixture.directory.path(), &parent_link).unwrap();
        assert_eq!(
            prepare(&parent_link.join("runtime.toml"))
                .unwrap_err()
                .kind(),
            RuntimePreparationErrorKind::FileSecurity
        );
        fs::remove_file(parent_link).unwrap();

        fs::remove_file(&fixture.certificate_path).unwrap();
        symlink(&fixture.trust_path, &fixture.certificate_path).unwrap();
        assert_kind(&fixture, RuntimePreparationErrorKind::FileSecurity);

        fs::remove_file(&fixture.certificate_path).unwrap();
        fs::create_dir(&fixture.certificate_path).unwrap();
        assert_kind(&fixture, RuntimePreparationErrorKind::FileSecurity);

        let fixture = Fixture::new();
        fs::remove_file(&fixture.certificate_path).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(&fixture.certificate_path)
            .status()
            .unwrap()
            .success());
        assert_kind(&fixture, RuntimePreparationErrorKind::FileSecurity);
    }

    #[test]
    fn rejects_permissive_or_wrong_owner_sensitive_files() {
        for select in 0..3 {
            let fixture = Fixture::new();
            let path = match select {
                0 => &fixture.profile_path,
                1 => &fixture.config_path,
                _ => &fixture.key_path,
            };
            fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
            assert_kind(&fixture, RuntimePreparationErrorKind::FileSecurity);
        }
    }

    #[test]
    fn rejects_empty_and_oversized_material() {
        let fixture = Fixture::new();
        fs::write(&fixture.certificate_path, []).unwrap();
        assert_kind(&fixture, RuntimePreparationErrorKind::SizeLimit);

        let fixture = Fixture::new();
        fs::write(
            &fixture.trust_path,
            vec![0_u8; MAX_TRUST_DER_BYTES.saturating_add(1)],
        )
        .unwrap();
        assert_kind(&fixture, RuntimePreparationErrorKind::SizeLimit);

        let fixture = Fixture::new();
        fs::write(
            &fixture.key_path,
            vec![0_u8; MAX_PRIVATE_KEY_DER_BYTES.saturating_add(1)],
        )
        .unwrap();
        set_private(&fixture.key_path);
        assert_kind(&fixture, RuntimePreparationErrorKind::SizeLimit);
    }

    #[test]
    fn rejects_third_peer_routes_discovery_and_port_mismatch() {
        let fixture = Fixture::new();
        let mut config = fixture.valid_config();
        config.paired_hosts.push(PairedHostConfig {
            host_id: HostId::from_bytes([8; 16]),
            peer_id: PeerId::from_bytes([9; 16]),
            name: "third".to_owned(),
            platform: Platform::MacOS,
            identity_fingerprint: "55".repeat(32),
            last_address: Some("192.168.7.30:24800".parse().unwrap()),
        });
        fixture.write_config(&config);
        assert_kind(&fixture, RuntimePreparationErrorKind::Config);

        let fixture = Fixture::new();
        let mut config = fixture.valid_config();
        config.device_routes.push(DeviceRouteConfig {
            device_id: DeviceId::from_bytes([7; 16]),
            route: ConfiguredDeviceRoute::Local,
        });
        fixture.write_config(&config);
        assert_kind(&fixture, RuntimePreparationErrorKind::Config);

        for mutate in 0..2 {
            let fixture = Fixture::new();
            let mut config = fixture.valid_config();
            if mutate == 0 {
                config.network.discovery_enabled = true;
            } else {
                config.network.listen_port = 24_801;
            }
            fixture.write_config(&config);
            assert_kind(&fixture, RuntimePreparationErrorKind::Config);
        }
    }

    #[test]
    fn rejects_selected_fingerprint_address_and_stable_identity_mismatches() {
        for mutate in 0..4 {
            let fixture = Fixture::new();
            let mut config = fixture.valid_config();
            match mutate {
                0 => config.paired_hosts[0].identity_fingerprint = "44".repeat(32),
                1 => {
                    config.paired_hosts[0].last_address =
                        Some("192.168.7.21:24800".parse().unwrap());
                }
                2 => config.paired_hosts[0].host_id = HostId::from_bytes([9; 16]),
                _ => config.paired_hosts[0].peer_id = PeerId::from_bytes([9; 16]),
            }
            fixture.write_config(&config);
            assert_kind(&fixture, RuntimePreparationErrorKind::Config);
        }
    }

    #[test]
    fn rejects_bad_der_private_key_trust_and_server_name() {
        let fixture = Fixture::new();
        fs::write(&fixture.certificate_path, b"bad certificate").unwrap();
        assert_kind(&fixture, RuntimePreparationErrorKind::Credentials);

        let fixture = Fixture::new();
        fs::write(&fixture.key_path, b"bad key").unwrap();
        set_private(&fixture.key_path);
        assert_kind(&fixture, RuntimePreparationErrorKind::Credentials);

        let fixture = Fixture::new();
        fixture.write_profile("bad name");
        assert_kind(&fixture, RuntimePreparationErrorKind::Credentials);

        let fixture = Fixture::new();
        fs::write(&fixture.trust_path, b"bad trust").unwrap();
        let bad_fingerprint = IdentityFingerprint::from_sha256(Sha256::digest(b"bad trust").into());
        let mut config = fixture.valid_config();
        config.paired_hosts[0].identity_fingerprint = bad_fingerprint.to_string();
        fixture.write_config(&config);
        let profile = fs::read_to_string(&fixture.profile_path)
            .unwrap()
            .replace(&fixture.fingerprint(), &bad_fingerprint.to_string());
        fs::write(&fixture.profile_path, profile).unwrap();
        set_private(&fixture.profile_path);
        assert_kind(&fixture, RuntimePreparationErrorKind::Credentials);
    }

    #[test]
    fn preparation_errors_redact_all_input_markers() {
        let fixture = Fixture::new();
        fixture.write_profile("INVALID SERVER MARKER");
        let error = prepare(&fixture.profile_path).unwrap_err();
        for rendered in [format!("{error}"), format!("{error:?}")] {
            for marker in [
                "MARKER",
                "192.168.7",
                fixture.directory.path().to_str().unwrap(),
                &fixture.fingerprint(),
                &LOCAL_HOST.to_string(),
            ] {
                assert!(!rendered.contains(marker));
            }
        }
    }
}

// `prepare` only returns `UnsupportedPlatform` on targets with neither Unix nor
// Windows file security (see the dispatch in `prepare`). Windows now does real
// work via `prepare_windows`, so this assertion must run on truly-unsupported
// targets only — otherwise it would assert the wrong error kind on Windows.
#[cfg(all(test, not(any(unix, windows))))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn preparation_fails_closed_before_file_access() {
        assert_eq!(
            prepare(Path::new("C:\\not-read\\runtime.toml"))
                .unwrap_err()
                .kind(),
            RuntimePreparationErrorKind::UnsupportedPlatform
        );
    }
}
