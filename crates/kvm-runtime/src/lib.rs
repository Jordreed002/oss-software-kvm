//! Foreground composition boundary for the manually provisioned two-host
//! Windows/macOS alpha.
//!
//! The runtime keeps one selected peer, authenticated transport, native
//! capture/injection, workspace authority, and shutdown tree under one
//! fail-closed owner.

use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use kvm_network::LanPeerAddress;
use kvm_types::{HostId, PeerId};
use serde::Deserialize;

mod active;
mod native_capture;
mod platform_run;
mod preparation;
mod runtime_status;

pub use active::{
    RuntimeCompositionError, RuntimeCompositionErrorKind, RuntimeTransportError,
    RuntimeTransportErrorKind, TwoHostAlphaRuntime,
};
pub use native_capture::{
    NativeCaptureError, NativeCaptureErrorKind, NativeCaptureRouter, NativeCaptureState,
    NativeCaptureSupervisor,
};
pub use platform_run::{run_native_profile, NativeRuntimeError, NativeRuntimeErrorKind};
pub use preparation::{
    prepare, PreparedTwoHostAlpha, PreparedTwoHostAlphaParts, RuntimePreparationError,
    RuntimePreparationErrorKind, MAX_CERTIFICATE_DER_BYTES, MAX_PRIVATE_KEY_DER_BYTES,
    MAX_TRUST_DER_BYTES,
};

/// Current manual two-host alpha profile version.
pub const CURRENT_PROFILE_VERSION: u16 = 2;

/// Maximum accepted profile size.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;

/// Maximum byte length for profile-owned display and TLS server names.
pub const MAX_PROFILE_NAME_BYTES: usize = 128;

/// Maximum number of explicitly provisioned local listener addresses.
pub const MAX_LISTEN_ADDRESSES: usize = 4;

/// Versioned manual provisioning for exactly one selected peer.
#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TwoHostAlphaProfile {
    pub version: u16,
    /// Master activation gate. Missing values remain disabled.
    #[serde(default)]
    pub enabled: bool,
    /// Explicit consent to use whole-host capture/suppression semantics.
    #[serde(default)]
    pub whole_host_alpha: bool,
    pub kvm_config_path: PathBuf,
    pub listen_addresses: Vec<SocketAddr>,
    pub local: LocalIdentity,
    pub selected_peer: SelectedPeer,
    pub tls: TlsPaths,
    pub topology: SelectedOnlyBoundary,
    pub routing: SelectedOnlyBoundary,
}

impl fmt::Debug for TwoHostAlphaProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwoHostAlphaProfile")
            .field("version", &self.version)
            .field("enabled", &self.enabled)
            .field("whole_host_alpha", &self.whole_host_alpha)
            .field("identity_count", &2)
            .field("has_kvm_config_path", &true)
            .field("listen_address_count", &self.listen_addresses.len())
            .field("tls_path_count", &3)
            .field("topology", &self.topology)
            .field("routing", &self.routing)
            .finish_non_exhaustive()
    }
}

/// Stable local host and transport peer identity.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalIdentity {
    pub host_id: HostId,
    pub peer_id: PeerId,
    pub display_name: String,
}

impl fmt::Debug for LocalIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalIdentity([REDACTED])")
    }
}

/// The sole remote peer admitted by the alpha profile.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SelectedPeer {
    pub host_id: HostId,
    pub peer_id: PeerId,
    /// SHA-256 certificate/public-identity fingerprint as 64 hexadecimal digits.
    pub identity_fingerprint: String,
    pub socket_address: SocketAddr,
    pub server_name: String,
}

impl fmt::Debug for SelectedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectedPeer([REDACTED])")
    }
}

/// Explicit filesystem locations for local TLS identity and selected-peer trust.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsPaths {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub peer_trust: PathBuf,
}

impl fmt::Debug for TlsPaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsPaths([REDACTED])")
    }
}

/// An explicit boundary preventing the alpha profile from expressing arbitrary
/// topology or routing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SelectedOnlyBoundary {
    SelectedOnly,
}

impl TwoHostAlphaProfile {
    /// Parses and validates a profile without exposing parser-controlled text.
    ///
    /// # Errors
    ///
    /// Returns a coarse, redacted error for malformed or invalid input.
    pub fn parse(source: &str) -> Result<Self, RuntimeProfileError> {
        if source.len() > MAX_PROFILE_BYTES {
            return Err(RuntimeProfileError::new(RuntimeProfileErrorKind::SizeLimit));
        }
        let profile: Self = toml::from_str(source)
            .map_err(|_| RuntimeProfileError::new(RuntimeProfileErrorKind::Decode))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Validates the selected-only identity, endpoint, and credential boundary.
    ///
    /// # Errors
    ///
    /// Returns a coarse, redacted validation error when any invariant fails.
    pub fn validate(&self) -> Result<(), RuntimeProfileError> {
        if self.version != CURRENT_PROFILE_VERSION {
            return invalid();
        }

        let ids = [
            self.local.host_id.into_bytes(),
            self.local.peer_id.into_bytes(),
            self.selected_peer.host_id.into_bytes(),
            self.selected_peer.peer_id.into_bytes(),
        ];
        if ids.contains(&[0; 16]) {
            return invalid();
        }
        for (index, id) in ids.iter().enumerate() {
            if ids[index + 1..].contains(id) {
                return invalid();
            }
        }

        if self.enabled && !self.whole_host_alpha {
            return invalid();
        }
        if !valid_name(&self.local.display_name)
            || !valid_name(&self.selected_peer.server_name)
            || !valid_fingerprint(&self.selected_peer.identity_fingerprint)
            || LanPeerAddress::new(self.selected_peer.socket_address).is_err()
        {
            return invalid();
        }

        if self.listen_addresses.is_empty() || self.listen_addresses.len() > MAX_LISTEN_ADDRESSES {
            return invalid();
        }
        let listener_port = self.listen_addresses[0].port();
        for (index, address) in self.listen_addresses.iter().copied().enumerate() {
            if LanPeerAddress::new(address).is_err()
                || address.port() != listener_port
                || self.listen_addresses[index + 1..].contains(&address)
            {
                return invalid();
            }
        }

        for path in [
            self.kvm_config_path.as_path(),
            self.tls.certificate.as_path(),
            self.tls.private_key.as_path(),
            self.tls.peer_trust.as_path(),
        ] {
            if !valid_absolute_path(path) {
                return invalid();
            }
        }

        Ok(())
    }
}

/// Reads, parses, and validates a manual profile.
///
/// # Errors
///
/// Returns a coarse error which never contains the path or file contents.
pub fn load_profile(path: &Path) -> Result<TwoHostAlphaProfile, RuntimeProfileError> {
    let metadata =
        fs::metadata(path).map_err(|_| RuntimeProfileError::new(RuntimeProfileErrorKind::Read))?;
    if metadata.len() > u64::try_from(MAX_PROFILE_BYTES).unwrap_or(u64::MAX) {
        return Err(RuntimeProfileError::new(RuntimeProfileErrorKind::SizeLimit));
    }
    let source = fs::read_to_string(path)
        .map_err(|_| RuntimeProfileError::new(RuntimeProfileErrorKind::Read))?;
    TwoHostAlphaProfile::parse(&source)
}

/// Executes the foreground native command with an explicit shutdown signal.
///
/// The `run` command crosses the secure preparation boundary and starts the
/// selected Windows/macOS alpha. `validate` remains non-activating.
///
/// # Errors
///
/// Returns redacted usage, profile, or native-runtime failures.
pub async fn execute_with_shutdown<I, S>(
    arguments: I,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<RuntimeCommandOutcome, RuntimeCommandError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let command = arguments.next().ok_or(RuntimeCommandError::Usage)?;
    let profile_path = arguments.next().ok_or(RuntimeCommandError::Usage)?;
    if arguments.next().is_some() {
        return Err(RuntimeCommandError::Usage);
    }

    match command.as_str() {
        "validate" => {
            load_profile(Path::new(&profile_path)).map_err(RuntimeCommandError::Profile)?;
            Ok(RuntimeCommandOutcome::Valid)
        }
        "run" => {
            run_native_profile(Path::new(&profile_path), shutdown)
                .await
                .map_err(RuntimeCommandError::Native)?;
            Ok(RuntimeCommandOutcome::Stopped)
        }
        _ => Err(RuntimeCommandError::Usage),
    }
}

/// Successful command result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCommandOutcome {
    Valid,
    Stopped,
}

/// Coarse profile failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProfileErrorKind {
    Read,
    SizeLimit,
    Decode,
    Validation,
}

/// Path-, identity-, endpoint-, and payload-redacted profile failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RuntimeProfileError {
    kind: RuntimeProfileErrorKind,
}

impl RuntimeProfileError {
    const fn new(kind: RuntimeProfileErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RuntimeProfileErrorKind {
        self.kind
    }
}

impl fmt::Debug for RuntimeProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProfileError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimeProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RuntimeProfileErrorKind::Read => "could not read runtime profile",
            RuntimeProfileErrorKind::SizeLimit => "runtime profile exceeds the size limit",
            RuntimeProfileErrorKind::Decode => "runtime profile contains invalid TOML",
            RuntimeProfileErrorKind::Validation => "runtime profile validation failed",
        })
    }
}

impl std::error::Error for RuntimeProfileError {}

/// Fail-closed CLI failure.
#[derive(Eq, PartialEq)]
pub enum RuntimeCommandError {
    Usage,
    Profile(RuntimeProfileError),
    Native(NativeRuntimeError),
}

impl fmt::Debug for RuntimeCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Usage => "Usage",
            Self::Profile(_) => "Profile",
            Self::Native(_) => "Native",
        };
        formatter
            .debug_struct("RuntimeCommandError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimeCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str("usage: kvm-runtime <validate|run> <profile.toml>"),
            Self::Profile(error) => error.fmt(formatter),
            Self::Native(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RuntimeCommandError {}

const fn invalid<T>() -> Result<T, RuntimeProfileError> {
    Err(RuntimeProfileError::new(
        RuntimeProfileErrorKind::Validation,
    ))
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_PROFILE_NAME_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_absolute_path(path: &Path) -> bool {
    path.is_absolute() && path.file_name().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_source() -> String {
        r#"
version = 2
enabled = false
whole_host_alpha = false
kvm_config_path = "/etc/software-kvm/config.toml"
topology = "selected_only"
routing = "selected_only"
listen_addresses = ["192.168.1.10:24800"]

[local]
host_id = "11111111-1111-4111-8111-111111111111"
peer_id = "22222222-2222-4222-8222-222222222222"
display_name = "Local Alpha"

[selected_peer]
host_id = "33333333-3333-4333-8333-333333333333"
peer_id = "44444444-4444-4444-8444-444444444444"
identity_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
socket_address = "192.168.1.20:24800"
server_name = "selected-peer.kvm.test"

[tls]
certificate = "/etc/software-kvm/tls/local.crt"
private_key = "/etc/software-kvm/tls/local.key"
peer_trust = "/etc/software-kvm/tls/selected-peer.crt"
"#
        .into()
    }

    #[test]
    fn parses_disabled_selected_only_profile() {
        let profile = TwoHostAlphaProfile::parse(&valid_source()).unwrap();
        assert!(!profile.enabled);
        assert!(!profile.whole_host_alpha);
        assert_eq!(profile.topology, SelectedOnlyBoundary::SelectedOnly);
        assert_eq!(profile.routing, SelectedOnlyBoundary::SelectedOnly);
    }

    #[test]
    fn rejects_previous_profile_version() {
        let source = valid_source().replace("version = 2", "version = 1");
        assert_eq!(
            TwoHostAlphaProfile::parse(&source).unwrap_err().kind(),
            RuntimeProfileErrorKind::Validation
        );
    }

    #[test]
    fn activation_requires_explicit_whole_host_opt_in() {
        let source = valid_source().replace("enabled = false", "enabled = true");
        assert_eq!(
            TwoHostAlphaProfile::parse(&source).unwrap_err().kind(),
            RuntimeProfileErrorKind::Validation
        );

        let source = source.replace("whole_host_alpha = false", "whole_host_alpha = true");
        TwoHostAlphaProfile::parse(&source).unwrap();
    }

    #[test]
    fn rejects_nil_duplicate_and_local_colliding_identities() {
        for source in [
            valid_source().replace(
                "11111111-1111-4111-8111-111111111111",
                "00000000-0000-0000-0000-000000000000",
            ),
            valid_source().replace(
                "33333333-3333-4333-8333-333333333333",
                "11111111-1111-4111-8111-111111111111",
            ),
            valid_source().replace(
                "44444444-4444-4444-8444-444444444444",
                "22222222-2222-4222-8222-222222222222",
            ),
        ] {
            assert!(TwoHostAlphaProfile::parse(&source).is_err());
        }
    }

    #[test]
    fn rejects_third_peer_and_open_ended_boundaries() {
        let third = format!(
            "{}\n[[peers]]\nhost_id = \"55555555-5555-4555-8555-555555555555\"\n",
            valid_source()
        );
        assert!(TwoHostAlphaProfile::parse(&third).is_err());
        assert!(
            TwoHostAlphaProfile::parse(&valid_source().replace("selected_only", "arbitrary",))
                .is_err()
        );
    }

    #[test]
    fn rejects_relative_or_empty_paths_and_unsafe_endpoint() {
        for source in [
            valid_source().replace("/etc/software-kvm/config.toml", "relative/config.toml"),
            valid_source().replace("/etc/software-kvm/tls/local.key", ""),
            valid_source().replace("192.168.1.20:24800", "0.0.0.0:24800"),
            valid_source().replace("192.168.1.20:24800", "192.168.1.20:0"),
        ] {
            assert!(TwoHostAlphaProfile::parse(&source).is_err());
        }
    }

    #[test]
    fn selected_and_listener_endpoints_use_lan_peer_policy() {
        for unsafe_address in [
            "8.8.8.8:24800",
            "127.0.0.1:24800",
            "169.254.1.2:24800",
            "224.0.0.1:24800",
        ] {
            let selected = valid_source().replace("192.168.1.20:24800", unsafe_address);
            assert!(TwoHostAlphaProfile::parse(&selected).is_err());

            let listener = valid_source().replace("192.168.1.10:24800", unsafe_address);
            assert!(TwoHostAlphaProfile::parse(&listener).is_err());
        }

        let ula = valid_source()
            .replace("192.168.1.20:24800", "[fd00::20]:24800")
            .replace("192.168.1.10:24800", "[fd00::10]:24800");
        TwoHostAlphaProfile::parse(&ula).unwrap();
    }

    #[test]
    fn fingerprint_must_be_canonical_lowercase_sha256_hex() {
        let uppercase = valid_source().replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(TwoHostAlphaProfile::parse(&uppercase).is_err());
    }

    #[test]
    fn display_and_server_names_are_nonblank_control_free_and_bounded() {
        let oversized = "x".repeat(MAX_PROFILE_NAME_BYTES + 1);
        for source in [
            valid_source().replace("Local Alpha", "   "),
            valid_source().replace("Local Alpha", "bad\\u0007name"),
            valid_source().replace("Local Alpha", &oversized),
            valid_source().replace("selected-peer.kvm.test", "   "),
            valid_source().replace("selected-peer.kvm.test", "bad\\u0007name"),
            valid_source().replace("selected-peer.kvm.test", &oversized),
        ] {
            assert!(TwoHostAlphaProfile::parse(&source).is_err());
        }
    }

    #[test]
    fn listener_addresses_are_nonempty_unique_bounded_and_share_a_port() {
        for replacement in [
            "[]".to_owned(),
            "[\"192.168.1.10:24800\", \"192.168.1.10:24800\"]".to_owned(),
            "[\"192.168.1.10:24800\", \"192.168.1.11:24801\"]".to_owned(),
            "[\"192.168.1.10:24800\", \"192.168.1.11:24800\", \"192.168.1.12:24800\", \"192.168.1.13:24800\", \"192.168.1.14:24800\"]".to_owned(),
        ] {
            let source = valid_source().replace(
                "[\"192.168.1.10:24800\"]",
                &replacement,
            );
            assert!(TwoHostAlphaProfile::parse(&source).is_err());
        }
    }

    #[test]
    fn diagnostics_redact_every_sensitive_marker() {
        let source = valid_source()
            .replace("Local Alpha", "LOCAL-SECRET")
            .replace("selected-peer.kvm.test", "SERVER-SECRET")
            .replace(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "not-a-fingerprint-SECRET",
            );
        let error = TwoHostAlphaProfile::parse(&source).unwrap_err();
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(!rendered.contains("SECRET"));
            assert!(!rendered.contains("192.168.1.20"));
            assert!(!rendered.contains("/etc/software-kvm"));
            assert!(!rendered.contains("11111111"));
        }

        let profile = TwoHostAlphaProfile::parse(
            &valid_source()
                .replace("Local Alpha", "LOCAL-SECRET")
                .replace("selected-peer.kvm.test", "SERVER-SECRET"),
        )
        .unwrap();
        let rendered = format!("{profile:?}");
        assert!(!rendered.contains("192.168.1.20"));
        assert!(!rendered.contains("/etc/software-kvm"));
        assert!(!rendered.contains("11111111"));
        assert!(!rendered.contains("LOCAL-SECRET"));
        assert!(!rendered.contains("SERVER-SECRET"));
    }
}
