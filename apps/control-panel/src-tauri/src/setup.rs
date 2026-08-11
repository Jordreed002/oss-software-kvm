// Tauri command parameters are owned/injected at the IPC boundary even when
// the command body only borrows them.
#![allow(clippy::needless_pass_by_value)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kvm_config::{
    encode_config, Config, DisplayPlacement, NetworkSettings, PairedHostConfig, TopologyConfig,
    TopologyLink,
};
#[cfg(any(target_os = "macos", windows))]
use kvm_daemon::DisplayBackend;
use kvm_types::{Display, DisplayId, Edge, HostId, PeerId, Platform};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SigningKey};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::nearby::{
    IncomingWorkspaceAcknowledgement, IncomingWorkspaceLayout, NearbyDiscovery, NearbyMachineDto,
    NearbyPairingDto, NearbyPresence,
};

const KVM_PORT: u16 = 24_800;
/// Separate diagnostics channel port (spec §31): one above the KVM switch so
/// the control panel polls telemetry over a different connection than the
/// active input stream. Mirrors `kvm_network::DEFAULT_DIAGNOSTICS_PORT`.
const DIAGNOSTICS_PORT: u16 = 24_801;
const PAIRING_VERSION: u16 = 3;
const CREDENTIAL_VERSION: u16 = 2;
const STATE_FILE: &str = "setup-state.json";
const LEGACY_STATE_BACKUP_FILE: &str = "setup-state.pre-tls-v2.json";
const PROFILE_FILE: &str = "runtime.toml";
const CONFIG_FILE: &str = "config.toml";
const CERT_FILE: &str = "local.der";
const KEY_FILE: &str = "local-key.pk8";
const TRUST_FILE: &str = "selected-peer.der";
const CONTROL_FILE: &str = "runtime.control";
const RUNTIME_LOG_FILE: &str = "runtime.log";
const RUNTIME_STATUS_FILE: &str = "runtime.status";
const MAX_RUNTIME_LOG_READ: u64 = 16 * 1024;
const MAX_RELAYED_DIAGNOSTIC_LINES: usize = 20;
const MAX_RELAYED_DIAGNOSTIC_LINE_CHARS: usize = 240;
/// Maximum decoded peer-bundle size (matches the import-bundle byte cap).
const MAX_PEER_BUNDLE_BYTES: usize = 64 * 1024;
/// Upper bound on the base64 (URL-safe, no-pad) bundle text *before* decoding:
/// every 3 bytes encode to 4 chars, plus slack for whitespace and rounding. This
/// lets an oversized paste be rejected without allocating the full decode (F-23).
const MAX_PEER_BUNDLE_INPUT_CHARS: usize = MAX_PEER_BUNDLE_BYTES * 4 / 3 + 16;
#[cfg(windows)]
// Keep credentials separate from WebView2's profile in the app-data root.
const WINDOWS_SETUP_DIRECTORY: &str = "runtime";

#[derive(Debug)]
pub(crate) struct SetupService {
    directory: PathBuf,
    inner: Mutex<StoredSetup>,
    runtime: Mutex<Option<Child>>,
    last_runtime_fault: Mutex<Option<RuntimeFault>>,
    pending_workspace: Mutex<Option<IncomingWorkspaceLayout>>,
    diagnostic_relay: Mutex<DiagnosticRelayState>,
    discovery: Option<NearbyDiscovery>,
}

struct DiagnosticRelayState {
    local_stream_id: String,
    next_local_sequence: u64,
    last_local_events: Vec<String>,
    peer_stream_id: Option<String>,
    peer_sequence: u64,
    peer_events: Vec<String>,
}

impl DiagnosticRelayState {
    fn new() -> Self {
        Self {
            local_stream_id: Uuid::new_v4().to_string(),
            next_local_sequence: 1,
            last_local_events: Vec::new(),
            peer_stream_id: None,
            peer_sequence: 0,
            peer_events: Vec::new(),
        }
    }
}

impl std::fmt::Debug for DiagnosticRelayState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiagnosticRelayState")
            .field("local_event_count", &self.last_local_events.len())
            .field("peer_event_count", &self.peer_events.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Placement {
    #[default]
    LocalLeft,
    LocalRight,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredSetup {
    draft_host_id: String,
    draft_peer_id: String,
    local: Option<StoredLocal>,
    peer: Option<PairingBundle>,
    placement: Placement,
    #[serde(default)]
    display_layout: Vec<DisplayLayoutDto>,
    #[serde(default)]
    workspace_role: WorkspaceRole,
    #[serde(default)]
    workspace_revision: u64,
    #[serde(default)]
    workspace_acknowledged_revision: u64,
    configured: bool,
    validated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredLocal {
    #[serde(default)]
    credential_version: u16,
    host_id: String,
    peer_id: String,
    display_name: String,
    server_name: String,
    certificate_fingerprint: String,
    address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PairingBundle {
    software_kvm_pairing: u16,
    host_id: String,
    peer_id: String,
    display_name: String,
    platform: PlatformDto,
    server_name: String,
    certificate_fingerprint: String,
    address: String,
    certificate_der: String,
    #[serde(default)]
    signing_public_key: String,
    displays: Vec<DisplayDto>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkspaceRole {
    #[default]
    Unassigned,
    Leader,
    Follower,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkspaceSyncState {
    NotConfigured,
    Manual,
    Waiting,
    Confirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlatformDto {
    Macos,
    Windows,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisplayDto {
    id: String,
    name: String,
    width: f64,
    height: f64,
    scale_factor: f64,
    primary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_bounds: Option<NativeBoundsDto>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeBoundsDto {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DisplayLayoutDto {
    display_id: DisplayId,
    x: f64,
    y: f64,
}

#[derive(Debug, Deserialize, Serialize)]
struct SignedWorkspaceLayout {
    schema_version: u16,
    revision: u64,
    layout: Vec<DisplayLayoutDto>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalIdentityDto {
    host_id: String,
    peer_id: String,
    display_name: String,
    server_name: String,
    certificate_fingerprint: String,
    address: String,
    public_bundle: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PeerIdentityDto {
    host_id: String,
    peer_id: String,
    display_name: String,
    platform: PlatformDto,
    server_name: String,
    certificate_fingerprint: String,
    address: String,
    displays: Vec<DisplayDto>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeState {
    Stopped,
    Running,
    Faulted,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeFault {
    NativeCapture,
    AuthenticatedTransport,
    RuntimeTask,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum InputOwnerState {
    Local,
    Peer,
    Transitioning,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InputAuthorityDto {
    owner: InputOwnerState,
    link_ready: bool,
    session_active: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeStatusService {
    Starting,
    Running,
    Stopping,
    Faulted,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeStatusOwner {
    Local,
    Peer,
    Transitioning,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeStatusRouting {
    Enabled,
    Gated,
    WaitingForWorkspace,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct RuntimeStatusFile {
    schema_version: u16,
    service: RuntimeStatusService,
    input_owner: RuntimeStatusOwner,
    routing: RuntimeStatusRouting,
    session_active: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum LanBindingState {
    Healthy,
    Mismatch,
    WaitingForPeer,
    NotConfigured,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeveloperDiagnosticsDto {
    lan_binding: LanBindingState,
    configured_listener: Option<String>,
    routed_listener: Option<String>,
    configured_peer: Option<String>,
    observed_peer: Option<String>,
    recent_events: Vec<String>,
    peer_recent_events: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetupSnapshot {
    platform: PlatformDto,
    suggested_name: String,
    address_options: Vec<String>,
    local: Option<LocalIdentityDto>,
    peer: Option<PeerIdentityDto>,
    displays: Vec<DisplayDto>,
    placement: Placement,
    display_layout: Vec<DisplayLayoutDto>,
    workspace_role: WorkspaceRole,
    workspace_revision: u64,
    workspace_sync: WorkspaceSyncState,
    configured: bool,
    validated: bool,
    runtime: RuntimeState,
    runtime_fault: Option<RuntimeFault>,
    input_authority: InputAuthorityDto,
    runtime_log_path: Option<String>,
    discovery_available: bool,
    nearby_machines: Vec<NearbyMachineDto>,
    nearby_pairing: Option<NearbyPairingDto>,
    developer_diagnostics: Option<DeveloperDiagnosticsDto>,
    setup_directory: Option<String>,
    profile_path: Option<String>,
}

impl SetupService {
    pub(crate) fn open(app: &AppHandle) -> Result<Self, Box<dyn std::error::Error>> {
        let app_data_directory = app.path().app_local_data_dir()?;
        fs::create_dir_all(&app_data_directory)?;
        #[cfg(windows)]
        let directory = {
            let directory = app_data_directory.join(WINDOWS_SETUP_DIRECTORY);
            fs::create_dir_all(&directory)?;
            secure_directory(&directory)?;
            migrate_legacy_windows_setup(&app_data_directory, &directory)?;
            restore_windows_app_data_acl(&app_data_directory)?;
            directory
        };
        #[cfg(not(windows))]
        let directory = app_data_directory;
        fs::create_dir_all(&directory)?;
        secure_directory(&directory)?;
        let state_path = directory.join(STATE_FILE);
        let mut stored = fs::read(&state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<StoredSetup>(&bytes).ok())
            .unwrap_or_default();
        if stored.draft_host_id.is_empty() {
            stored.draft_host_id = Uuid::new_v4().to_string();
        }
        if stored.draft_peer_id.is_empty() {
            stored.draft_peer_id = Uuid::new_v4().to_string();
        }
        if !runtime_lock_held(&directory) && reset_legacy_credentials(&directory, &mut stored)? {
            let bytes = serde_json::to_vec_pretty(&stored)?;
            secure_write(&state_path, &bytes, true)
                .map_err(|()| std::io::Error::other("credential upgrade failed"))?;
        }
        let discovery_addresses = private_broadcast_addresses();
        let discovery =
            NearbyDiscovery::start(&stored.draft_peer_id, &discovery_addresses, KVM_PORT).ok();
        if let Some(discovery) = &discovery {
            let advertised_name = stored
                .local
                .as_ref()
                .map_or_else(suggested_name, |local| local.display_name.clone());
            discovery.refresh(&advertised_name, platform_name(), NearbyPresence::SettingUp);
        }
        Ok(Self {
            directory,
            inner: Mutex::new(stored),
            runtime: Mutex::new(None),
            last_runtime_fault: Mutex::new(None),
            pending_workspace: Mutex::new(None),
            diagnostic_relay: Mutex::new(DiagnosticRelayState::new()),
            discovery,
        })
    }

    fn save(&self, setup: &StoredSetup) -> Result<(), ()> {
        let bytes = serde_json::to_vec_pretty(setup).map_err(|_| ())?;
        secure_write(&self.directory.join(STATE_FILE), &bytes, true)
    }

    fn snapshot(&self) -> Result<SetupSnapshot, ()> {
        let (runtime_state, runtime_fault) = self.poll_runtime_state()?;
        let mut setup = self.inner.lock().map_err(|_| ())?.clone();
        let presence = if matches!(runtime_state, RuntimeState::Running) {
            NearbyPresence::RuntimeActive
        } else {
            NearbyPresence::SettingUp
        };
        if let Some(discovery) = &self.discovery {
            let advertised_name = setup
                .local
                .as_ref()
                .map_or_else(suggested_name, |local| local.display_name.clone());
            discovery.refresh(&advertised_name, platform_name(), presence);
        }
        let mut nearby_machines = self.discovery.as_ref().map_or_else(Vec::new, |discovery| {
            discovery.snapshot(setup.peer.as_ref().map(|peer| peer.peer_id.as_str()))
        });
        if let Some(bundle) = self
            .discovery
            .as_ref()
            .and_then(NearbyDiscovery::take_completed_bundle)
        {
            // N-3: a late incoming-pairing completion must not overwrite an
            // already-configured peer (the victim's own concurrent action).
            // install_peer_bundle guards atomically under its lock as well.
            if setup.peer.is_none()
                && self
                    .install_peer_bundle(&bundle, WorkspaceRole::Follower)
                    .is_ok()
            {
                setup = self.inner.lock().map_err(|_| ())?.clone();
            }
            if let Some(discovery) = &self.discovery {
                nearby_machines =
                    discovery.snapshot(setup.peer.as_ref().map(|peer| peer.peer_id.as_str()));
            }
        }
        let nearby_pairing = self
            .discovery
            .as_ref()
            .and_then(NearbyDiscovery::pairing_snapshot);
        let host_id = setup
            .local
            .as_ref()
            .map_or(setup.draft_host_id.as_str(), |local| local.host_id.as_str());
        let displays = native_displays(parse_host_id(host_id).map_err(|_| ())?).map_err(|_| ())?;
        self.synchronize_workspace(runtime_state, &displays, &mut setup)?;
        if cfg!(debug_assertions) {
            let _ = self.synchronize_developer_diagnostics(&setup);
        }
        let developer_diagnostics =
            cfg!(debug_assertions).then(|| self.developer_diagnostics(&setup));
        let local = setup
            .local
            .as_ref()
            .map(|local| self.local_dto(local, &displays))
            .transpose()?;
        let peer = setup.peer.clone().map(peer_dto);
        let input_authority = snapshot_input_authority(runtime_state, &self.directory);
        let workspace_sync = workspace_sync_state(&setup);
        Ok(SetupSnapshot {
            platform: current_platform(),
            suggested_name: suggested_name(),
            address_options: private_addresses(),
            local,
            peer,
            displays,
            placement: setup.placement,
            display_layout: setup.display_layout,
            workspace_role: setup.workspace_role,
            workspace_revision: setup.workspace_revision,
            workspace_sync,
            configured: setup.configured,
            validated: setup.validated,
            runtime: runtime_state,
            runtime_fault,
            input_authority,
            runtime_log_path: setup.configured.then(|| {
                self.directory
                    .join(RUNTIME_LOG_FILE)
                    .to_string_lossy()
                    .into_owned()
            }),
            discovery_available: self.discovery.is_some(),
            nearby_machines,
            nearby_pairing,
            developer_diagnostics,
            setup_directory: setup
                .configured
                .then(|| self.directory.to_string_lossy().into_owned()),
            profile_path: setup.configured.then(|| {
                self.directory
                    .join(PROFILE_FILE)
                    .to_string_lossy()
                    .into_owned()
            }),
        })
    }

    fn poll_runtime_state(&self) -> Result<(RuntimeState, Option<RuntimeFault>), ()> {
        let mut runtime = self.runtime.lock().map_err(|_| ())?;
        let mut last_fault = self.last_runtime_fault.lock().map_err(|_| ())?;
        let runtime_state = match runtime.as_mut() {
            Some(child) => match child.try_wait().map_err(|_| ())? {
                None => RuntimeState::Running,
                Some(status) if status.success() => {
                    *runtime = None;
                    *last_fault = None;
                    RuntimeState::Stopped
                }
                Some(_) => {
                    *runtime = None;
                    *last_fault = Some(read_runtime_fault(&self.directory));
                    RuntimeState::Faulted
                }
            },
            None if runtime_lock_held(&self.directory) => RuntimeState::Running,
            None if last_fault.is_some() => RuntimeState::Faulted,
            None => RuntimeState::Stopped,
        };
        Ok((runtime_state, *last_fault))
    }

    fn local_dto(
        &self,
        local: &StoredLocal,
        displays: &[DisplayDto],
    ) -> Result<LocalIdentityDto, ()> {
        let certificate = fs::read(self.directory.join(CERT_FILE)).map_err(|_| ())?;
        let private_key = Zeroizing::new(fs::read(self.directory.join(KEY_FILE)).map_err(|_| ())?);
        let key_pair = KeyPair::try_from(private_key.as_slice()).map_err(|_| ())?;
        let bundle = PairingBundle {
            software_kvm_pairing: PAIRING_VERSION,
            host_id: local.host_id.clone(),
            peer_id: local.peer_id.clone(),
            display_name: local.display_name.clone(),
            platform: current_platform(),
            server_name: local.server_name.clone(),
            certificate_fingerprint: local.certificate_fingerprint.clone(),
            address: local.address.clone(),
            certificate_der: URL_SAFE_NO_PAD.encode(certificate),
            signing_public_key: URL_SAFE_NO_PAD.encode(key_pair.public_key_raw()),
            displays: displays.to_vec(),
        };
        let encoded = serde_json::to_vec(&bundle).map_err(|_| ())?;
        Ok(LocalIdentityDto {
            host_id: local.host_id.clone(),
            peer_id: local.peer_id.clone(),
            display_name: local.display_name.clone(),
            server_name: local.server_name.clone(),
            certificate_fingerprint: local.certificate_fingerprint.clone(),
            address: local.address.clone(),
            public_bundle: URL_SAFE_NO_PAD.encode(encoded),
        })
    }

    fn local_bundle(&self) -> Result<String, String> {
        let setup = self.inner.lock().map_err(|_| coarse_error())?.clone();
        let local = setup.local.as_ref().ok_or_else(coarse_error)?;
        let displays =
            native_displays(parse_host_id(&local.host_id)?).map_err(|_| coarse_error())?;
        self.local_dto(local, &displays)
            .map(|identity| identity.public_bundle)
            .map_err(|()| coarse_error())
    }

    fn validate_peer_bundle(&self, bundle: &str) -> Result<(PairingBundle, Vec<u8>), String> {
        let trimmed = bundle.trim();
        // F-23: bound the input text length before base64 allocation so an
        // oversized paste can't force a large transient allocation.
        if trimmed.len() > MAX_PEER_BUNDLE_INPUT_CHARS {
            return Err(coarse_error());
        }
        let raw = URL_SAFE_NO_PAD
            .decode(trimmed)
            .map_err(|_| coarse_error())?;
        if raw.len() > MAX_PEER_BUNDLE_BYTES {
            return Err(coarse_error());
        }
        let peer: PairingBundle = serde_json::from_slice(&raw).map_err(|_| coarse_error())?;
        validate_bundle(&peer)?;
        let certificate = URL_SAFE_NO_PAD
            .decode(&peer.certificate_der)
            .map_err(|_| coarse_error())?;
        let setup = self.inner.lock().map_err(|_| coarse_error())?;
        let local = setup.local.as_ref().ok_or_else(coarse_error)?;
        if peer.host_id == local.host_id
            || peer.peer_id == local.peer_id
            || peer.platform == current_platform()
        {
            return Err(coarse_error());
        }
        Ok((peer, certificate))
    }

    fn install_peer_bundle(&self, bundle: &str, role: WorkspaceRole) -> Result<(), String> {
        let (peer, certificate) = self.validate_peer_bundle(bundle)?;
        secure_write(&self.directory.join(TRUST_FILE), &certificate, false)
            .map_err(|()| coarse_error())?;
        let mut setup = self.inner.lock().map_err(|_| coarse_error())?;
        // N-3: never overwrite an already-configured peer. The command handlers
        // pre-check this for UX, but the snapshot-driven incoming-completion
        // path does not; guard atomically under the lock so a late/async
        // completion cannot silently discard a prior trust decision.
        if setup.peer.is_some() {
            return Err(coarse_error());
        }
        setup.peer = Some(peer);
        setup.display_layout.clear();
        setup.workspace_role = role;
        setup.workspace_revision = 0;
        setup.workspace_acknowledged_revision = 0;
        setup.configured = false;
        setup.validated = false;
        self.save(&setup).map_err(|()| coarse_error())
    }

    fn sign_workspace_layout(&self, setup: &StoredSetup) -> Result<(String, String), String> {
        let local = setup.local.as_ref().ok_or_else(coarse_error)?;
        let peer = setup.peer.as_ref().ok_or_else(coarse_error)?;
        let workspace = SignedWorkspaceLayout {
            schema_version: 1,
            revision: setup.workspace_revision,
            layout: canonical_layout(&setup.display_layout),
        };
        let encoded = serde_json::to_vec(&workspace).map_err(|_| coarse_error())?;
        let payload = URL_SAFE_NO_PAD.encode(encoded);
        let message = workspace_signature_message(
            &local.peer_id,
            &peer.peer_id,
            setup.workspace_revision,
            &payload,
        );
        let private_key = Zeroizing::new(
            fs::read(self.directory.join(KEY_FILE)).map_err(|_| coarse_error())?,
        );
        let key_pair = KeyPair::try_from(private_key.as_slice()).map_err(|_| coarse_error())?;
        let signature = key_pair.sign(&message).map_err(|_| coarse_error())?;
        Ok((payload, URL_SAFE_NO_PAD.encode(signature)))
    }

    fn sign_workspace_ack(&self, setup: &StoredSetup) -> Result<String, String> {
        let local = setup.local.as_ref().ok_or_else(coarse_error)?;
        let peer = setup.peer.as_ref().ok_or_else(coarse_error)?;
        let message = workspace_ack_signature_message(
            &local.peer_id,
            &peer.peer_id,
            setup.workspace_revision,
        );
        let private_key = Zeroizing::new(
            fs::read(self.directory.join(KEY_FILE)).map_err(|_| coarse_error())?,
        );
        let key_pair = KeyPair::try_from(private_key.as_slice()).map_err(|_| coarse_error())?;
        let signature = key_pair.sign(&message).map_err(|_| coarse_error())?;
        Ok(URL_SAFE_NO_PAD.encode(signature))
    }

    fn synchronize_workspace(
        &self,
        runtime_state: RuntimeState,
        displays: &[DisplayDto],
        setup: &mut StoredSetup,
    ) -> Result<(), ()> {
        if let Some(acknowledgement) = self
            .discovery
            .as_ref()
            .and_then(NearbyDiscovery::take_workspace_ack)
        {
            self.apply_workspace_ack(acknowledgement, setup)?;
        }
        if let Some(update) = self
            .discovery
            .as_ref()
            .and_then(NearbyDiscovery::take_workspace_layout)
        {
            if Self::verify_incoming_workspace(setup, &update).is_ok() {
                *self.pending_workspace.lock().map_err(|_| ())? = Some(update);
            }
        }
        if self.pending_workspace.lock().map_err(|_| ())?.is_some()
            && matches!(runtime_state, RuntimeState::Running)
        {
            let _ = secure_write(&self.directory.join(CONTROL_FILE), b"stop\n", true);
        } else if let Some(update) = self.pending_workspace.lock().map_err(|_| ())?.take() {
            let _ = self.apply_workspace_layout(update, displays);
            *setup = self.inner.lock().map_err(|_| ())?.clone();
        }
        if setup.workspace_role == WorkspaceRole::Leader
            && setup.configured
            && setup.workspace_revision > 0
        {
            if let (Some(discovery), Some(peer), Ok((payload, signature))) = (
                self.discovery.as_ref(),
                setup.peer.as_ref(),
                self.sign_workspace_layout(setup),
            ) {
                let _ = discovery.publish_workspace_layout(
                    &peer.peer_id,
                    setup.workspace_revision,
                    &payload,
                    &signature,
                );
            }
        }
        if setup.workspace_role == WorkspaceRole::Follower
            && setup.configured
            && setup.workspace_revision > 0
        {
            if let (Some(discovery), Some(peer), Ok(signature)) = (
                self.discovery.as_ref(),
                setup.peer.as_ref(),
                self.sign_workspace_ack(setup),
            ) {
                let _ = discovery.publish_workspace_ack(
                    &peer.peer_id,
                    setup.workspace_revision,
                    &signature,
                );
            }
        }
        Ok(())
    }

    fn apply_workspace_ack(
        &self,
        acknowledgement: IncomingWorkspaceAcknowledgement,
        setup: &mut StoredSetup,
    ) -> Result<(), ()> {
        let peer = setup.peer.as_ref().ok_or(())?;
        let local = setup.local.as_ref().ok_or(())?;
        if setup.workspace_role != WorkspaceRole::Leader
            || acknowledgement.from_peer_id != peer.peer_id
            || acknowledgement.revision != setup.workspace_revision
            || acknowledgement.revision == 0
        {
            return Ok(());
        }
        if verify_workspace_ack_signature(
            &peer.signing_public_key,
            &acknowledgement.signature,
            &peer.peer_id,
            &local.peer_id,
            acknowledgement.revision,
        )
        .is_err()
        {
            return Ok(());
        }
        if setup.workspace_acknowledged_revision != acknowledgement.revision {
            let mut current = self.inner.lock().map_err(|_| ())?;
            if current.workspace_role != WorkspaceRole::Leader
                || current.workspace_revision != acknowledgement.revision
            {
                return Ok(());
            }
            current.workspace_acknowledged_revision = acknowledgement.revision;
            self.save(&current)?;
            *setup = current.clone();
        }
        Ok(())
    }

    fn verify_incoming_workspace(
        setup: &StoredSetup,
        update: &IncomingWorkspaceLayout,
    ) -> Result<(), String> {
        let peer = setup.peer.as_ref().ok_or_else(coarse_error)?;
        let local = setup.local.as_ref().ok_or_else(coarse_error)?;
        if setup.workspace_role != WorkspaceRole::Follower
            || update.from_peer_id != peer.peer_id
            || update.revision <= setup.workspace_revision
        {
            return Err(coarse_error());
        }
        verify_workspace_signature(
            &peer.signing_public_key,
            &update.signature,
            &peer.peer_id,
            &local.peer_id,
            update.revision,
            &update.payload,
        )
    }

    fn apply_workspace_layout(
        &self,
        update: IncomingWorkspaceLayout,
        local_displays: &[DisplayDto],
    ) -> Result<(), String> {
        let mut setup = self.inner.lock().map_err(|_| coarse_error())?;
        Self::verify_incoming_workspace(&setup, &update)?;
        let peer = setup.peer.as_ref().ok_or_else(coarse_error)?;
        let encoded = URL_SAFE_NO_PAD
            .decode(&update.payload)
            .map_err(|_| coarse_error())?;
        if encoded.len() > 16 * 1024 {
            return Err(coarse_error());
        }
        let workspace: SignedWorkspaceLayout =
            serde_json::from_slice(&encoded).map_err(|_| coarse_error())?;
        if workspace.schema_version != 1 || workspace.revision != update.revision {
            return Err(coarse_error());
        }
        validate_display_layout(&workspace.layout, local_displays, &peer.displays)?;
        let mut candidate = setup.clone();
        candidate.display_layout = canonical_layout(&workspace.layout);
        candidate.workspace_revision = workspace.revision;
        candidate.placement = placement_from_layout(
            &candidate.display_layout,
            local_displays,
            &peer.displays,
        )?;
        write_setup_configuration(self, &mut candidate)?;
        *setup = candidate;
        Ok(())
    }

    fn developer_diagnostics(&self, setup: &StoredSetup) -> DeveloperDiagnosticsDto {
        let configured_listener = setup.local.as_ref().map(|local| local.address.clone());
        let configured_peer = setup.peer.as_ref().map(|peer| peer.address.clone());
        let observed_peer = setup.peer.as_ref().and_then(|peer| {
            self.discovery
                .as_ref()?
                .observed_runtime_address(&peer.peer_id)
                .map(|address| address.to_string())
        });
        let route_target = observed_peer
            .as_deref()
            .or(configured_peer.as_deref())
            .and_then(|address| address.parse::<SocketAddr>().ok());
        let routed_listener = route_target
            .and_then(routed_local_address)
            .map(|address| address.to_string());
        let lan_binding = match (
            configured_listener.as_deref(),
            configured_peer.as_deref(),
            observed_peer.as_deref(),
            routed_listener.as_deref(),
        ) {
            (None, _, _, _) | (_, None, _, _) => LanBindingState::NotConfigured,
            (_, _, None, _) => LanBindingState::WaitingForPeer,
            (Some(listener), Some(peer), Some(observed), Some(routed))
                if listener == routed && peer == observed =>
            {
                LanBindingState::Healthy
            }
            _ => LanBindingState::Mismatch,
        };
        DeveloperDiagnosticsDto {
            lan_binding,
            configured_listener,
            routed_listener,
            configured_peer,
            observed_peer,
            recent_events: read_developer_events(&self.directory.join(RUNTIME_LOG_FILE)),
            peer_recent_events: self
                .diagnostic_relay
                .lock()
                .map_or_else(|_| Vec::new(), |relay| relay.peer_events.clone()),
        }
    }

    fn synchronize_developer_diagnostics(&self, setup: &StoredSetup) -> Result<(), ()> {
        let Some(discovery) = self.discovery.as_ref() else {
            return Ok(());
        };
        match setup.workspace_role {
            WorkspaceRole::Follower => self.publish_developer_diagnostics(setup, discovery),
            WorkspaceRole::Leader => self.receive_developer_diagnostics(setup, discovery),
            WorkspaceRole::Unassigned => {
                let mut relay = self.diagnostic_relay.lock().map_err(|_| ())?;
                relay.peer_stream_id = None;
                relay.peer_sequence = 0;
                relay.peer_events.clear();
                Ok(())
            }
        }
    }

    fn publish_developer_diagnostics(
        &self,
        setup: &StoredSetup,
        discovery: &NearbyDiscovery,
    ) -> Result<(), ()> {
        let local = setup.local.as_ref().ok_or(())?;
        let peer = setup.peer.as_ref().ok_or(())?;
        let events = relayed_developer_events(&self.directory.join(RUNTIME_LOG_FILE));
        let mut relay = self.diagnostic_relay.lock().map_err(|_| ())?;
        if relay.last_local_events == events {
            return Ok(());
        }
        let sequence = relay.next_local_sequence;
        let encoded = serde_json::to_vec(&events).map_err(|_| ())?;
        let payload = URL_SAFE_NO_PAD.encode(encoded);
        let message = diagnostic_signature_message(
            &local.peer_id,
            &peer.peer_id,
            &relay.local_stream_id,
            sequence,
            &payload,
        );
        let private_key = Zeroizing::new(fs::read(self.directory.join(KEY_FILE)).map_err(|_| ())?);
        let key_pair = KeyPair::try_from(private_key.as_slice()).map_err(|_| ())?;
        let signature = URL_SAFE_NO_PAD.encode(key_pair.sign(&message).map_err(|_| ())?);
        discovery.publish_diagnostic_batch(
            &peer.peer_id,
            &relay.local_stream_id,
            sequence,
            &payload,
            &signature,
        )?;
        relay.last_local_events = events;
        relay.next_local_sequence = sequence.checked_add(1).ok_or(())?;
        Ok(())
    }

    fn receive_developer_diagnostics(
        &self,
        setup: &StoredSetup,
        discovery: &NearbyDiscovery,
    ) -> Result<(), ()> {
        let Some(batch) = discovery.take_diagnostic_batch() else {
            return Ok(());
        };
        let local = setup.local.as_ref().ok_or(())?;
        let peer = setup.peer.as_ref().ok_or(())?;
        if batch.from_peer_id != peer.peer_id {
            return Ok(());
        }
        let message = diagnostic_signature_message(
            &batch.from_peer_id,
            &local.peer_id,
            &batch.stream_id,
            batch.first_sequence,
            &batch.payload,
        );
        if verify_peer_signature(&peer.signing_public_key, &batch.signature, &message).is_err() {
            return Ok(());
        }
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(&batch.payload) else {
            return Ok(());
        };
        let Ok(events) = serde_json::from_slice::<Vec<String>>(&decoded) else {
            return Ok(());
        };
        if !valid_relayed_developer_events(&events) {
            return Ok(());
        }
        let mut relay = self.diagnostic_relay.lock().map_err(|_| ())?;
        if relay.peer_stream_id.as_deref() == Some(batch.stream_id.as_str())
            && batch.first_sequence <= relay.peer_sequence
        {
            return Ok(());
        }
        relay.peer_stream_id = Some(batch.stream_id);
        relay.peer_sequence = batch.first_sequence;
        relay.peer_events = events;
        Ok(())
    }
}

fn reset_legacy_credentials(
    directory: &Path,
    setup: &mut StoredSetup,
) -> Result<bool, std::io::Error> {
    if setup
        .local
        .as_ref()
        .is_none_or(|local| local.credential_version == CREDENTIAL_VERSION)
    {
        return Ok(false);
    }
    let backup_path = directory.join(LEGACY_STATE_BACKUP_FILE);
    if !backup_path.exists() {
        let backup = serde_json::to_vec_pretty(setup)
            .map_err(|_| std::io::Error::other("credential backup failed"))?;
        secure_write(&backup_path, &backup, true)
            .map_err(|()| std::io::Error::other("credential backup failed"))?;
    }
    setup.draft_host_id = Uuid::new_v4().to_string();
    setup.draft_peer_id = Uuid::new_v4().to_string();
    setup.local = None;
    setup.peer = None;
    setup.display_layout.clear();
    setup.workspace_role = WorkspaceRole::Unassigned;
    setup.workspace_revision = 0;
    setup.workspace_acknowledged_revision = 0;
    setup.configured = false;
    setup.validated = false;
    Ok(true)
}

#[cfg(windows)]
fn migrate_legacy_windows_setup(root: &Path, directory: &Path) -> Result<(), std::io::Error> {
    let legacy_state = root.join(STATE_FILE);
    let files = [
        (CONFIG_FILE, true),
        (CERT_FILE, false),
        (KEY_FILE, true),
        (TRUST_FILE, false),
        (PROFILE_FILE, true),
        (RUNTIME_LOG_FILE, true),
        (STATE_FILE, true),
    ];

    if legacy_state.is_file() && !directory.join(STATE_FILE).is_file() {
        // State is copied last so an interrupted migration is retried rather
        // than treating a partial destination as authoritative.
        for (name, private) in files {
            let source = root.join(name);
            if !source.is_file() {
                continue;
            }
            let mut contents = fs::read(&source)?;
            if name == PROFILE_FILE {
                contents = rewrite_windows_profile_paths(&contents, root, directory)?;
            }
            secure_write(&directory.join(name), &contents, private)
                .map_err(|()| std::io::Error::other("setup migration failed"))?;
        }
    }

    let profile_path = directory.join(PROFILE_FILE);
    if profile_path.is_file() {
        let profile = fs::read(&profile_path)?;
        let rewritten = rewrite_windows_profile_paths(&profile, root, directory)?;
        if rewritten != profile {
            secure_write(&profile_path, &rewritten, true)
                .map_err(|()| std::io::Error::other("setup migration failed"))?;
        }
    }

    if directory.join(STATE_FILE).is_file() {
        for (name, _) in files {
            let source = root.join(name);
            if source.is_file() {
                fs::remove_file(source)?;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn rewrite_windows_profile_paths(
    contents: &[u8],
    root: &Path,
    directory: &Path,
) -> Result<Vec<u8>, std::io::Error> {
    let source = std::str::from_utf8(contents)
        .map_err(|_| std::io::Error::other("setup migration failed"))?;
    let mut rewritten = source.to_owned();
    for name in [CONFIG_FILE, CERT_FILE, KEY_FILE, TRUST_FILE] {
        rewritten = rewritten.replace(
            root.join(name).to_string_lossy().as_ref(),
            directory.join(name).to_string_lossy().as_ref(),
        );
    }
    Ok(rewritten.into_bytes())
}

#[cfg(windows)]
fn restore_windows_app_data_acl(path: &Path) -> Result<(), std::io::Error> {
    run_icacls(path, &["/reset"])
}

#[tauri::command]
pub(crate) fn setup_status(service: State<'_, SetupService>) -> Result<SetupSnapshot, String> {
    service.snapshot().map_err(|()| coarse_error())
}

/// Pulls one diagnostics report over the separate §31 channel — a TCP
/// connection on `DIAGNOSTICS_PORT` distinct from the active KVM switch on
/// `KVM_PORT`. `host` is the reporting host's LAN IP (local or remote peer).
///
/// Returns `Ok(None)` when the host is unreachable or slow so the dashboard can
/// mark it offline instead of surfacing a hard error on every poll. A malformed
/// `host` is the only hard error.
#[tauri::command]
pub(crate) fn fetch_diagnostics(
    host: String,
    port: Option<u16>,
) -> Result<Option<kvm_network::DiagnosticsReport>, String> {
    let ip: IpAddr = host.parse().map_err(|_| coarse_error())?;
    let port = port.unwrap_or(DIAGNOSTICS_PORT);
    let addr = SocketAddr::new(ip, port);
    let report = kvm_network::fetch_report(addr, std::time::Duration::from_secs(1));
    Ok(report.ok())
}

#[tauri::command]
pub(crate) fn create_local_identity(
    display_name: String,
    address: String,
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    if display_name.trim().is_empty()
        || display_name.len() > 128
        || display_name.chars().any(char::is_control)
    {
        return Err(coarse_error());
    }
    let ip: IpAddr = address.parse().map_err(|_| coarse_error())?;
    if !is_private_ip(ip) {
        return Err(coarse_error());
    }
    let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
    if let Some(local) = setup.local.as_mut() {
        let next_name = display_name.trim();
        let next_address = SocketAddr::new(ip, KVM_PORT).to_string();
        if local.display_name != next_name || local.address != next_address {
            next_name.clone_into(&mut local.display_name);
            local.address = next_address;
            setup.configured = false;
            setup.validated = false;
        }
    } else {
        let server_name = format!("peer-{}.kvm.test", setup.draft_peer_id);
        let key = KeyPair::generate().map_err(|_| coarse_error())?;
        let mut parameters =
            CertificateParams::new(vec![server_name.clone()]).map_err(|_| coarse_error())?;
        parameters.is_ca = IsCa::NoCa;
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = parameters.self_signed(&key).map_err(|_| coarse_error())?;
        let certificate_der = certificate.der().to_vec();
        let fingerprint = hex::encode(Sha256::digest(&certificate_der));
        secure_write(&service.directory.join(CERT_FILE), &certificate_der, false)
            .map_err(|()| coarse_error())?;
        secure_write(
            &service.directory.join(KEY_FILE),
            &key.serialize_der(),
            true,
        )
        .map_err(|()| coarse_error())?;
        setup.local = Some(StoredLocal {
            credential_version: CREDENTIAL_VERSION,
            host_id: setup.draft_host_id.clone(),
            peer_id: setup.draft_peer_id.clone(),
            display_name: display_name.trim().to_owned(),
            server_name,
            certificate_fingerprint: fingerprint,
            address: SocketAddr::new(ip, KVM_PORT).to_string(),
        });
        setup.validated = false;
    }
    service.save(&setup).map_err(|()| coarse_error())?;
    drop(setup);
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn import_peer_bundle(
    bundle: String,
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    service.install_peer_bundle(&bundle, WorkspaceRole::Unassigned)?;
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn request_nearby_pairing(
    peer_id: String,
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    {
        let setup = service.inner.lock().map_err(|_| coarse_error())?;
        if setup.local.is_none() || setup.peer.is_some() {
            return Err(coarse_error());
        }
    }
    let bundle = service.local_bundle()?;
    service
        .discovery
        .as_ref()
        .ok_or_else(coarse_error)?
        .request_pairing(&peer_id, &bundle)
        .map_err(|()| coarse_error())?;
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn accept_nearby_pairing(
    request_id: String,
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    {
        let setup = service.inner.lock().map_err(|_| coarse_error())?;
        if setup.local.is_none() || setup.peer.is_some() {
            return Err(coarse_error());
        }
    }
    let discovery = service.discovery.as_ref().ok_or_else(coarse_error)?;
    let remote_bundle = discovery
        .incoming_pairing_bundle(&request_id)
        .map_err(|()| coarse_error())?;
    service.validate_peer_bundle(&remote_bundle)?;
    let bundle = service.local_bundle()?;
    discovery
        .accept_pairing(&request_id, &bundle)
        .map_err(|()| coarse_error())?;
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn confirm_nearby_pairing(
    request_id: String,
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    {
        let setup = service.inner.lock().map_err(|_| coarse_error())?;
        if setup.local.is_none() || setup.peer.is_some() {
            return Err(coarse_error());
        }
    }
    let discovery = service.discovery.as_ref().ok_or_else(coarse_error)?;
    let bundle = discovery
        .accepted_pairing_bundle(&request_id)
        .map_err(|()| coarse_error())?;
    service.validate_peer_bundle(&bundle)?;
    discovery
        .confirm_pairing(&request_id)
        .map_err(|()| coarse_error())?;
    service.install_peer_bundle(&bundle, WorkspaceRole::Leader)?;
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn decline_nearby_pairing(
    request_id: String,
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    service
        .discovery
        .as_ref()
        .ok_or_else(coarse_error)?
        .decline_pairing(&request_id)
        .map_err(|()| coarse_error())?;
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn forget_paired_computer(
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
    if setup.local.is_none() || setup.peer.is_none() {
        return Err(coarse_error());
    }
    setup.peer = None;
    setup.display_layout.clear();
    setup.workspace_role = WorkspaceRole::Unassigned;
    setup.workspace_revision = 0;
    setup.workspace_acknowledged_revision = 0;
    setup.configured = false;
    setup.validated = false;
    service.save(&setup).map_err(|()| coarse_error())?;
    drop(setup);

    // The local private identity remains intact. Only peer-derived public
    // trust and runtime configuration are discarded and can be regenerated.
    for name in [TRUST_FILE, CONFIG_FILE, PROFILE_FILE, RUNTIME_STATUS_FILE] {
        match fs::remove_file(service.directory.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(coarse_error()),
        }
    }
    if let Some(discovery) = &service.discovery {
        discovery.clear_pairing();
    }
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn finalize_setup(
    placement: Placement,
    layout: Vec<DisplayLayoutDto>,
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
    if setup.workspace_role == WorkspaceRole::Follower {
        return Err("The paired computer controls this display map. Change it there and this computer will follow automatically.".to_owned());
    }
    let canonical = canonical_layout(&layout);
    let changed = canonical != canonical_layout(&setup.display_layout);
    let mut candidate = setup.clone();
    candidate.placement = placement;
    candidate.display_layout = canonical;
    if candidate.workspace_role == WorkspaceRole::Leader && changed {
        candidate.workspace_revision = candidate
            .workspace_revision
            .checked_add(1)
            .ok_or_else(coarse_error)?;
        candidate.workspace_acknowledged_revision = 0;
    }
    write_setup_configuration(&service, &mut candidate)?;
    *setup = candidate;
    drop(setup);
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn repair_lan_binding(
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
    write_setup_configuration(&service, &mut setup)?;
    drop(setup);
    kvm_runtime::prepare(&service.directory.join(PROFILE_FILE))
        .map_err(|error| format!("runtime validation failed safely: {error}"))?;
    let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
    setup.validated = true;
    service.save(&setup).map_err(|()| coarse_error())?;
    drop(setup);
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn validate_setup(service: State<'_, SetupService>) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    kvm_runtime::prepare(&service.directory.join(PROFILE_FILE))
        .map_err(|error| format!("runtime validation failed safely: {error}"))?;
    let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
    setup.validated = true;
    service.save(&setup).map_err(|()| coarse_error())?;
    drop(setup);
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn start_runtime(service: State<'_, SetupService>) -> Result<SetupSnapshot, String> {
    let mut active = service.runtime.lock().map_err(|_| coarse_error())?;
    if active.is_some() || runtime_lock_held(&service.directory) {
        return Err(coarse_error());
    }
    {
        let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
        if !setup.validated {
            return Err(coarse_error());
        }
        if !workspace_is_synchronized(&setup) {
            return Err("The paired computer has not confirmed this display map yet. Keep both setup consoles open and wait for display-map sync.".to_owned());
        }
        // Re-enumerate displays on every start. Docking, undocking, or moving
        // a secondary monitor must not leave the cross-host edge attached to
        // a stale virtual-desktop boundary.
        write_setup_configuration(&service, &mut setup)?;
    }
    kvm_runtime::prepare(&service.directory.join(PROFILE_FILE))
        .map_err(|error| format!("runtime validation failed safely: {error}"))?;
    {
        let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
        setup.validated = true;
        service.save(&setup).map_err(|()| coarse_error())?;
    }
    let binary = runtime_binary().ok_or_else(coarse_error)?;
    let control = service.directory.join(CONTROL_FILE);
    secure_write(&control, b"run\n", true).map_err(|()| coarse_error())?;
    match fs::remove_file(service.directory.join(RUNTIME_STATUS_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(coarse_error()),
    }
    let log_path = service.directory.join(RUNTIME_LOG_FILE);
    secure_write(&log_path, b"", true).map_err(|()| coarse_error())?;
    let stdout_log = fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .map_err(|_| coarse_error())?;
    let stderr_log = stdout_log.try_clone().map_err(|_| coarse_error())?;
    *service
        .last_runtime_fault
        .lock()
        .map_err(|_| coarse_error())? = None;
    let mut command = Command::new(binary);
    command
        .arg("run-managed")
        .arg(service.directory.join(PROFILE_FILE))
        .arg(control)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log));
    if cfg!(debug_assertions) {
        command.env("SOFTWARE_KVM_DEV_LOG", "1");
    }
    let child = command.spawn().map_err(|_| coarse_error())?;
    *active = Some(child);
    drop(active);
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn stop_runtime(service: State<'_, SetupService>) -> Result<SetupSnapshot, String> {
    let mut active = service.runtime.lock().map_err(|_| coarse_error())?;
    secure_write(&service.directory.join(CONTROL_FILE), b"stop\n", true)
        .map_err(|()| coarse_error())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    if let Some(child) = active.as_mut() {
        loop {
            if child.try_wait().map_err(|_| coarse_error())?.is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(coarse_error());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    } else {
        if !runtime_lock_held(&service.directory) {
            return Err(coarse_error());
        }
        while runtime_lock_held(&service.directory) {
            if std::time::Instant::now() >= deadline {
                return Err(coarse_error());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    *active = None;
    *service
        .last_runtime_fault
        .lock()
        .map_err(|_| coarse_error())? = None;
    drop(active);
    service.snapshot().map_err(|()| coarse_error())
}

fn validate_bundle(peer: &PairingBundle) -> Result<(), String> {
    if peer.software_kvm_pairing != PAIRING_VERSION
        || peer.display_name.trim().is_empty()
        || peer.display_name.len() > 128
        || peer.display_name.chars().any(char::is_control)
        || peer.server_name.trim().is_empty()
        || peer.server_name.len() > 128
        || peer.server_name.chars().any(char::is_control)
        || peer.certificate_fingerprint.len() != 64
        || !peer
            .certificate_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || peer.displays.is_empty()
        || peer.displays.len() > 32
        || peer.displays.iter().any(|display| {
            display.id.parse::<DisplayId>().is_err()
                || display.name.trim().is_empty()
                || display.name.len() > 128
                || display.name.chars().any(char::is_control)
                || !display.width.is_finite()
                || !display.height.is_finite()
                || !display.scale_factor.is_finite()
                || display.width <= 0.0
                || display.height <= 0.0
                || display.scale_factor <= 0.0
                || display.native_bounds.is_some_and(|bounds| {
                    !bounds.x.is_finite()
                        || !bounds.y.is_finite()
                        || !bounds.width.is_finite()
                        || !bounds.height.is_finite()
                        || bounds.width <= 0.0
                        || bounds.height <= 0.0
                })
        })
    {
        return Err(coarse_error());
    }
    let mut display_ids = HashSet::with_capacity(peer.displays.len());
    if peer
        .displays
        .iter()
        .any(|display| !display_ids.insert(display.id.as_str()))
    {
        return Err(coarse_error());
    }
    parse_host_id(&peer.host_id)?;
    parse_peer_id(&peer.peer_id)?;
    let address: SocketAddr = peer.address.parse().map_err(|_| coarse_error())?;
    if address.port() != KVM_PORT || !is_private_ip(address.ip()) {
        return Err(coarse_error());
    }
    let certificate = URL_SAFE_NO_PAD
        .decode(&peer.certificate_der)
        .map_err(|_| coarse_error())?;
    let signing_public_key = URL_SAFE_NO_PAD
        .decode(&peer.signing_public_key)
        .map_err(|_| coarse_error())?;
    if certificate.is_empty()
        || certificate.len() > kvm_runtime::MAX_CERTIFICATE_DER_BYTES
        || hex::encode(Sha256::digest(&certificate)) != peer.certificate_fingerprint
        || signing_public_key.len() != 65
        || signing_public_key.first() != Some(&4)
    {
        return Err(coarse_error());
    }
    Ok(())
}

fn write_setup_configuration(
    service: &SetupService,
    setup: &mut StoredSetup,
) -> Result<(), String> {
    refresh_lan_addresses(service, setup)?;
    let local = setup.local.clone().ok_or_else(coarse_error)?;
    let peer = setup.peer.clone().ok_or_else(coarse_error)?;
    let local_displays =
        native_displays(parse_host_id(&local.host_id)?).map_err(|_| coarse_error())?;
    if local_displays.is_empty() || peer.displays.is_empty() {
        return Err(coarse_error());
    }
    let config = build_config(
        &peer,
        &local_displays,
        &setup.placement,
        &setup.display_layout,
    )?;
    let config_source = encode_config(&config).map_err(|_| coarse_error())?;
    secure_write(
        &service.directory.join(CONFIG_FILE),
        config_source.as_bytes(),
        true,
    )
    .map_err(|()| coarse_error())?;
    let profile = build_profile(&service.directory, &local, &peer);
    secure_write(
        &service.directory.join(PROFILE_FILE),
        profile.as_bytes(),
        true,
    )
    .map_err(|()| coarse_error())?;
    setup.configured = true;
    setup.validated = false;
    service.save(setup).map_err(|()| coarse_error())
}

fn refresh_lan_addresses(service: &SetupService, setup: &mut StoredSetup) -> Result<(), String> {
    let peer = setup.peer.as_mut().ok_or_else(coarse_error)?;
    if let Some(observed) = service
        .discovery
        .as_ref()
        .and_then(|discovery| discovery.observed_runtime_address(&peer.peer_id))
    {
        peer.address = observed.to_string();
    }
    let peer_address = peer
        .address
        .parse::<SocketAddr>()
        .map_err(|_| coarse_error())?;
    let local_address = routed_local_address(peer_address).ok_or_else(coarse_error)?;
    setup.local.as_mut().ok_or_else(coarse_error)?.address = local_address.to_string();
    Ok(())
}

fn build_config(
    peer: &PairingBundle,
    local_displays: &[DisplayDto],
    placement: &Placement,
    requested_layout: &[DisplayLayoutDto],
) -> Result<Config, String> {
    let remote_host = parse_host_id(&peer.host_id)?;
    let layout = if requested_layout.is_empty() {
        default_display_layout(local_displays, &peer.displays, placement)?
    } else {
        validate_display_layout(requested_layout, local_displays, &peer.displays)?;
        requested_layout.to_vec()
    };
    let placements = layout
        .iter()
        .map(|display| DisplayPlacement {
            display_id: display.display_id,
            x: display.x,
            y: display.y,
        })
        .collect();
    let (local_display, local_edge, remote_display, remote_edge) =
        selected_cross_host_edge(&layout, local_displays, &peer.displays)?;
    let mut links = vec![
        TopologyLink {
            from_display: local_display,
            from_edge: local_edge,
            to_display: remote_display,
            to_edge: remote_edge,
        },
        TopologyLink {
            from_display: remote_display,
            from_edge: remote_edge,
            to_display: local_display,
            to_edge: local_edge,
        },
    ];
    links.sort_by_key(|link| link.from_display);
    let address: SocketAddr = peer.address.parse().map_err(|_| coarse_error())?;
    let config = Config {
        paired_hosts: vec![PairedHostConfig {
            host_id: remote_host,
            peer_id: parse_peer_id(&peer.peer_id)?,
            name: peer.display_name.clone(),
            platform: match peer.platform {
                PlatformDto::Macos => Platform::MacOS,
                PlatformDto::Windows => Platform::Windows,
            },
            identity_fingerprint: peer.certificate_fingerprint.clone(),
            last_address: Some(address),
        }],
        topology: TopologyConfig {
            displays: placements,
            links,
        },
        network: NetworkSettings {
            discovery_enabled: false,
            listen_port: KVM_PORT,
            ..NetworkSettings::default()
        },
        ..Config::default()
    };
    config.validate().map_err(|_| coarse_error())?;
    Ok(config)
}

fn default_display_layout(
    local_displays: &[DisplayDto],
    peer_displays: &[DisplayDto],
    placement: &Placement,
) -> Result<Vec<DisplayLayoutDto>, String> {
    let ordered_local = displays_left_to_right(local_displays);
    let ordered_peer = displays_left_to_right(peer_displays);
    let (first, second) = match placement {
        Placement::LocalLeft => (&ordered_local, &ordered_peer),
        Placement::LocalRight => (&ordered_peer, &ordered_local),
    };
    let mut x = 0.0;
    let mut layout = Vec::with_capacity(first.len() + second.len());
    for display in first.iter().chain(second) {
        layout.push(DisplayLayoutDto {
            display_id: display.id.parse().map_err(|_| coarse_error())?,
            x,
            y: 0.0,
        });
        x += display.width;
    }
    Ok(layout)
}

fn canonical_layout(layout: &[DisplayLayoutDto]) -> Vec<DisplayLayoutDto> {
    let mut canonical = layout.to_vec();
    canonical.sort_by_key(|display| display.display_id);
    canonical
}

fn workspace_signature_message(
    from_peer_id: &str,
    to_peer_id: &str,
    revision: u64,
    payload: &str,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        64 + from_peer_id.len() + to_peer_id.len() + payload.len(),
    );
    message.extend_from_slice(b"software-kvm-workspace-layout-v1\0");
    message.extend_from_slice(from_peer_id.as_bytes());
    message.push(0);
    message.extend_from_slice(to_peer_id.as_bytes());
    message.push(0);
    message.extend_from_slice(&revision.to_be_bytes());
    message.extend_from_slice(payload.as_bytes());
    message
}

fn workspace_ack_signature_message(
    from_peer_id: &str,
    to_peer_id: &str,
    revision: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(64 + from_peer_id.len() + to_peer_id.len());
    message.extend_from_slice(b"software-kvm-workspace-layout-ack-v1\0");
    message.extend_from_slice(from_peer_id.as_bytes());
    message.push(0);
    message.extend_from_slice(to_peer_id.as_bytes());
    message.push(0);
    message.extend_from_slice(&revision.to_be_bytes());
    message
}

fn diagnostic_signature_message(
    from_peer_id: &str,
    to_peer_id: &str,
    stream_id: &str,
    first_sequence: u64,
    payload: &str,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        96 + from_peer_id.len() + to_peer_id.len() + stream_id.len() + payload.len(),
    );
    message.extend_from_slice(b"software-kvm-redacted-diagnostics-v1\0");
    message.extend_from_slice(from_peer_id.as_bytes());
    message.push(0);
    message.extend_from_slice(to_peer_id.as_bytes());
    message.push(0);
    message.extend_from_slice(stream_id.as_bytes());
    message.push(0);
    message.extend_from_slice(&first_sequence.to_be_bytes());
    message.extend_from_slice(payload.as_bytes());
    message
}

fn verify_peer_signature(
    encoded_public_key: &str,
    encoded_signature: &str,
    message: &[u8],
) -> Result<(), ()> {
    let public_key = URL_SAFE_NO_PAD.decode(encoded_public_key).map_err(|_| ())?;
    let signature = URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|_| ())?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, &signature)
        .map_err(|_| ())
}

fn verify_workspace_signature(
    encoded_public_key: &str,
    encoded_signature: &str,
    from_peer_id: &str,
    to_peer_id: &str,
    revision: u64,
    payload: &str,
) -> Result<(), String> {
    let public_key = URL_SAFE_NO_PAD
        .decode(encoded_public_key)
        .map_err(|_| coarse_error())?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| coarse_error())?;
    let message = workspace_signature_message(
        from_peer_id,
        to_peer_id,
        revision,
        payload,
    );
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(&message, &signature)
        .map_err(|_| coarse_error())
}

fn relayed_developer_events(path: &Path) -> Vec<String> {
    let events = read_developer_events(path);
    let mut relayed = events
        .into_iter()
        .filter(|line| line.starts_with("[dev] "))
        .rev()
        .take(MAX_RELAYED_DIAGNOSTIC_LINES)
        .collect::<Vec<_>>();
    relayed.reverse();
    relayed
}

fn valid_relayed_developer_events(events: &[String]) -> bool {
    events.len() <= MAX_RELAYED_DIAGNOSTIC_LINES
        && events.iter().all(|line| {
            line.starts_with("[dev] ")
                && line.chars().count() <= MAX_RELAYED_DIAGNOSTIC_LINE_CHARS
                && !line.chars().any(char::is_control)
        })
}

fn verify_workspace_ack_signature(
    encoded_public_key: &str,
    encoded_signature: &str,
    from_peer_id: &str,
    to_peer_id: &str,
    revision: u64,
) -> Result<(), String> {
    let public_key = URL_SAFE_NO_PAD
        .decode(encoded_public_key)
        .map_err(|_| coarse_error())?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| coarse_error())?;
    let message = workspace_ack_signature_message(from_peer_id, to_peer_id, revision);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(&message, &signature)
        .map_err(|_| coarse_error())
}

fn workspace_is_synchronized(setup: &StoredSetup) -> bool {
    matches!(
        workspace_sync_state(setup),
        WorkspaceSyncState::Manual | WorkspaceSyncState::Confirmed
    )
}

fn workspace_sync_state(setup: &StoredSetup) -> WorkspaceSyncState {
    if !setup.configured {
        return WorkspaceSyncState::NotConfigured;
    }
    match setup.workspace_role {
        WorkspaceRole::Unassigned => WorkspaceSyncState::Manual,
        WorkspaceRole::Follower if setup.workspace_revision > 0 => WorkspaceSyncState::Confirmed,
        WorkspaceRole::Leader
            if setup.workspace_revision > 0
                && setup.workspace_acknowledged_revision == setup.workspace_revision =>
        {
            WorkspaceSyncState::Confirmed
        }
        WorkspaceRole::Leader | WorkspaceRole::Follower => WorkspaceSyncState::Waiting,
    }
}

fn placement_from_layout(
    layout: &[DisplayLayoutDto],
    local_displays: &[DisplayDto],
    peer_displays: &[DisplayDto],
) -> Result<Placement, String> {
    let positions = layout
        .iter()
        .map(|position| (position.display_id, position))
        .collect::<HashMap<_, _>>();
    let center = |displays: &[DisplayDto]| -> Result<f64, String> {
        let sum = displays.iter().try_fold(0.0, |sum, display| {
            let id = display.id.parse::<DisplayId>().map_err(|_| coarse_error())?;
            let position = positions.get(&id).ok_or_else(coarse_error)?;
            Ok::<_, String>(sum + position.x + display.width / 2.0)
        })?;
        let count = u32::try_from(displays.len()).map_err(|_| coarse_error())?;
        Ok(sum / f64::from(count))
    };
    Ok(if center(local_displays)? <= center(peer_displays)? {
        Placement::LocalLeft
    } else {
        Placement::LocalRight
    })
}

fn validate_display_layout(
    layout: &[DisplayLayoutDto],
    local_displays: &[DisplayDto],
    peer_displays: &[DisplayDto],
) -> Result<(), String> {
    if layout.len() != local_displays.len() + peer_displays.len()
        || layout.iter().any(|display| {
            display.display_id == DisplayId::from_bytes([0; 16])
                || !display.x.is_finite()
                || !display.y.is_finite()
                || display.x.abs() > 100_000.0
                || display.y.abs() > 100_000.0
        })
    {
        return Err(coarse_error());
    }
    let expected = local_displays
        .iter()
        .chain(peer_displays)
        .map(|display| display.id.parse::<DisplayId>().map_err(|_| coarse_error()))
        .collect::<Result<HashSet<_>, _>>()?;
    let actual = layout
        .iter()
        .map(|display| display.display_id)
        .collect::<HashSet<_>>();
    if actual.len() != layout.len() || actual != expected {
        return Err(coarse_error());
    }
    let dimensions = local_displays
        .iter()
        .chain(peer_displays)
        .map(|display| {
            Ok((
                display.id.parse::<DisplayId>().map_err(|_| coarse_error())?,
                (display.width, display.height),
            ))
        })
        .collect::<Result<HashMap<_, _>, String>>()?;
    for (index, first) in layout.iter().enumerate() {
        let (first_width, first_height) = dimensions
            .get(&first.display_id)
            .copied()
            .ok_or_else(coarse_error)?;
        for second in &layout[index + 1..] {
            let (second_width, second_height) = dimensions
                .get(&second.display_id)
                .copied()
                .ok_or_else(coarse_error)?;
            let horizontal_overlap = (first.x + first_width)
                .min(second.x + second_width)
                - first.x.max(second.x);
            let vertical_overlap = (first.y + first_height)
                .min(second.y + second_height)
                - first.y.max(second.y);
            if horizontal_overlap > 0.001 && vertical_overlap > 0.001 {
                return Err(coarse_error());
            }
        }
    }
    Ok(())
}

fn selected_cross_host_edge(
    layout: &[DisplayLayoutDto],
    local_displays: &[DisplayDto],
    peer_displays: &[DisplayDto],
) -> Result<(DisplayId, Edge, DisplayId, Edge), String> {
    let mut candidates = Vec::new();
    for local in local_displays {
        let local_id = local.id.parse::<DisplayId>().map_err(|_| coarse_error())?;
        let local_position = layout
            .iter()
            .find(|position| position.display_id == local_id)
            .ok_or_else(coarse_error)?;
        for remote in peer_displays {
            let remote_id = remote.id.parse::<DisplayId>().map_err(|_| coarse_error())?;
            let remote_position = layout
                .iter()
                .find(|position| position.display_id == remote_id)
                .ok_or_else(coarse_error)?;
            if let Some((local_edge, remote_edge, overlap)) =
                touching_edges(local_position, local, remote_position, remote)
            {
                candidates.push((overlap, local_id, local_edge, remote_id, remote_edge));
            }
        }
    }
    candidates.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.3.cmp(&right.3))
    });
    candidates
        .first()
        .map(|(_, local, local_edge, remote, remote_edge)| {
            (*local, *local_edge, *remote, *remote_edge)
        })
        .ok_or_else(coarse_error)
}

fn touching_edges(
    first_position: &DisplayLayoutDto,
    first: &DisplayDto,
    second_position: &DisplayLayoutDto,
    second: &DisplayDto,
) -> Option<(Edge, Edge, f64)> {
    const EPSILON: f64 = 0.001;
    let first_right = first_position.x + first.width;
    let first_bottom = first_position.y + first.height;
    let second_right = second_position.x + second.width;
    let second_bottom = second_position.y + second.height;
    let vertical_overlap =
        first_bottom.min(second_bottom) - first_position.y.max(second_position.y);
    let horizontal_overlap =
        first_right.min(second_right) - first_position.x.max(second_position.x);
    if vertical_overlap > EPSILON && (first_right - second_position.x).abs() <= EPSILON {
        Some((Edge::Right, Edge::Left, vertical_overlap))
    } else if vertical_overlap > EPSILON && (first_position.x - second_right).abs() <= EPSILON {
        Some((Edge::Left, Edge::Right, vertical_overlap))
    } else if horizontal_overlap > EPSILON && (first_bottom - second_position.y).abs() <= EPSILON {
        Some((Edge::Bottom, Edge::Top, horizontal_overlap))
    } else if horizontal_overlap > EPSILON && (first_position.y - second_bottom).abs() <= EPSILON {
        Some((Edge::Top, Edge::Bottom, horizontal_overlap))
    } else {
        None
    }
}

fn displays_left_to_right(displays: &[DisplayDto]) -> Vec<DisplayDto> {
    let mut ordered = displays.to_vec();
    if ordered
        .iter()
        .all(|display| display.native_bounds.is_some())
    {
        ordered.sort_by(|left, right| {
            let left_bounds = left.native_bounds.expect("bounds presence checked");
            let right_bounds = right.native_bounds.expect("bounds presence checked");
            left_bounds
                .x
                .total_cmp(&right_bounds.x)
                .then_with(|| left_bounds.y.total_cmp(&right_bounds.y))
                .then_with(|| right.primary.cmp(&left.primary))
                .then_with(|| left.id.cmp(&right.id))
        });
    } else {
        // Pairing bundles created before native bounds were included retain
        // their former one-display/primary-first behavior. A fresh pairing
        // upgrades both sides to exact multi-monitor ordering.
        ordered.sort_by_key(|display| !display.primary);
    }
    ordered
}

fn build_profile(directory: &Path, local: &StoredLocal, peer: &PairingBundle) -> String {
    format!(
        "version = 2\nenabled = true\nwhole_host_alpha = true\nkvm_config_path = {}\ntopology = \"selected_only\"\nrouting = \"selected_only\"\nlisten_addresses = [{}]\n\n[local]\nhost_id = \"{}\"\npeer_id = \"{}\"\ndisplay_name = {}\n\n[selected_peer]\nhost_id = \"{}\"\npeer_id = \"{}\"\nidentity_fingerprint = \"{}\"\nsocket_address = \"{}\"\nserver_name = {}\n\n[tls]\ncertificate = {}\nprivate_key = {}\npeer_trust = {}\n",
        quote(&directory.join(CONFIG_FILE).to_string_lossy()), quote(&local.address), local.host_id, local.peer_id,
        quote(&local.display_name), peer.host_id, peer.peer_id, peer.certificate_fingerprint, peer.address,
        quote(&peer.server_name), quote(&directory.join(CERT_FILE).to_string_lossy()),
        quote(&directory.join(KEY_FILE).to_string_lossy()), quote(&directory.join(TRUST_FILE).to_string_lossy()),
    )
}

fn quote(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}
fn parse_host_id(value: &str) -> Result<HostId, String> {
    value.parse().map_err(|_| coarse_error())
}
fn parse_peer_id(value: &str) -> Result<PeerId, String> {
    value.parse().map_err(|_| coarse_error())
}
fn peer_dto(peer: PairingBundle) -> PeerIdentityDto {
    PeerIdentityDto {
        host_id: peer.host_id,
        peer_id: peer.peer_id,
        display_name: peer.display_name,
        platform: peer.platform,
        server_name: peer.server_name,
        certificate_fingerprint: peer.certificate_fingerprint,
        address: peer.address,
        displays: peer.displays,
    }
}
fn coarse_error() -> String {
    "setup operation failed safely".to_owned()
}

fn read_runtime_fault(directory: &Path) -> RuntimeFault {
    let Ok(file) = fs::File::open(directory.join(RUNTIME_LOG_FILE)) else {
        return RuntimeFault::Unknown;
    };
    let mut message = String::new();
    if file
        .take(MAX_RUNTIME_LOG_READ)
        .read_to_string(&mut message)
        .is_err()
    {
        return RuntimeFault::Unknown;
    }
    if message.contains("native capture lifecycle failed") {
        RuntimeFault::NativeCapture
    } else if message.contains("authenticated transport service failed") {
        RuntimeFault::AuthenticatedTransport
    } else if message.contains("runtime service task failed") {
        RuntimeFault::RuntimeTask
    } else {
        RuntimeFault::Unknown
    }
}

fn snapshot_input_authority(runtime: RuntimeState, directory: &Path) -> InputAuthorityDto {
    if matches!(runtime, RuntimeState::Running) {
        read_input_authority(directory)
    } else {
        InputAuthorityDto {
            owner: InputOwnerState::Unavailable,
            link_ready: false,
            session_active: false,
        }
    }
}

fn read_input_authority(directory: &Path) -> InputAuthorityDto {
    let unavailable = InputAuthorityDto {
        owner: InputOwnerState::Unavailable,
        link_ready: false,
        session_active: false,
    };
    let Ok(file) = fs::File::open(directory.join(RUNTIME_STATUS_FILE)) else {
        return unavailable;
    };
    let mut source = String::new();
    if file.take(4 * 1024).read_to_string(&mut source).is_err() {
        return unavailable;
    }
    let Ok(status) = toml::from_str::<RuntimeStatusFile>(&source) else {
        return unavailable;
    };
    if status.schema_version != 1 {
        return unavailable;
    }

    let running = matches!(status.service, RuntimeStatusService::Running);
    let link_ready =
        running && status.session_active && matches!(status.routing, RuntimeStatusRouting::Enabled);
    let owner = match status.service {
        RuntimeStatusService::Starting
        | RuntimeStatusService::Stopping
        | RuntimeStatusService::Faulted => InputOwnerState::Local,
        RuntimeStatusService::Running => match status.input_owner {
            RuntimeStatusOwner::Peer if link_ready => InputOwnerState::Peer,
            RuntimeStatusOwner::Transitioning if status.session_active => {
                InputOwnerState::Transitioning
            }
            RuntimeStatusOwner::Local | RuntimeStatusOwner::Peer => InputOwnerState::Local,
            RuntimeStatusOwner::Transitioning => InputOwnerState::Unavailable,
        },
    };
    InputAuthorityDto {
        owner,
        link_ready,
        session_active: running && status.session_active,
    }
}

fn ensure_runtime_stopped(service: &SetupService) -> Result<(), String> {
    let mut runtime = service.runtime.lock().map_err(|_| coarse_error())?;
    if let Some(child) = runtime.as_mut() {
        if child.try_wait().map_err(|_| coarse_error())?.is_none() {
            return Err(coarse_error());
        }
        *runtime = None;
    }
    if runtime_lock_held(&service.directory) {
        return Err(coarse_error());
    }
    Ok(())
}

fn current_platform() -> PlatformDto {
    #[cfg(target_os = "macos")]
    {
        PlatformDto::Macos
    }
    #[cfg(windows)]
    {
        PlatformDto::Windows
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        PlatformDto::Macos
    }
}

const fn platform_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(windows)]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        "macos"
    }
}

fn suggested_name() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "This computer".to_owned())
}

fn private_addresses() -> Vec<String> {
    let mut addresses: Vec<_> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|interface| interface.ip())
        .filter(|ip| is_private_ip(*ip))
        .map(|ip| ip.to_string())
        .collect();
    addresses.sort();
    addresses.dedup();
    addresses
}

fn routed_local_address(peer: SocketAddr) -> Option<SocketAddr> {
    let bind_address: SocketAddr = match peer {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().ok()?,
        SocketAddr::V6(_) => "[::]:0".parse().ok()?,
    };
    let socket = UdpSocket::bind(bind_address).ok()?;
    socket.connect(peer).ok()?;
    let address = socket.local_addr().ok()?;
    is_private_ip(address.ip()).then(|| SocketAddr::new(address.ip(), KVM_PORT))
}

fn read_developer_events(path: &Path) -> Vec<String> {
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };
    let length = file.metadata().map_or(0, |metadata| metadata.len());
    let offset = length.saturating_sub(MAX_RUNTIME_LOG_READ);
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return Vec::new();
    }
    let mut contents = String::new();
    if file
        .take(MAX_RUNTIME_LOG_READ)
        .read_to_string(&mut contents)
        .is_err()
    {
        return Vec::new();
    }
    contents
        .lines()
        .rev()
        .take(40)
        .map(|line| {
            line.chars()
                .filter(|character| !character.is_control())
                .take(240)
                .collect::<String>()
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn private_broadcast_addresses() -> Vec<IpAddr> {
    let mut broadcasts: Vec<_> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(if_addrs::Interface::is_oper_up)
        .filter_map(|interface| match interface.addr {
            if_addrs::IfAddr::V4(address) if address.ip.is_private() => {
                let broadcast = address.broadcast.unwrap_or_else(|| {
                    let ip = u32::from(address.ip);
                    let netmask = u32::from(address.netmask);
                    std::net::Ipv4Addr::from(ip | !netmask)
                });
                Some(IpAddr::V4(broadcast))
            }
            _ => None,
        })
        .collect();
    broadcasts.sort_unstable();
    broadcasts.dedup();
    broadcasts.truncate(8);
    broadcasts
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.segments()[0] & 0xfe00 == 0xfc00,
    }
}

// On Windows and macOS the native backend is fallible; the unsupported build
// used for portable linting intentionally returns an empty inventory.
#[allow(clippy::unnecessary_wraps)]
fn native_displays(
    host: HostId,
) -> Result<Vec<DisplayDto>, Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "macos")]
    let displays = kvm_macos::MacDisplayBackend::new(host).enumerate_displays()?;
    #[cfg(windows)]
    let displays = kvm_windows::WindowsDisplayBackend::new(host).enumerate_displays()?;
    #[cfg(not(any(target_os = "macos", windows)))]
    let displays: Vec<Display> = {
        let _ = host;
        Vec::new()
    };
    Ok(displays.into_iter().map(display_dto).collect())
}

fn display_dto(display: Display) -> DisplayDto {
    DisplayDto {
        id: display.id.to_string(),
        name: display.name,
        width: display.logical_size.width,
        height: display.logical_size.height,
        scale_factor: display.scale_factor,
        primary: display.primary,
        native_bounds: Some(NativeBoundsDto {
            x: display.native_bounds.x,
            y: display.native_bounds.y,
            width: display.native_bounds.width,
            height: display.native_bounds.height,
        }),
    }
}

fn secure_write(path: &Path, contents: &[u8], private: bool) -> Result<(), ()> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(&temporary).map_err(|_| ())?;
    #[cfg(windows)]
    if private {
        secure_windows_acl(&temporary)?;
    }
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| ())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &temporary,
            fs::Permissions::from_mode(if private { 0o600 } else { 0o644 }),
        )
        .map_err(|_| ())?;
    }
    if fs::rename(&temporary, path).is_err() {
        fs::remove_file(path).map_err(|_| ())?;
        fs::rename(&temporary, path).map_err(|_| ())?;
    }
    Ok(())
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn secure_directory(path: &Path) -> Result<(), std::io::Error> {
    // Reset first so Windows' explicit default-token grants become inherited;
    // removing inheritance then leaves a clean DACL for the owner-only grant.
    run_icacls(path, &["/reset"])?;
    run_icacls(path, &["/inheritance:r"])?;
    let grant = format!(
        "{}:(OI)(CI)(F)",
        std::env::var("USERNAME")
            .map_err(|_| std::io::Error::other("directory protection identity unavailable"))?
    );
    run_icacls(path, &["/grant:r", &grant])
}

#[cfg(not(any(unix, windows)))]
fn secure_directory(path: &Path) -> Result<(), std::io::Error> {
    fs::metadata(path).and_then(|metadata| {
        metadata
            .is_dir()
            .then_some(())
            .ok_or_else(|| std::io::Error::other("setup path is not a directory"))
    })
}

#[cfg(windows)]
fn secure_windows_acl(path: &Path) -> Result<(), ()> {
    let grant = format!("{}:(F)", std::env::var("USERNAME").map_err(|_| ())?);
    run_icacls(path, &["/inheritance:r", "/grant:r", &grant]).map_err(|_| ())
}

#[cfg(windows)]
fn run_icacls(path: &Path, arguments: &[&str]) -> Result<(), std::io::Error> {
    let status = Command::new("icacls")
        .arg(path)
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| std::io::Error::other("Windows ACL update failed"))
}

fn runtime_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SOFTWARE_KVM_RUNTIME")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
    {
        return Some(path);
    }
    let executable = if cfg!(windows) {
        "kvm-runtime.exe"
    } else {
        "kvm-runtime"
    };
    let current = std::env::current_exe().ok()?;
    let sibling = current.parent()?.join(executable);
    if sibling.is_file() {
        return Some(sibling);
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../target/release")
        .join(executable);
    workspace.is_file().then_some(workspace)
}

fn runtime_lock_held(directory: &Path) -> bool {
    let path = directory.join(CONTROL_FILE).with_extension("lock");
    let Ok(file) = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
    else {
        return true;
    };
    if fs2::FileExt::try_lock_exclusive(&file).is_err() {
        return true;
    }
    let _ = fs2::FileExt::unlock(&file);
    false
}

#[cfg(test)]
mod tests {
    use super::{
        build_config, diagnostic_signature_message, read_input_authority, validate_bundle,
        verify_peer_signature, verify_workspace_ack_signature, verify_workspace_signature,
        workspace_ack_signature_message, workspace_signature_message, DisplayDto,
        DisplayLayoutDto, InputOwnerState, NativeBoundsDto, PairingBundle, Placement, PlatformDto,
        PAIRING_VERSION, RUNTIME_STATUS_FILE,
    };
    #[cfg(windows)]
    use super::{rewrite_windows_profile_paths, CONFIG_FILE, KEY_FILE};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use kvm_types::Edge;
    use rcgen::{CertificateParams, KeyPair, SigningKey};
    use sha2::{Digest, Sha256};
    use std::fs;
    #[cfg(windows)]
    use std::path::Path;

    fn display(id: &str, primary: bool) -> DisplayDto {
        DisplayDto {
            id: id.to_owned(),
            name: "Main display".to_owned(),
            width: 1_920.0,
            height: 1_080.0,
            scale_factor: 1.0,
            primary,
            native_bounds: Some(NativeBoundsDto {
                x: 0.0,
                y: 0.0,
                width: 1_920.0,
                height: 1_080.0,
            }),
        }
    }

    fn bundle() -> PairingBundle {
        let key = KeyPair::generate().expect("test key should generate");
        let certificate = CertificateParams::new(vec!["peer-b.kvm.test".to_owned()])
            .expect("test certificate parameters should build")
            .self_signed(&key)
            .expect("test certificate should sign")
            .der()
            .to_vec();
        PairingBundle {
            software_kvm_pairing: PAIRING_VERSION,
            host_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            peer_id: "00000000-0000-4000-8000-000000000002".to_owned(),
            display_name: "Windows desk".to_owned(),
            platform: PlatformDto::Windows,
            server_name: "peer-b.kvm.test".to_owned(),
            certificate_fingerprint: hex::encode(Sha256::digest(&certificate)),
            address: "192.168.1.22:24800".to_owned(),
            certificate_der: URL_SAFE_NO_PAD.encode(certificate),
            signing_public_key: URL_SAFE_NO_PAD.encode(key.public_key_raw()),
            displays: vec![display("00000000-0000-4000-8000-000000000003", true)],
        }
    }

    #[test]
    fn pairing_bundle_is_bounded_and_rejects_duplicate_displays() {
        let mut peer = bundle();
        assert!(validate_bundle(&peer).is_ok());
        let mut invalid_signer = peer.clone();
        invalid_signer.signing_public_key = URL_SAFE_NO_PAD.encode([0_u8; 65]);
        assert!(validate_bundle(&invalid_signer).is_err());
        peer.displays.push(peer.displays[0].clone());
        assert!(validate_bundle(&peer).is_err());
    }

    #[test]
    fn generated_topology_links_both_directions() {
        let peer = bundle();
        let local = [display("00000000-0000-4000-8000-000000000004", true)];
        let config = build_config(&peer, &local, &Placement::LocalLeft, &[])
            .expect("bounded two-display topology should build");
        assert_eq!(config.topology.displays.len(), 2);
        assert_eq!(config.topology.links.len(), 2);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn generated_topology_uses_the_real_outer_monitor_instead_of_primary_order() {
        let peer = bundle();
        let mut left_secondary = display("00000000-0000-4000-8000-000000000004", false);
        left_secondary.native_bounds.as_mut().unwrap().x = -1_920.0;
        let primary = display("00000000-0000-4000-8000-000000000005", true);

        let local_right = build_config(
            &peer,
            &[primary.clone(), left_secondary.clone()],
            &Placement::LocalRight,
            &[],
        )
        .expect("left outer monitor should form the host boundary");
        let local_right_link = local_right
            .topology
            .links
            .iter()
            .find(|link| link.from_display == left_secondary.id.parse().unwrap())
            .unwrap();
        assert_eq!(local_right_link.from_edge, Edge::Left);

        let local_left = build_config(
            &peer,
            &[primary.clone(), left_secondary],
            &Placement::LocalLeft,
            &[],
        )
        .expect("right outer monitor should form the host boundary");
        let local_left_link = local_left
            .topology
            .links
            .iter()
            .find(|link| link.from_display == primary.id.parse().unwrap())
            .unwrap();
        assert_eq!(local_left_link.from_edge, Edge::Right);
    }

    #[test]
    fn both_hosts_compile_the_same_topology_for_a_secondary_monitor_on_the_left() {
        let mac_display = display("00000000-0000-4000-8000-000000000006", true);
        let mut windows_secondary = display("00000000-0000-4000-8000-000000000004", false);
        windows_secondary.native_bounds.as_mut().unwrap().x = -1_920.0;
        let windows_primary = display("00000000-0000-4000-8000-000000000005", true);

        let mut windows_bundle = bundle();
        windows_bundle.displays = vec![windows_primary.clone(), windows_secondary.clone()];
        let mac_config = build_config(
            &windows_bundle,
            std::slice::from_ref(&mac_display),
            &Placement::LocalLeft,
            &[],
        )
        .unwrap();

        let mut mac_bundle = bundle();
        mac_bundle.displays = vec![mac_display];
        let windows_config = build_config(
            &mac_bundle,
            &[windows_primary, windows_secondary],
            &Placement::LocalRight,
            &[],
        )
        .unwrap();

        assert_eq!(mac_config.topology, windows_config.topology);
    }

    #[test]
    fn custom_display_map_supports_vertical_cross_host_handoff() {
        let peer = bundle();
        let local = [display("00000000-0000-4000-8000-000000000004", true)];
        let local_id = local[0].id.parse().unwrap();
        let peer_id = peer.displays[0].id.parse().unwrap();
        let layout = [
            DisplayLayoutDto {
                display_id: local_id,
                x: 0.0,
                y: 1_080.0,
            },
            DisplayLayoutDto {
                display_id: peer_id,
                x: 0.0,
                y: 0.0,
            },
        ];

        let config = build_config(&peer, &local, &Placement::LocalLeft, &layout).unwrap();
        let local_link = config
            .topology
            .links
            .iter()
            .find(|link| link.from_display == local_id)
            .unwrap();
        assert_eq!(local_link.from_edge, Edge::Top);
        assert_eq!(local_link.to_display, peer_id);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn custom_display_map_rejects_overlapping_screens() {
        let peer = bundle();
        let local = [display("00000000-0000-4000-8000-000000000004", true)];
        let layout = [
            DisplayLayoutDto {
                display_id: local[0].id.parse().unwrap(),
                x: 0.0,
                y: 0.0,
            },
            DisplayLayoutDto {
                display_id: peer.displays[0].id.parse().unwrap(),
                x: 1_000.0,
                y: 0.0,
            },
        ];

        assert!(build_config(&peer, &local, &Placement::LocalLeft, &layout).is_err());
    }

    #[test]
    fn workspace_signature_binds_both_peers_revision_and_payload() {
        let key = KeyPair::generate().unwrap();
        let from = "00000000-0000-4000-8000-000000000001";
        let to = "00000000-0000-4000-8000-000000000002";
        let payload = "eyJzY2hlbWFfdmVyc2lvbiI6MX0";
        let message = workspace_signature_message(from, to, 7, payload);
        let signature = key.sign(&message).unwrap();
        let public_key = URL_SAFE_NO_PAD.encode(key.public_key_raw());
        let signature = URL_SAFE_NO_PAD.encode(signature);

        assert!(verify_workspace_signature(&public_key, &signature, from, to, 7, payload).is_ok());
        assert!(verify_workspace_signature(&public_key, &signature, from, to, 8, payload).is_err());
        assert!(verify_workspace_signature(&public_key, &signature, to, from, 7, payload).is_err());

        let acknowledgement = workspace_ack_signature_message(to, from, 7);
        let acknowledgement = URL_SAFE_NO_PAD.encode(key.sign(&acknowledgement).unwrap());
        assert!(
            verify_workspace_ack_signature(&public_key, &acknowledgement, to, from, 7).is_ok()
        );
        assert!(
            verify_workspace_ack_signature(&public_key, &acknowledgement, to, from, 8).is_err()
        );
        assert!(
            verify_workspace_ack_signature(&public_key, &acknowledgement, from, to, 7).is_err()
        );
    }

    #[test]
    fn diagnostic_signature_binds_direction_stream_sequence_and_payload() {
        let key = KeyPair::generate().unwrap();
        let from = "00000000-0000-4000-8000-000000000001";
        let to = "00000000-0000-4000-8000-000000000002";
        let stream = "00000000-0000-4000-8000-000000000003";
        let payload = URL_SAFE_NO_PAD.encode(b"[\"[dev] routing=enabled\"]");
        let message = diagnostic_signature_message(from, to, stream, 1, &payload);
        let public_key = URL_SAFE_NO_PAD.encode(key.public_key_raw());
        let signature = URL_SAFE_NO_PAD.encode(key.sign(&message).unwrap());

        assert!(verify_peer_signature(&public_key, &signature, &message).is_ok());
        let replay = diagnostic_signature_message(from, to, stream, 2, &payload);
        assert!(verify_peer_signature(&public_key, &signature, &replay).is_err());
        let reversed = diagnostic_signature_message(to, from, stream, 1, &payload);
        assert!(verify_peer_signature(&public_key, &signature, &reversed).is_err());
    }

    #[test]
    fn runtime_status_reports_only_an_effective_peer_authority() {
        let directory =
            std::env::temp_dir().join(format!("software-kvm-status-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join(RUNTIME_STATUS_FILE),
            b"schema_version = 1\nservice = \"running\"\ninput_owner = \"peer\"\nrouting = \"enabled\"\nsession_active = true\n",
        )
        .unwrap();

        let status = read_input_authority(&directory);
        assert!(matches!(status.owner, InputOwnerState::Peer));
        assert!(status.link_ready);
        assert!(status.session_active);

        fs::write(
            directory.join(RUNTIME_STATUS_FILE),
            b"schema_version = 1\nservice = \"running\"\ninput_owner = \"peer\"\nrouting = \"gated\"\nsession_active = true\n",
        )
        .unwrap();
        let gated = read_input_authority(&directory);
        assert!(matches!(gated.owner, InputOwnerState::Local));
        assert!(!gated.link_ready);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_profile_migration_rewrites_only_legacy_material_paths() {
        let root = Path::new(r"C:\Users\test\AppData\Local\software-kvm");
        let directory = root.join("runtime");
        let source = format!(
            "kvm_config_path = '{}'\nprivate_key = '{}'\n",
            root.join(CONFIG_FILE).display(),
            root.join(KEY_FILE).display()
        );
        let expected = format!(
            "kvm_config_path = '{}'\nprivate_key = '{}'\n",
            directory.join(CONFIG_FILE).display(),
            directory.join(KEY_FILE).display()
        );

        let rewritten = rewrite_windows_profile_paths(source.as_bytes(), root, &directory)
            .expect("legacy paths should rewrite");
        assert_eq!(rewritten, expected.as_bytes());
        assert_eq!(
            rewrite_windows_profile_paths(&rewritten, root, &directory)
                .expect("rewritten paths should remain stable"),
            rewritten
        );
    }
}
