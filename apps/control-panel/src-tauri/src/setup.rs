// Tauri command parameters are owned/injected at the IPC boundary even when
// the command body only borrows them.
#![allow(clippy::needless_pass_by_value)]

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
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
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

use crate::nearby::{NearbyDiscovery, NearbyMachineDto, NearbyPresence};

const KVM_PORT: u16 = 24_800;
const PAIRING_VERSION: u16 = 2;
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
const MAX_RUNTIME_LOG_READ: u64 = 16 * 1024;
#[cfg(windows)]
// Keep credentials separate from WebView2's profile in the app-data root.
const WINDOWS_SETUP_DIRECTORY: &str = "runtime";

#[derive(Debug)]
pub(crate) struct SetupService {
    directory: PathBuf,
    inner: Mutex<StoredSetup>,
    runtime: Mutex<Option<Child>>,
    last_runtime_fault: Mutex<Option<RuntimeFault>>,
    discovery: Option<NearbyDiscovery>,
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
    displays: Vec<DisplayDto>,
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
    configured: bool,
    validated: bool,
    runtime: RuntimeState,
    runtime_fault: Option<RuntimeFault>,
    runtime_log_path: Option<String>,
    discovery_available: bool,
    nearby_machines: Vec<NearbyMachineDto>,
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
        let discovery_addresses = private_addresses()
            .into_iter()
            .filter_map(|address| address.parse().ok())
            .take(8)
            .collect();
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
            discovery,
        })
    }

    fn save(&self, setup: &StoredSetup) -> Result<(), ()> {
        let bytes = serde_json::to_vec_pretty(setup).map_err(|_| ())?;
        secure_write(&self.directory.join(STATE_FILE), &bytes, true)
    }

    fn snapshot(&self) -> Result<SetupSnapshot, ()> {
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
        let setup = self.inner.lock().map_err(|_| ())?.clone();
        let host_id = setup
            .local
            .as_ref()
            .map_or(setup.draft_host_id.as_str(), |local| local.host_id.as_str());
        let displays = native_displays(parse_host_id(host_id).map_err(|_| ())?).map_err(|_| ())?;
        let local = setup
            .local
            .as_ref()
            .map(|local| self.local_dto(local, &displays))
            .transpose()?;
        let peer = setup.peer.clone().map(peer_dto);
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
        let nearby_machines = self.discovery.as_ref().map_or_else(Vec::new, |discovery| {
            discovery.snapshot(setup.peer.as_ref().map(|peer| peer.peer_id.as_str()))
        });
        Ok(SetupSnapshot {
            platform: current_platform(),
            suggested_name: suggested_name(),
            address_options: private_addresses(),
            local,
            peer,
            displays,
            placement: setup.placement,
            configured: setup.configured,
            validated: setup.validated,
            runtime: runtime_state,
            runtime_fault: *last_fault,
            runtime_log_path: setup.configured.then(|| {
                self.directory
                    .join(RUNTIME_LOG_FILE)
                    .to_string_lossy()
                    .into_owned()
            }),
            discovery_available: self.discovery.is_some(),
            nearby_machines,
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

    fn local_dto(
        &self,
        local: &StoredLocal,
        displays: &[DisplayDto],
    ) -> Result<LocalIdentityDto, ()> {
        let certificate = fs::read(self.directory.join(CERT_FILE)).map_err(|_| ())?;
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
    let raw = URL_SAFE_NO_PAD
        .decode(bundle.trim())
        .map_err(|_| coarse_error())?;
    if raw.len() > 64 * 1024 {
        return Err(coarse_error());
    }
    let peer: PairingBundle = serde_json::from_slice(&raw).map_err(|_| coarse_error())?;
    validate_bundle(&peer)?;
    let certificate = URL_SAFE_NO_PAD
        .decode(&peer.certificate_der)
        .map_err(|_| coarse_error())?;
    let setup = service.inner.lock().map_err(|_| coarse_error())?;
    let local = setup.local.as_ref().ok_or_else(coarse_error)?;
    if peer.host_id == local.host_id
        || peer.peer_id == local.peer_id
        || peer.platform == current_platform()
    {
        return Err(coarse_error());
    }
    drop(setup);
    secure_write(&service.directory.join(TRUST_FILE), &certificate, false)
        .map_err(|()| coarse_error())?;
    let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
    setup.peer = Some(peer);
    setup.configured = false;
    setup.validated = false;
    service.save(&setup).map_err(|()| coarse_error())?;
    drop(setup);
    service.snapshot().map_err(|()| coarse_error())
}

#[tauri::command]
pub(crate) fn finalize_setup(
    placement: Placement,
    service: State<'_, SetupService>,
) -> Result<SetupSnapshot, String> {
    ensure_runtime_stopped(&service)?;
    let mut setup = service.inner.lock().map_err(|_| coarse_error())?;
    let local = setup.local.clone().ok_or_else(coarse_error)?;
    let peer = setup.peer.clone().ok_or_else(coarse_error)?;
    let local_displays =
        native_displays(parse_host_id(&local.host_id)?).map_err(|_| coarse_error())?;
    if local_displays.is_empty() || peer.displays.is_empty() {
        return Err(coarse_error());
    }
    let config = build_config(&peer, &local_displays, &placement)?;
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
    setup.placement = placement;
    setup.configured = true;
    setup.validated = false;
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
    {
        let setup = service.inner.lock().map_err(|_| coarse_error())?;
        if !setup.validated {
            return Err(coarse_error());
        }
    }
    let mut active = service.runtime.lock().map_err(|_| coarse_error())?;
    if active.is_some() || runtime_lock_held(&service.directory) {
        return Err(coarse_error());
    }
    let binary = runtime_binary().ok_or_else(coarse_error)?;
    let control = service.directory.join(CONTROL_FILE);
    secure_write(&control, b"run\n", true).map_err(|()| coarse_error())?;
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
    let child = Command::new(binary)
        .arg("run-managed")
        .arg(service.directory.join(PROFILE_FILE))
        .arg(control)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .map_err(|_| coarse_error())?;
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
    if certificate.is_empty()
        || certificate.len() > kvm_runtime::MAX_CERTIFICATE_DER_BYTES
        || hex::encode(Sha256::digest(&certificate)) != peer.certificate_fingerprint
    {
        return Err(coarse_error());
    }
    Ok(())
}

fn build_config(
    peer: &PairingBundle,
    local_displays: &[DisplayDto],
    placement: &Placement,
) -> Result<Config, String> {
    let remote_host = parse_host_id(&peer.host_id)?;
    let mut ordered_local = local_displays.to_vec();
    ordered_local.sort_by_key(|display| !display.primary);
    let mut ordered_peer = peer.displays.clone();
    ordered_peer.sort_by_key(|display| !display.primary);
    let (first, second) = match placement {
        Placement::LocalLeft => (&ordered_local, &ordered_peer),
        Placement::LocalRight => (&ordered_peer, &ordered_local),
    };
    let mut x = 0.0;
    let mut placements = Vec::new();
    for display in first.iter().chain(second) {
        placements.push(DisplayPlacement {
            display_id: display.id.parse().map_err(|_| coarse_error())?,
            x,
            y: 0.0,
        });
        x += display.width;
    }
    let (left_display, right_display) = (
        first.last().ok_or_else(coarse_error)?,
        second.first().ok_or_else(coarse_error)?,
    );
    let links = vec![
        TopologyLink {
            from_display: left_display.id.parse().map_err(|_| coarse_error())?,
            from_edge: Edge::Right,
            to_display: right_display.id.parse().map_err(|_| coarse_error())?,
            to_edge: Edge::Left,
        },
        TopologyLink {
            from_display: right_display.id.parse().map_err(|_| coarse_error())?,
            from_edge: Edge::Left,
            to_display: left_display.id.parse().map_err(|_| coarse_error())?,
            to_edge: Edge::Right,
        },
    ];
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
        build_config, validate_bundle, DisplayDto, PairingBundle, Placement, PlatformDto,
        PAIRING_VERSION,
    };
    #[cfg(windows)]
    use super::{rewrite_windows_profile_paths, CONFIG_FILE, KEY_FILE};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rcgen::{CertificateParams, KeyPair};
    use sha2::{Digest, Sha256};
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
            displays: vec![display("00000000-0000-4000-8000-000000000003", true)],
        }
    }

    #[test]
    fn pairing_bundle_is_bounded_and_rejects_duplicate_displays() {
        let mut peer = bundle();
        assert!(validate_bundle(&peer).is_ok());
        peer.displays.push(peer.displays[0].clone());
        assert!(validate_bundle(&peer).is_err());
    }

    #[test]
    fn generated_topology_links_both_directions() {
        let peer = bundle();
        let local = [display("00000000-0000-4000-8000-000000000004", true)];
        let config = build_config(&peer, &local, &Placement::LocalLeft)
            .expect("bounded two-display topology should build");
        assert_eq!(config.topology.displays.len(), 2);
        assert_eq!(config.topology.links.len(), 2);
        assert!(config.validate().is_ok());
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
