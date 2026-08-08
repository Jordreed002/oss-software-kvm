use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use kvm_types::PeerId;
use mdns_sd::{
    DaemonStatus, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo, UnregisterStatus,
};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::{
    is_supported_lan_address, DiscoveryCache, DiscoveryCacheChange, DiscoveryCacheConfig,
    DiscoverySnapshot, RawDiscoveryRecord, RawTxtProperty, DISCOVERY_PROTOCOL_VERSION,
    MAX_ADDRESSES_PER_SERVICE, MAX_FULLNAME_BYTES, MAX_HOSTNAME_BYTES, MAX_INSTANCE_NAME_BYTES,
    MAX_TXT_KEY_BYTES, MAX_TXT_PROPERTIES, MAX_TXT_VALUE_BYTES, SOFTWARE_KVM_SERVICE_TYPE,
};

const DEFAULT_RESOLVED_TTL: Duration = Duration::from_mins(2);
const DEFAULT_EXPIRY_INTERVAL: Duration = Duration::from_millis(250);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimal caller-selected metadata advertised on the LAN.
pub struct MdnsAdvertisement {
    peer_id: PeerId,
    instance_name: String,
    port: u16,
    addresses: Vec<IpAddr>,
}

impl MdnsAdvertisement {
    /// Validates the complete advertisement before mDNS allocation.
    ///
    /// # Errors
    ///
    /// Rejects nil identity, invalid instance name, zero port, an empty or
    /// oversized address set and every non-private/non-ULA IP. Duplicate safe
    /// addresses are canonicalized away.
    pub fn new(
        peer_id: PeerId,
        instance_name: impl Into<String>,
        port: u16,
        mut addresses: Vec<IpAddr>,
    ) -> Result<Self, MdnsAdapterError> {
        let instance_name = instance_name.into();
        if peer_id.into_bytes() == [0; 16]
            || instance_name.is_empty()
            || instance_name.len() > MAX_INSTANCE_NAME_BYTES
            || instance_name.chars().any(char::is_control)
            || port == 0
            || addresses.is_empty()
            || addresses.len() > MAX_ADDRESSES_PER_SERVICE
            || addresses
                .iter()
                .copied()
                .any(|address| !is_supported_lan_address(address))
        {
            return Err(MdnsAdapterError::InvalidConfig);
        }
        addresses.sort_unstable();
        addresses.dedup();
        Ok(Self {
            peer_id,
            instance_name,
            port,
            addresses,
        })
    }
}

impl fmt::Debug for MdnsAdvertisement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MdnsAdvertisement")
            .field("peer_id", &"[REDACTED]")
            .field("instance_name", &"[REDACTED]")
            .field("port_present", &(self.port != 0))
            .field("address_count", &self.addresses.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdnsAdapterConfig {
    pub cache: DiscoveryCacheConfig,
    pub resolved_ttl: Duration,
    pub expiry_interval: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for MdnsAdapterConfig {
    fn default() -> Self {
        Self {
            cache: DiscoveryCacheConfig::default(),
            resolved_ttl: DEFAULT_RESOLVED_TTL,
            expiry_interval: DEFAULT_EXPIRY_INTERVAL,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }
}

impl MdnsAdapterConfig {
    fn validate(self) -> Result<(), MdnsAdapterError> {
        self.cache
            .validate()
            .map_err(|_| MdnsAdapterError::InvalidConfig)?;
        if self.resolved_ttl == Duration::ZERO
            || self.resolved_ttl > self.cache.maximum_ttl
            || self.expiry_interval == Duration::ZERO
            || self.expiry_interval > self.cache.maximum_ttl
            || self.shutdown_timeout == Duration::ZERO
            || self.shutdown_timeout > MAX_SHUTDOWN_TIMEOUT
        {
            return Err(MdnsAdapterError::InvalidConfig);
        }
        Ok(())
    }
}

/// Coarse adapter/lifecycle error with no dependency or record strings.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MdnsAdapterError {
    #[error("mDNS discovery configuration is invalid")]
    InvalidConfig,
    #[error("mDNS discovery daemon is unavailable")]
    DaemonUnavailable,
    #[error("mDNS discovery bridge failed")]
    BridgeFailed,
    #[error("mDNS discovery shutdown exceeded its deadline")]
    ShutdownTimeout,
    #[error("mDNS discovery shutdown cleanup failed")]
    ShutdownFailed,
}

/// Production advertisement/browser with a bounded snapshot bridge.
pub struct MdnsDiscoveryAdapter {
    daemon: ServiceDaemon,
    registration_fullname: String,
    snapshots: watch::Receiver<DiscoverySnapshot>,
    stop: watch::Sender<bool>,
    bridge: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
    stopped: bool,
}

impl fmt::Debug for MdnsDiscoveryAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MdnsDiscoveryAdapter")
            .field("service_type", &SOFTWARE_KVM_SERVICE_TYPE)
            .field("registration", &"[REDACTED]")
            .field("snapshot_candidate_count", &self.snapshots.borrow().len())
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}

impl MdnsDiscoveryAdapter {
    /// Starts production mDNS on the standard port.
    ///
    /// # Errors
    ///
    /// Returns a coarse error if validation, daemon creation, registration,
    /// browsing, or bridge startup fails.
    pub fn start(
        advertisement: &MdnsAdvertisement,
        config: MdnsAdapterConfig,
    ) -> Result<Self, MdnsAdapterError> {
        tokio::runtime::Handle::try_current().map_err(|_| MdnsAdapterError::DaemonUnavailable)?;
        config.validate()?;
        let service = build_service_info(advertisement)?;
        let daemon = ServiceDaemon::new().map_err(|_| MdnsAdapterError::DaemonUnavailable)?;
        Self::start_with_daemon(daemon, service, config)
    }

    #[cfg(test)]
    fn start_with_port(
        advertisement: &MdnsAdvertisement,
        config: MdnsAdapterConfig,
        mdns_port: u16,
    ) -> Result<Self, MdnsAdapterError> {
        tokio::runtime::Handle::try_current().map_err(|_| MdnsAdapterError::DaemonUnavailable)?;
        config.validate()?;
        let service = build_service_info(advertisement)?;
        let daemon = ServiceDaemon::new_with_port(mdns_port)
            .map_err(|_| MdnsAdapterError::DaemonUnavailable)?;
        Self::start_with_daemon(daemon, service, config)
    }

    fn start_with_daemon(
        daemon: ServiceDaemon,
        service: ServiceInfo,
        config: MdnsAdapterConfig,
    ) -> Result<Self, MdnsAdapterError> {
        let registration_fullname = service.get_fullname().to_owned();
        let Ok(cache) = DiscoveryCache::new(config.cache) else {
            let _ = daemon.shutdown();
            return Err(MdnsAdapterError::InvalidConfig);
        };
        let Ok(browse_events) = daemon.browse(SOFTWARE_KVM_SERVICE_TYPE) else {
            let _ = daemon.shutdown();
            return Err(MdnsAdapterError::DaemonUnavailable);
        };
        if daemon.register(service).is_err() {
            let _ = daemon.stop_browse(SOFTWARE_KVM_SERVICE_TYPE);
            let _ = daemon.shutdown();
            return Err(MdnsAdapterError::DaemonUnavailable);
        }

        let (snapshot_sender, snapshots) = watch::channel(cache.snapshot());
        let (stop, stop_receiver) = watch::channel(false);
        let bridge = tokio::spawn(run_bridge(
            browse_events,
            cache,
            snapshot_sender,
            stop_receiver,
            config.resolved_ttl,
            config.expiry_interval,
        ));
        Ok(Self {
            daemon,
            registration_fullname,
            snapshots,
            stop,
            bridge: Some(bridge),
            shutdown_timeout: config.shutdown_timeout,
            stopped: false,
        })
    }

    /// Receives the next immutable latest-view update.
    pub async fn next_snapshot(&mut self) -> Option<DiscoverySnapshot> {
        self.snapshots.changed().await.ok()?;
        Some(self.snapshots.borrow_and_update().clone())
    }

    /// Returns the latest immutable view without waiting for a change.
    #[must_use]
    pub fn current_snapshot(&self) -> DiscoverySnapshot {
        self.snapshots.borrow().clone()
    }

    /// Stops the bridge and mDNS browse/registration/daemon within one bound.
    ///
    /// # Errors
    ///
    /// Returns a coarse daemon or timeout error after aborting local bridge
    /// work. No bridge task remains detached.
    pub async fn shutdown(mut self) -> Result<(), MdnsAdapterError> {
        let deadline = Instant::now() + self.shutdown_timeout;
        let mut failure = None;
        let _ = self.stop.send(true);
        if let Some(bridge) = self.bridge.as_mut() {
            match tokio::time::timeout_at(deadline, bridge).await {
                Ok(Ok(())) => {
                    self.bridge.take();
                }
                Ok(Err(_)) => {
                    self.bridge.take();
                    failure = Some(MdnsAdapterError::BridgeFailed);
                }
                Err(_) => {
                    if let Some(bridge) = self.bridge.take() {
                        bridge.abort();
                        let _ = bridge.await;
                    }
                    failure = Some(MdnsAdapterError::ShutdownTimeout);
                }
            }
        }

        if self.daemon.stop_browse(SOFTWARE_KVM_SERVICE_TYPE).is_err() {
            failure.get_or_insert(MdnsAdapterError::ShutdownFailed);
        }

        match self.daemon.unregister(&self.registration_fullname) {
            Ok(unregister) => {
                match tokio::time::timeout_at(deadline, unregister.recv_async()).await {
                    Ok(Ok(UnregisterStatus::OK)) => {}
                    Ok(Ok(UnregisterStatus::NotFound) | Err(_)) => {
                        failure.get_or_insert(MdnsAdapterError::ShutdownFailed);
                    }
                    Err(_) => failure = Some(MdnsAdapterError::ShutdownTimeout),
                }
            }
            Err(_) => {
                failure.get_or_insert(MdnsAdapterError::ShutdownFailed);
            }
        }

        let daemon_stopped = if let Ok(shutdown) = self.daemon.shutdown() {
            match tokio::time::timeout_at(deadline, shutdown.recv_async()).await {
                Ok(Ok(DaemonStatus::Shutdown)) => true,
                Ok(Ok(_) | Err(_)) => {
                    failure.get_or_insert(MdnsAdapterError::ShutdownFailed);
                    false
                }
                Err(_) => {
                    failure = Some(MdnsAdapterError::ShutdownTimeout);
                    false
                }
            }
        } else {
            failure.get_or_insert(MdnsAdapterError::ShutdownFailed);
            false
        };
        self.stopped = daemon_stopped;
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for MdnsDiscoveryAdapter {
    fn drop(&mut self) {
        if self.stopped {
            return;
        }
        let _ = self.stop.send(true);
        if let Some(bridge) = self.bridge.take() {
            bridge.abort();
        }
        let _ = self.daemon.stop_browse(SOFTWARE_KVM_SERVICE_TYPE);
        let _ = self.daemon.unregister(&self.registration_fullname);
        let _ = self.daemon.shutdown();
        self.stopped = true;
    }
}

fn build_service_info(advertisement: &MdnsAdvertisement) -> Result<ServiceInfo, MdnsAdapterError> {
    let peer = advertisement.peer_id.to_string();
    let hostname = format!("{peer}.local.");
    let properties = [("ver", DISCOVERY_PROTOCOL_VERSION), ("peer", peer.as_str())];
    ServiceInfo::new(
        SOFTWARE_KVM_SERVICE_TYPE,
        &advertisement.instance_name,
        &hostname,
        advertisement.addresses.as_slice(),
        advertisement.port,
        properties.as_slice(),
    )
    .map_err(|_| MdnsAdapterError::InvalidConfig)
}

async fn run_bridge(
    browse_events: mdns_sd::Receiver<ServiceEvent>,
    mut cache: DiscoveryCache,
    snapshots: watch::Sender<DiscoverySnapshot>,
    mut stop: watch::Receiver<bool>,
    resolved_ttl: Duration,
    expiry_interval: Duration,
) {
    let origin = Instant::now();
    let mut expiry = tokio::time::interval(expiry_interval);
    expiry.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        if *stop.borrow() {
            break;
        }

        tokio::select! {
            biased;
            result = stop.changed() => {
                if result.is_err() || *stop.borrow() {
                    break;
                }
            }
            event = browse_events.recv_async() => {
                let Ok(event) = event else { break };
                let changed = apply_service_event(&mut cache, event, origin.elapsed(), resolved_ttl);
                if changed == DiscoveryCacheChange::Changed {
                    snapshots.send_replace(cache.snapshot());
                }
            }
            _ = expiry.tick() => {
                if cache.expire(origin.elapsed()) == DiscoveryCacheChange::Changed {
                    snapshots.send_replace(cache.snapshot());
                }
            }
        }
    }
}

fn apply_service_event(
    cache: &mut DiscoveryCache,
    event: ServiceEvent,
    now: Duration,
    resolved_ttl: Duration,
) -> DiscoveryCacheChange {
    match event {
        ServiceEvent::ServiceResolved(service) => raw_from_resolved(&service, resolved_ttl)
            .and_then(|record| cache.apply_resolved(record, now).ok())
            .unwrap_or(DiscoveryCacheChange::Unchanged),
        ServiceEvent::ServiceRemoved(service_type, fullname)
            if service_type == SOFTWARE_KVM_SERVICE_TYPE =>
        {
            cache
                .remove_fullname(fullname.as_bytes())
                .unwrap_or(DiscoveryCacheChange::Unchanged)
        }
        _ => DiscoveryCacheChange::Unchanged,
    }
}

fn raw_from_resolved(service: &ResolvedService, ttl: Duration) -> Option<RawDiscoveryRecord> {
    if service.ty_domain.len() > MAX_FULLNAME_BYTES
        || service.get_fullname().len() > MAX_FULLNAME_BYTES
        || service.get_hostname().len() > MAX_HOSTNAME_BYTES
        || service.get_addresses().len() > MAX_ADDRESSES_PER_SERVICE
        || service.get_properties().len() > MAX_TXT_PROPERTIES
        || service.get_properties().iter().any(|property| {
            property.key().len() > MAX_TXT_KEY_BYTES
                || property
                    .val()
                    .is_none_or(|value| value.len() > MAX_TXT_VALUE_BYTES)
        })
    {
        return None;
    }
    Some(RawDiscoveryRecord {
        service_type: service.ty_domain.as_bytes().to_vec(),
        fullname: service.get_fullname().as_bytes().to_vec(),
        hostname: service.get_hostname().as_bytes().to_vec(),
        port: service.get_port(),
        addresses: service
            .get_addresses()
            .iter()
            .map(mdns_sd::ScopedIp::to_ip_addr)
            .collect(),
        txt: service
            .get_properties()
            .iter()
            .map(|property| RawTxtProperty {
                key: property.key().as_bytes().to_vec(),
                value: property.val().map(<[u8]>::to_vec),
            })
            .collect(),
        ttl,
    })
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::DiscoveryCandidate;

    fn advertisement(marker: &str) -> MdnsAdvertisement {
        MdnsAdvertisement::new(
            PeerId::from_bytes([1; 16]),
            marker,
            4242,
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        )
        .unwrap()
    }

    #[test]
    fn advertisement_rejects_nil_unsafe_and_oversized_metadata() {
        assert!(matches!(
            MdnsAdvertisement::new(
                PeerId::from_bytes([0; 16]),
                "peer",
                4242,
                vec!["10.0.0.1".parse().unwrap()]
            ),
            Err(MdnsAdapterError::InvalidConfig)
        ));
        assert!(matches!(
            MdnsAdvertisement::new(
                PeerId::from_bytes([1; 16]),
                "peer",
                4242,
                vec!["8.8.8.8".parse().unwrap()]
            ),
            Err(MdnsAdapterError::InvalidConfig)
        ));
        assert!(matches!(
            MdnsAdvertisement::new(
                PeerId::from_bytes([1; 16]),
                "x".repeat(MAX_INSTANCE_NAME_BYTES + 1),
                4242,
                vec!["10.0.0.1".parse().unwrap()]
            ),
            Err(MdnsAdapterError::InvalidConfig)
        ));
    }

    #[test]
    fn service_info_publishes_only_minimal_properties() {
        let service = build_service_info(&advertisement("minimal")).unwrap();
        assert_eq!(service.get_type(), SOFTWARE_KVM_SERVICE_TYPE);
        assert_eq!(service.get_port(), 4242);
        assert_eq!(service.get_properties().len(), 2);
        assert_eq!(
            service.get_property_val_str("ver"),
            Some(DISCOVERY_PROTOCOL_VERSION)
        );
        assert_eq!(
            service.get_property_val_str("peer"),
            Some("01010101-0101-0101-0101-010101010101")
        );
        for forbidden in ["fingerprint", "host", "key", "nonce", "display", "input"] {
            assert!(service.get_property(forbidden).is_none());
        }
    }

    #[tokio::test]
    async fn custom_port_adapter_starts_and_shuts_down_boundedly() {
        let config = MdnsAdapterConfig {
            shutdown_timeout: Duration::from_secs(3),
            ..MdnsAdapterConfig::default()
        };
        let adapter =
            MdnsDiscoveryAdapter::start_with_port(&advertisement("smoke"), config, 0).unwrap();
        tokio::time::timeout(Duration::from_secs(4), adapter.shutdown())
            .await
            .expect("adapter shutdown exceeded outer test bound")
            .unwrap();
    }

    #[tokio::test]
    async fn cancelling_shutdown_aborts_the_still_owned_bridge() {
        struct CancellationProbe(Arc<AtomicBool>);

        impl Drop for CancellationProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let mut adapter = MdnsDiscoveryAdapter::start_with_port(
            &advertisement("cancelled-shutdown"),
            MdnsAdapterConfig::default(),
            0,
        )
        .unwrap();
        let previous_bridge = adapter.bridge.take().unwrap();
        previous_bridge.abort();
        let _ = previous_bridge.await;

        let cancelled = Arc::new(AtomicBool::new(false));
        let bridge_probe = Arc::clone(&cancelled);
        adapter.bridge = Some(tokio::spawn(async move {
            let _probe = CancellationProbe(bridge_probe);
            pending::<()>().await;
        }));
        let mut stop_observer = adapter.stop.subscribe();
        let shutdown = tokio::spawn(adapter.shutdown());
        stop_observer.changed().await.unwrap();
        assert!(*stop_observer.borrow_and_update());

        shutdown.abort();
        let _ = shutdown.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancelled.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled shutdown detached its bridge");
    }

    #[test]
    fn start_outside_tokio_runtime_returns_error_without_panicking() {
        assert!(matches!(
            MdnsDiscoveryAdapter::start(
                &advertisement("outside-runtime"),
                MdnsAdapterConfig::default()
            ),
            Err(MdnsAdapterError::DaemonUnavailable)
        ));
    }

    #[test]
    fn config_and_diagnostics_are_bounded_and_redacted() {
        let marker = "SECRET-INSTANCE-MARKER";
        let advertisement = advertisement(marker);
        let rendered = format!("{advertisement:?} {:?}", MdnsAdapterError::BridgeFailed);
        assert!(!rendered.contains(marker));
        assert!(!rendered.contains("01010101-0101-0101-0101-010101010101"));
        assert!(rendered.len() < 240);

        let invalid = MdnsAdapterConfig {
            shutdown_timeout: MAX_SHUTDOWN_TIMEOUT + Duration::from_nanos(1),
            ..MdnsAdapterConfig::default()
        };
        assert_eq!(invalid.validate(), Err(MdnsAdapterError::InvalidConfig));
    }

    #[tokio::test]
    async fn snapshot_channel_replaces_stale_pending_views_with_latest() {
        let peer = PeerId::from_bytes([1; 16]);
        let populated = DiscoverySnapshot::from_candidates(vec![DiscoveryCandidate::new(
            peer,
            "10.0.0.1:4242".parse().unwrap(),
        )]);
        let (sender, mut receiver) = watch::channel(DiscoverySnapshot::default());
        sender.send_replace(populated);
        sender.send_replace(DiscoverySnapshot::default());

        receiver.changed().await.unwrap();
        assert!(receiver.borrow_and_update().is_empty());
    }
}
