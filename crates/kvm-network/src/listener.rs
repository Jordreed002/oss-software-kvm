use crate::{AuthenticatedAcceptor, SecurePeerStream};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Instant};

const HARD_MAX_LISTENERS: usize = 8;
const HARD_MAX_OUTSTANDING_HANDSHAKES: usize = 256;
const HARD_MAX_PER_SOURCE_HANDSHAKES: usize = 32;
const HARD_MAX_ATTEMPTS_PER_SOURCE: u32 = 256;
const HARD_MAX_GLOBAL_ATTEMPTS: u32 = 4_096;
const HARD_MAX_TRACKED_SOURCES: usize = 1_024;
const HARD_MAX_RAW_ACCEPT_QUEUE: usize = 1_024;
const HARD_MAX_EVENT_QUEUE: usize = 4_096;
const HARD_MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const HARD_MAX_ATTEMPT_WINDOW: Duration = Duration::from_mins(1);
const HARD_MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_ERROR_BACKOFF_BASE: Duration = Duration::from_millis(1);
const ACCEPT_ERROR_BACKOFF_MAX: Duration = Duration::from_millis(8);
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 8;

/// Positive resource and time bounds for an explicit-LAN listener service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LanListenerConfig {
    pub maximum_listeners: usize,
    pub maximum_outstanding_handshakes: usize,
    pub maximum_per_source_handshakes: usize,
    pub maximum_attempts_per_source: u32,
    pub maximum_global_attempts: u32,
    pub maximum_tracked_sources: usize,
    pub raw_accept_queue_capacity: usize,
    pub event_queue_capacity: usize,
    pub handshake_timeout: Duration,
    pub attempt_window: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for LanListenerConfig {
    fn default() -> Self {
        Self {
            maximum_listeners: 4,
            maximum_outstanding_handshakes: 32,
            maximum_per_source_handshakes: 4,
            maximum_attempts_per_source: 32,
            maximum_global_attempts: 512,
            maximum_tracked_sources: 256,
            raw_accept_queue_capacity: 128,
            event_queue_capacity: 128,
            handshake_timeout: Duration::from_secs(6),
            attempt_window: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(2),
        }
    }
}

impl LanListenerConfig {
    fn validate(self) -> Result<(), LanListenerConfigError> {
        if self.maximum_listeners == 0
            || self.maximum_outstanding_handshakes == 0
            || self.maximum_per_source_handshakes == 0
            || self.maximum_attempts_per_source == 0
            || self.maximum_global_attempts == 0
            || self.maximum_tracked_sources == 0
            || self.raw_accept_queue_capacity == 0
            || self.event_queue_capacity == 0
        {
            return Err(LanListenerConfigError::ZeroBound);
        }
        if self.maximum_listeners > HARD_MAX_LISTENERS
            || self.maximum_outstanding_handshakes > HARD_MAX_OUTSTANDING_HANDSHAKES
            || self.maximum_per_source_handshakes > HARD_MAX_PER_SOURCE_HANDSHAKES
            || self.maximum_attempts_per_source > HARD_MAX_ATTEMPTS_PER_SOURCE
            || self.maximum_global_attempts > HARD_MAX_GLOBAL_ATTEMPTS
            || self.maximum_tracked_sources > HARD_MAX_TRACKED_SOURCES
            || self.raw_accept_queue_capacity > HARD_MAX_RAW_ACCEPT_QUEUE
            || self.event_queue_capacity > HARD_MAX_EVENT_QUEUE
        {
            return Err(LanListenerConfigError::BoundTooLarge);
        }
        if self.maximum_per_source_handshakes > self.maximum_outstanding_handshakes {
            return Err(LanListenerConfigError::InvalidConcurrencyRelationship);
        }
        if self.handshake_timeout == Duration::ZERO
            || self.handshake_timeout > HARD_MAX_HANDSHAKE_TIMEOUT
            || self.attempt_window == Duration::ZERO
            || self.attempt_window > HARD_MAX_ATTEMPT_WINDOW
            || self.shutdown_timeout == Duration::ZERO
            || self.shutdown_timeout > HARD_MAX_SHUTDOWN_TIMEOUT
        {
            return Err(LanListenerConfigError::InvalidDuration);
        }
        Ok(())
    }
}

/// Coarse configuration failure that never contains a bind address or
/// peer-controlled value.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LanListenerConfigError {
    #[error("all listener resource bounds must be positive")]
    ZeroBound,
    #[error("a listener resource bound exceeds its hard maximum")]
    BoundTooLarge,
    #[error("per-source concurrency exceeds global concurrency")]
    InvalidConcurrencyRelationship,
    #[error("a listener duration is outside its permitted range")]
    InvalidDuration,
}

/// Failure to validate or bind the explicitly requested LAN listeners.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LanListenerBuildError {
    #[error(transparent)]
    InvalidConfig(#[from] LanListenerConfigError),
    #[error("at least one explicit LAN bind address is required")]
    MissingBindAddress,
    #[error("the explicit bind-address count exceeds its configured bound")]
    TooManyBindAddresses,
    #[error("duplicate explicit LAN bind addresses are not permitted")]
    DuplicateBindAddress,
    #[error("a bind address is not an allowed initial LAN endpoint")]
    UnsafeBindAddress,
    #[error("an explicit LAN listener could not be bound ({0:?})")]
    BindFailed(io::ErrorKind),
}

/// Coarse listener rejection telemetry. Source addresses, TLS errors,
/// credentials, fingerprints, and peer-controlled strings are omitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanListenerRejection {
    UnsafeSource,
    SourceTrackingLimited,
    SourceRateLimited,
    GlobalRateLimited,
    SourceConcurrencyLimited,
    GlobalConcurrencyLimited,
    RawAcceptQueueSaturated,
    AcceptedSocketSetupFailed,
    AcceptFailed,
    HandshakeFailed,
    HandshakeTaskPanicked,
    AcceptTaskPanicked,
}

/// Bounded authenticated-stream output from the listener.
///
/// Rejections are reported only through count fields in [`LanListenerReport`],
/// so an unauthenticated rejection flood cannot consume this queue.
pub enum LanListenerEvent<S> {
    Accepted { stream: S },
}

impl<S> std::fmt::Debug for LanListenerEvent<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted { .. } => formatter
                .debug_struct("Accepted")
                .field("stream", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Count-only terminal listener telemetry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LanListenerReport {
    pub accepted_streams: u64,
    pub rejected_attempts: u64,
    pub dropped_events: u64,
    pub accept_errors: u64,
    pub handshake_task_panics: u64,
    pub accept_task_panics: u64,
    pub unsafe_sources: u64,
    pub source_tracking_limited: u64,
    pub source_rate_limited: u64,
    pub global_rate_limited: u64,
    pub source_concurrency_limited: u64,
    pub global_concurrency_limited: u64,
    pub raw_accept_queue_saturated: u64,
    pub accepted_socket_setup_failures: u64,
    pub handshake_failures: u64,
    pub shutdown_timed_out: bool,
}

#[derive(Default)]
struct ListenerCounters {
    accepted_streams: AtomicU64,
    rejected_attempts: AtomicU64,
    dropped_events: AtomicU64,
    accept_errors: AtomicU64,
    handshake_task_panics: AtomicU64,
    accept_task_panics: AtomicU64,
    unsafe_sources: AtomicU64,
    source_tracking_limited: AtomicU64,
    source_rate_limited: AtomicU64,
    global_rate_limited: AtomicU64,
    source_concurrency_limited: AtomicU64,
    global_concurrency_limited: AtomicU64,
    raw_accept_queue_saturated: AtomicU64,
    accepted_socket_setup_failures: AtomicU64,
    handshake_failures: AtomicU64,
}

impl ListenerCounters {
    fn report(&self, shutdown_timed_out: bool) -> LanListenerReport {
        LanListenerReport {
            accepted_streams: self.accepted_streams.load(Ordering::Relaxed),
            rejected_attempts: self.rejected_attempts.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            accept_errors: self.accept_errors.load(Ordering::Relaxed),
            handshake_task_panics: self.handshake_task_panics.load(Ordering::Relaxed),
            accept_task_panics: self.accept_task_panics.load(Ordering::Relaxed),
            unsafe_sources: self.unsafe_sources.load(Ordering::Relaxed),
            source_tracking_limited: self.source_tracking_limited.load(Ordering::Relaxed),
            source_rate_limited: self.source_rate_limited.load(Ordering::Relaxed),
            global_rate_limited: self.global_rate_limited.load(Ordering::Relaxed),
            source_concurrency_limited: self.source_concurrency_limited.load(Ordering::Relaxed),
            global_concurrency_limited: self.global_concurrency_limited.load(Ordering::Relaxed),
            raw_accept_queue_saturated: self.raw_accept_queue_saturated.load(Ordering::Relaxed),
            accepted_socket_setup_failures: self
                .accepted_socket_setup_failures
                .load(Ordering::Relaxed),
            handshake_failures: self.handshake_failures.load(Ordering::Relaxed),
            shutdown_timed_out,
        }
    }
}

struct RawAccepted {
    stream: TcpStream,
    source: IpAddr,
}

struct SourceState {
    window_started_at: Instant,
    attempts: u32,
    in_flight: usize,
}

struct GlobalAttemptState {
    window_started_at: Instant,
    attempts: u32,
}

/// Opaque validated production LAN reachability address.
///
/// Initial policy accepts a nonzero port on RFC 1918 private IPv4 or IPv6 ULA
/// only. Wildcard, loopback, link-local, multicast, limited broadcast, and
/// public addresses fail construction. IPv6 ULA candidates must use zero scope
/// and flow-information fields. Directed-subnet broadcast detection requires
/// interface-prefix metadata and remains an outer interface-policy responsibility.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LanPeerAddress(SocketAddr);

impl LanPeerAddress {
    /// Validates a production LAN reachability candidate.
    ///
    /// # Errors
    ///
    /// Returns a coarse error unless the address satisfies the initial LAN
    /// policy and carries a nonzero port.
    pub fn new(address: SocketAddr) -> Result<Self, LanAddressError> {
        if is_safe_lan_socket(address) {
            Ok(Self(address))
        } else {
            Err(LanAddressError::Unsafe)
        }
    }

    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

impl std::fmt::Debug for LanPeerAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LanPeerAddress([REDACTED])")
    }
}

/// Rejected production LAN address without echoing the supplied endpoint.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LanAddressError {
    #[error("address is not an allowed initial LAN endpoint")]
    Unsafe,
}

/// Reusable bounded service for explicit private-IPv4 and IPv6-ULA listeners.
///
/// Listener binding is separate from execution so the caller can finish
/// composition before any socket is accepted. The returned event receiver is
/// the only path by which authenticated accepted streams leave the service.
pub struct BoundedLanListener<A>
where
    A: AuthenticatedAcceptor,
{
    acceptor: Arc<A>,
    listeners: Vec<TcpListener>,
    bound_addresses: Vec<SocketAddr>,
    config: LanListenerConfig,
    events: mpsc::Sender<LanListenerEvent<A::Stream>>,
    counters: Arc<ListenerCounters>,
}

impl<A> std::fmt::Debug for BoundedLanListener<A>
where
    A: AuthenticatedAcceptor,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundedLanListener")
            .field("listener_count", &self.listeners.len())
            .field("config", &self.config)
            .field("acceptor", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<A> BoundedLanListener<A>
where
    A: AuthenticatedAcceptor + Send + Sync + 'static,
    A::Stream: SecurePeerStream + 'static,
{
    /// Validates every requested endpoint before binding any socket.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, wildcard, zero-port, loopback, public,
    /// link-local, multicast, broadcast, or otherwise unsupported endpoints,
    /// and reports bind failures without returning their address or OS text.
    pub async fn bind(
        acceptor: A,
        bind_addresses: Vec<SocketAddr>,
        config: LanListenerConfig,
    ) -> Result<(Self, mpsc::Receiver<LanListenerEvent<A::Stream>>), LanListenerBuildError> {
        config.validate()?;
        if bind_addresses.is_empty() {
            return Err(LanListenerBuildError::MissingBindAddress);
        }
        if bind_addresses.len() > config.maximum_listeners {
            return Err(LanListenerBuildError::TooManyBindAddresses);
        }
        if bind_addresses.iter().copied().collect::<HashSet<_>>().len() != bind_addresses.len() {
            return Err(LanListenerBuildError::DuplicateBindAddress);
        }
        if bind_addresses
            .iter()
            .any(|address| !is_safe_lan_socket(*address))
        {
            return Err(LanListenerBuildError::UnsafeBindAddress);
        }

        let mut listeners = Vec::with_capacity(bind_addresses.len());
        let mut bound = Vec::with_capacity(bind_addresses.len());
        for address in bind_addresses {
            let listener = TcpListener::bind(address)
                .await
                .map_err(|error| LanListenerBuildError::BindFailed(error.kind()))?;
            bound.push(
                listener
                    .local_addr()
                    .map_err(|error| LanListenerBuildError::BindFailed(error.kind()))?,
            );
            listeners.push(listener);
        }
        let (events, event_receiver) = mpsc::channel(config.event_queue_capacity);
        Ok((
            Self {
                acceptor: Arc::new(acceptor),
                listeners,
                bound_addresses: bound,
                config,
                events,
                counters: Arc::new(ListenerCounters::default()),
            },
            event_receiver,
        ))
    }

    /// Exact endpoints successfully bound by this service.
    #[must_use]
    pub fn bound_addresses(&self) -> &[SocketAddr] {
        &self.bound_addresses
    }

    /// Accepts, rate-limits, authenticates, and emits sealed streams until
    /// shutdown. All socket and handshake tasks are owned by this future.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> LanListenerReport {
        let (raw_sender, mut raw_receiver) =
            mpsc::channel::<RawAccepted>(self.config.raw_accept_queue_capacity);
        let (accept_shutdown_sender, accept_shutdown) = watch::channel(false);
        let mut accept_tasks = JoinSet::new();
        for listener in self.listeners.drain(..) {
            accept_tasks.spawn(accept_loop(
                listener,
                raw_sender.clone(),
                Arc::clone(&self.counters),
                accept_shutdown.clone(),
            ));
        }
        drop(raw_sender);

        let mut handshake_tasks = JoinSet::new();
        let mut sources = HashMap::<IpAddr, SourceState>::new();
        let mut global_attempts = GlobalAttemptState {
            window_started_at: Instant::now(),
            attempts: 0,
        };
        loop {
            tokio::select! {
                biased;
                () = wait_for_shutdown(&mut shutdown) => break,
                () = self.events.closed() => break,
                joined = handshake_tasks.join_next(), if !handshake_tasks.is_empty() => {
                    handle_handshake_join(
                        joined,
                        &mut sources,
                        &self.events,
                        &self.counters,
                    );
                }
                accepted = raw_receiver.recv() => {
                    let Some(accepted) = accepted else {
                        break;
                    };
                    start_handshake(
                        accepted,
                        &self.acceptor,
                        self.config,
                        &mut sources,
                        &mut global_attempts,
                        &mut handshake_tasks,
                        &self.counters,
                    );
                }
                joined = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                    if joined.is_some_and(|result| result.is_err()) {
                        record_rejection(&self.counters, LanListenerRejection::AcceptTaskPanicked);
                    }
                }
            }
        }

        let deadline = Instant::now() + self.config.shutdown_timeout;
        let _ = accept_shutdown_sender.send(true);
        accept_tasks.abort_all();
        let accept_drained = drain_join_set_until(&mut accept_tasks, deadline).await;
        raw_receiver.close();
        while raw_receiver.try_recv().is_ok() {}
        handshake_tasks.abort_all();
        let handshakes_drained = drain_join_set_until(&mut handshake_tasks, deadline).await;
        self.counters
            .report(!(accept_drained && handshakes_drained))
    }
}

trait ListenerSocket: Send + 'static {
    async fn accept_next(&self) -> io::Result<(TcpStream, SocketAddr)>;
}

impl ListenerSocket for TcpListener {
    async fn accept_next(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.accept().await
    }
}

async fn accept_loop<L>(
    listener: L,
    raw: mpsc::Sender<RawAccepted>,
    counters: Arc<ListenerCounters>,
    mut shutdown: watch::Receiver<bool>,
) where
    L: ListenerSocket,
{
    let mut consecutive_errors = 0_u32;
    loop {
        tokio::select! {
            biased;
            () = wait_for_shutdown(&mut shutdown) => break,
            accepted = listener.accept_next() => if let Ok((stream, source)) = accepted {
                consecutive_errors = 0;
                if !is_safe_lan_ip(source.ip()) {
                    record_rejection(&counters, LanListenerRejection::UnsafeSource);
                    continue;
                }
                if stream.set_nodelay(true).is_err() {
                    record_rejection(
                        &counters,
                        LanListenerRejection::AcceptedSocketSetupFailed,
                    );
                    continue;
                }
                match raw.try_send(RawAccepted {
                    stream,
                    source: source.ip(),
                }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)
                    | mpsc::error::TrySendError::Closed(_)) => record_rejection(
                        &counters,
                        LanListenerRejection::RawAcceptQueueSaturated,
                    ),
                }
            } else {
                record_rejection(&counters, LanListenerRejection::AcceptFailed);
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    break;
                }
                let multiplier = 1_u32 << (consecutive_errors - 1);
                tokio::time::sleep(
                    ACCEPT_ERROR_BACKOFF_BASE
                        .saturating_mul(multiplier)
                        .min(ACCEPT_ERROR_BACKOFF_MAX),
                )
                .await;
            }
        }
    }
}

fn start_handshake<A>(
    accepted: RawAccepted,
    acceptor: &Arc<A>,
    config: LanListenerConfig,
    sources: &mut HashMap<IpAddr, SourceState>,
    global: &mut GlobalAttemptState,
    tasks: &mut JoinSet<(IpAddr, io::Result<A::Stream>)>,
    counters: &ListenerCounters,
) where
    A: AuthenticatedAcceptor + Send + Sync + 'static,
    A::Stream: SecurePeerStream + 'static,
{
    let now = Instant::now();
    if now.duration_since(global.window_started_at) >= config.attempt_window {
        global.window_started_at = now;
        global.attempts = 0;
    }
    if global.attempts >= config.maximum_global_attempts {
        record_rejection(counters, LanListenerRejection::GlobalRateLimited);
        return;
    }
    global.attempts += 1;
    sources.retain(|_, state| {
        state.in_flight > 0 || now.duration_since(state.window_started_at) < config.attempt_window
    });
    if !sources.contains_key(&accepted.source) && sources.len() >= config.maximum_tracked_sources {
        record_rejection(counters, LanListenerRejection::SourceTrackingLimited);
        return;
    }
    let source = sources.entry(accepted.source).or_insert(SourceState {
        window_started_at: now,
        attempts: 0,
        in_flight: 0,
    });
    if now.duration_since(source.window_started_at) >= config.attempt_window {
        source.window_started_at = now;
        source.attempts = 0;
    }
    if source.attempts >= config.maximum_attempts_per_source {
        record_rejection(counters, LanListenerRejection::SourceRateLimited);
        return;
    }
    source.attempts += 1;
    if source.in_flight >= config.maximum_per_source_handshakes {
        record_rejection(counters, LanListenerRejection::SourceConcurrencyLimited);
        return;
    }
    if tasks.len() >= config.maximum_outstanding_handshakes {
        record_rejection(counters, LanListenerRejection::GlobalConcurrencyLimited);
        return;
    }

    source.in_flight += 1;
    let source_ip = accepted.source;
    let acceptor = Arc::clone(acceptor);
    tasks.spawn(async move {
        let result = match timeout(config.handshake_timeout, acceptor.accept(accepted.stream)).await
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS handshake timed out",
            )),
        };
        (source_ip, result)
    });
}

fn handle_handshake_join<S>(
    joined: Option<Result<(IpAddr, io::Result<S>), tokio::task::JoinError>>,
    sources: &mut HashMap<IpAddr, SourceState>,
    events: &mpsc::Sender<LanListenerEvent<S>>,
    counters: &ListenerCounters,
) where
    S: SecurePeerStream + 'static,
{
    match joined {
        Some(Ok((source, result))) => {
            if let Some(state) = sources.get_mut(&source) {
                state.in_flight = state.in_flight.saturating_sub(1);
            }
            match result {
                Ok(stream) => match events.try_send(LanListenerEvent::Accepted { stream }) {
                    Ok(()) => {
                        counters.accepted_streams.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(
                        mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_),
                    ) => {
                        counters.rejected_attempts.fetch_add(1, Ordering::Relaxed);
                        counters.dropped_events.fetch_add(1, Ordering::Relaxed);
                    }
                },
                Err(_) => {
                    record_rejection(counters, LanListenerRejection::HandshakeFailed);
                }
            }
        }
        Some(Err(_)) => {
            // A panic cannot return its source key. The bounded source entry
            // therefore remains occupied fail-closed for this service run.
            record_rejection(counters, LanListenerRejection::HandshakeTaskPanicked);
        }
        None => {}
    }
}

fn record_rejection(counters: &ListenerCounters, reason: LanListenerRejection) {
    counters.rejected_attempts.fetch_add(1, Ordering::Relaxed);
    match reason {
        LanListenerRejection::UnsafeSource => &counters.unsafe_sources,
        LanListenerRejection::SourceTrackingLimited => &counters.source_tracking_limited,
        LanListenerRejection::SourceRateLimited => &counters.source_rate_limited,
        LanListenerRejection::GlobalRateLimited => &counters.global_rate_limited,
        LanListenerRejection::SourceConcurrencyLimited => &counters.source_concurrency_limited,
        LanListenerRejection::GlobalConcurrencyLimited => &counters.global_concurrency_limited,
        LanListenerRejection::RawAcceptQueueSaturated => &counters.raw_accept_queue_saturated,
        LanListenerRejection::AcceptedSocketSetupFailed => &counters.accepted_socket_setup_failures,
        LanListenerRejection::AcceptFailed => &counters.accept_errors,
        LanListenerRejection::HandshakeFailed => &counters.handshake_failures,
        LanListenerRejection::HandshakeTaskPanicked => &counters.handshake_task_panics,
        LanListenerRejection::AcceptTaskPanicked => &counters.accept_task_panics,
    }
    .fetch_add(1, Ordering::Relaxed);
}

async fn drain_join_set_until<T: 'static>(tasks: &mut JoinSet<T>, deadline: Instant) -> bool {
    while !tasks.is_empty() {
        if timeout_at(deadline, tasks.join_next()).await.is_err() {
            return false;
        }
    }
    true
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

fn is_safe_lan_socket(address: SocketAddr) -> bool {
    address.port() != 0
        && match address {
            SocketAddr::V4(address) => is_private_ipv4(*address.ip()),
            SocketAddr::V6(address) => {
                address.flowinfo() == 0
                    && address.scope_id() == 0
                    && is_unique_local_ipv6(*address.ip())
            }
        }
}

fn is_safe_lan_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_private_ipv4(address),
        IpAddr::V6(address) => is_unique_local_ipv6(address),
    }
}

fn is_private_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
}

fn is_unique_local_ipv6(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::sealed;
    use crate::{
        AuthenticatedLanConnector, ClientIdentityResolutionError, ConnectionDirection,
        PairedClientIdentityResolver, RustlsAcceptorConfig, RustlsClientCredentials,
        RustlsClientTrust, RustlsConnectorConfig, RustlsServerCredentials, RustlsServerTrust,
        RustlsTcpAcceptor, RustlsTcpConnector, TransportPeerIdentity,
    };
    use kvm_protocol::{WireHostId, WirePeerId};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair,
    };
    use sha2::{Digest, Sha256};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::sync::Notify;

    struct TestSecureStream {
        inner: TcpStream,
        identity: TransportPeerIdentity,
    }

    impl std::fmt::Debug for TestSecureStream {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("TestSecureStream([REDACTED])")
        }
    }

    impl sealed::SecureStream for TestSecureStream {}

    impl SecurePeerStream for TestSecureStream {
        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            &self.identity
        }

        fn connection_direction(&self) -> ConnectionDirection {
            ConnectionDirection::Inbound
        }

        fn export_keying_material(&self, _label: &[u8], _context: &[u8]) -> io::Result<[u8; 32]> {
            Ok([7; 32])
        }
    }

    impl AsyncRead for TestSecureStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for TestSecureStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    fn test_identity() -> TransportPeerIdentity {
        TransportPeerIdentity {
            host_id: WireHostId([1; 16]),
            peer_id: WirePeerId([2; 16]),
            credential_fingerprint: [3; 32],
        }
    }

    struct PassAcceptor;

    impl sealed::Acceptor for PassAcceptor {}

    impl AuthenticatedAcceptor for PassAcceptor {
        type Stream = TestSecureStream;

        fn accept(
            &self,
            stream: TcpStream,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>> {
            Box::pin(async move {
                Ok(TestSecureStream {
                    inner: stream,
                    identity: test_identity(),
                })
            })
        }
    }

    struct HoldingAcceptor {
        started: Arc<AtomicUsize>,
        release: Arc<Notify>,
    }

    impl sealed::Acceptor for HoldingAcceptor {}

    impl AuthenticatedAcceptor for HoldingAcceptor {
        type Stream = TestSecureStream;

        fn accept(
            &self,
            stream: TcpStream,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>> {
            self.started.fetch_add(1, AtomicOrdering::SeqCst);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                release.notified().await;
                Ok(TestSecureStream {
                    inner: stream,
                    identity: test_identity(),
                })
            })
        }
    }

    struct PanicAcceptor;

    impl sealed::Acceptor for PanicAcceptor {}

    impl AuthenticatedAcceptor for PanicAcceptor {
        type Stream = TestSecureStream;

        fn accept(
            &self,
            _stream: TcpStream,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>> {
            Box::pin(async move { panic!("synthetic acceptor panic") })
        }
    }

    struct FailingAcceptListener {
        failed_once: AtomicBool,
    }

    impl ListenerSocket for FailingAcceptListener {
        async fn accept_next(&self) -> io::Result<(TcpStream, SocketAddr)> {
            if self.failed_once.swap(true, AtomicOrdering::SeqCst) {
                std::future::pending().await
            } else {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "synthetic peer-controlled accept detail",
                ))
            }
        }
    }

    struct PersistentlyFailingAcceptListener;

    impl ListenerSocket for PersistentlyFailingAcceptListener {
        async fn accept_next(&self) -> io::Result<(TcpStream, SocketAddr)> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "persistent peer-controlled accept detail",
            ))
        }
    }

    struct TestPki {
        root: Vec<u8>,
        server_certificate: Vec<u8>,
        server_private_key: Vec<u8>,
        client_certificate: Vec<u8>,
        client_private_key: Vec<u8>,
    }

    impl TestPki {
        fn generate() -> Self {
            let mut root_params = CertificateParams::default();
            root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let root_key = KeyPair::generate().unwrap();
            let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();
            let server_key = KeyPair::generate().unwrap();
            let mut server_params = CertificateParams::new(vec!["kvm.test".to_owned()]).unwrap();
            server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server = server_params.signed_by(&server_key, &root).unwrap();
            let client_key = KeyPair::generate().unwrap();
            let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let client = client_params.signed_by(&client_key, &root).unwrap();
            Self {
                root: root.der().to_vec(),
                server_certificate: server.der().to_vec(),
                server_private_key: server_key.serialize_der(),
                client_certificate: client.der().to_vec(),
                client_private_key: client_key.serialize_der(),
            }
        }

        fn client_identity(&self) -> TransportPeerIdentity {
            TransportPeerIdentity {
                host_id: WireHostId([4; 16]),
                peer_id: WirePeerId([5; 16]),
                credential_fingerprint: Sha256::digest(&self.client_certificate).into(),
            }
        }

        fn server_identity(&self) -> TransportPeerIdentity {
            TransportPeerIdentity {
                host_id: WireHostId([6; 16]),
                peer_id: WirePeerId([7; 16]),
                credential_fingerprint: Sha256::digest(&self.server_certificate).into(),
            }
        }
    }

    struct FixedResolver(TransportPeerIdentity);

    impl PairedClientIdentityResolver for FixedResolver {
        fn resolve(
            &self,
            credential_fingerprint: &[u8; 32],
        ) -> Result<TransportPeerIdentity, ClientIdentityResolutionError> {
            if credential_fingerprint == &self.0.credential_fingerprint {
                Ok(self.0.clone())
            } else {
                Err(ClientIdentityResolutionError::Unknown)
            }
        }
    }

    fn private_local_ip() -> Ipv4Addr {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.connect("192.0.2.1:9").unwrap();
        let IpAddr::V4(address) = socket.local_addr().unwrap().ip() else {
            panic!("test route did not select IPv4")
        };
        assert!(is_private_ipv4(address));
        address
    }

    fn unused_private_address() -> SocketAddr {
        let listener = std::net::TcpListener::bind((private_local_ip(), 0)).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let (server, _) = listener.accept().await.unwrap();
        (client.await.unwrap().unwrap(), server)
    }

    async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
        timeout(Duration::from_secs(5), async {
            while counter.load(AtomicOrdering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_for_report_count(counter: &AtomicU64, expected: u64) {
        timeout(Duration::from_secs(5), async {
            while counter.load(AtomicOrdering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn production_address_validation_is_exact_and_debug_redacted() {
        for address in [
            "10.1.2.3:24800",
            "172.16.1.2:24800",
            "172.31.255.255:24800",
            "192.168.4.5:24800",
            "[fd00::1]:24800",
            "[fc12:3456::7]:24800",
        ] {
            let address: SocketAddr = address.parse().unwrap();
            let validated = LanPeerAddress::new(address).unwrap();
            assert_eq!(validated.socket_addr(), address);
            assert_eq!(format!("{validated:?}"), "LanPeerAddress([REDACTED])");
        }
        for address in [
            "0.0.0.0:24800",
            "10.1.2.3:0",
            "127.0.0.1:24800",
            "169.254.1.2:24800",
            "224.0.0.1:24800",
            "255.255.255.255:24800",
            "8.8.8.8:24800",
            "[::]:24800",
            "[::1]:24800",
            "[fe80::1]:24800",
            "[ff02::1]:24800",
            "[2001:db8::1]:24800",
        ] {
            assert_eq!(
                LanPeerAddress::new(address.parse().unwrap()),
                Err(LanAddressError::Unsafe)
            );
        }
        for address in [
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "fd00::1".parse().unwrap(),
                24_800,
                1,
                0,
            )),
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "fd00::1".parse().unwrap(),
                24_800,
                0,
                1,
            )),
        ] {
            assert_eq!(LanPeerAddress::new(address), Err(LanAddressError::Unsafe));
        }
    }

    #[tokio::test]
    async fn bind_validation_rejects_unsafe_duplicate_excessive_and_occupied_endpoints() {
        let config = LanListenerConfig::default();
        for address in [
            "0.0.0.0:24800",
            "127.0.0.1:24800",
            "8.8.8.8:24800",
            "[::]:24800",
            "[fe80::1]:24800",
        ] {
            assert!(matches!(
                BoundedLanListener::bind(PassAcceptor, vec![address.parse().unwrap()], config)
                    .await,
                Err(LanListenerBuildError::UnsafeBindAddress)
            ));
        }
        let address = unused_private_address();
        assert!(matches!(
            BoundedLanListener::bind(PassAcceptor, vec![address, address], config).await,
            Err(LanListenerBuildError::DuplicateBindAddress)
        ));
        let mut one = config;
        one.maximum_listeners = 1;
        assert!(matches!(
            BoundedLanListener::bind(
                PassAcceptor,
                vec![unused_private_address(), unused_private_address()],
                one,
            )
            .await,
            Err(LanListenerBuildError::TooManyBindAddresses)
        ));

        let occupied = std::net::TcpListener::bind(address).unwrap();
        assert!(matches!(
            BoundedLanListener::bind(PassAcceptor, vec![address], config).await,
            Err(LanListenerBuildError::BindFailed(_))
        ));
        drop(occupied);
    }

    #[test]
    fn every_configured_resource_and_duration_is_hard_bounded() {
        let valid = LanListenerConfig::default();
        assert_eq!(valid.validate(), Ok(()));
        let mut invalid = valid;
        invalid.maximum_global_attempts = 0;
        assert_eq!(invalid.validate(), Err(LanListenerConfigError::ZeroBound));
        let mut invalid = valid;
        invalid.event_queue_capacity = HARD_MAX_EVENT_QUEUE + 1;
        assert_eq!(
            invalid.validate(),
            Err(LanListenerConfigError::BoundTooLarge)
        );
        let mut invalid = valid;
        invalid.maximum_outstanding_handshakes = 1;
        invalid.maximum_per_source_handshakes = 2;
        assert_eq!(
            invalid.validate(),
            Err(LanListenerConfigError::InvalidConcurrencyRelationship)
        );
        let mut invalid = valid;
        invalid.shutdown_timeout = Duration::ZERO;
        assert_eq!(
            invalid.validate(),
            Err(LanListenerConfigError::InvalidDuration)
        );
    }

    #[tokio::test]
    async fn actual_tls_listener_rejects_plaintext_then_emits_only_authenticated_stream() {
        let pki = TestPki::generate();
        let client_identity = pki.client_identity();
        let acceptor = RustlsTcpAcceptor::new(
            RustlsServerCredentials::new(
                vec![pki.server_certificate.clone()],
                pki.server_private_key.clone(),
            ),
            RustlsClientTrust::new(vec![pki.root.clone()]),
            FixedResolver(client_identity.clone()),
            RustlsAcceptorConfig::default(),
        )
        .unwrap();
        let address = unused_private_address();
        let (listener, mut events) =
            BoundedLanListener::bind(acceptor, vec![address], LanListenerConfig::default())
                .await
                .unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let service = tokio::spawn(listener.run(shutdown));

        let mut plaintext = TcpStream::connect(address).await.unwrap();
        plaintext.write_all(b"not tls").await.unwrap();
        plaintext.shutdown().await.unwrap();

        let mut connector = RustlsTcpConnector::new(
            RustlsClientCredentials::new(
                vec![pki.client_certificate.clone()],
                pki.client_private_key.clone(),
            ),
            RustlsServerTrust::new(vec![pki.root.clone()]),
            "kvm.test".to_owned(),
            pki.server_identity(),
            RustlsConnectorConfig::default(),
        )
        .unwrap();
        let client = connector
            .connect_lan(LanPeerAddress::new(address).unwrap())
            .await
            .unwrap();
        let LanListenerEvent::Accepted { stream: accepted } =
            timeout(Duration::from_secs(2), events.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(accepted.authenticated_peer_identity(), &client_identity);
        assert_eq!(
            accepted.connection_direction(),
            ConnectionDirection::Inbound
        );
        assert_eq!(
            client
                .export_keying_material(b"EXPORTER-listener-test", b"context")
                .unwrap(),
            accepted
                .export_keying_material(b"EXPORTER-listener-test", b"context")
                .unwrap()
        );

        shutdown_sender.send(true).unwrap();
        let report = service.await.unwrap();
        assert_eq!(report.accepted_streams, 1);
        assert!(report.handshake_failures >= 1);
        assert!(!report.shutdown_timed_out);
    }

    #[tokio::test]
    async fn source_and_global_limits_run_before_expensive_acceptor_work() {
        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let acceptor = Arc::new(HoldingAcceptor {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        });
        let config = LanListenerConfig {
            maximum_outstanding_handshakes: 2,
            maximum_per_source_handshakes: 1,
            maximum_attempts_per_source: 8,
            maximum_global_attempts: 8,
            ..LanListenerConfig::default()
        };
        let mut sources = HashMap::new();
        let mut global = GlobalAttemptState {
            window_started_at: Instant::now(),
            attempts: 0,
        };
        let mut tasks = JoinSet::new();
        let counters = ListenerCounters::default();
        let (client_one, server_one) = tcp_pair().await;
        let (client_two, server_two) = tcp_pair().await;
        start_handshake(
            RawAccepted {
                stream: server_one,
                source: "10.1.1.1".parse().unwrap(),
            },
            &acceptor,
            config,
            &mut sources,
            &mut global,
            &mut tasks,
            &counters,
        );
        start_handshake(
            RawAccepted {
                stream: server_two,
                source: "10.1.1.1".parse().unwrap(),
            },
            &acceptor,
            config,
            &mut sources,
            &mut global,
            &mut tasks,
            &counters,
        );
        wait_for_count(&started, 1).await;
        assert_eq!(
            counters.source_concurrency_limited.load(Ordering::Relaxed),
            1
        );

        let (client_three, server_three) = tcp_pair().await;
        let mut rate_config = config;
        rate_config.maximum_global_attempts = 2;
        start_handshake(
            RawAccepted {
                stream: server_three,
                source: "10.1.1.2".parse().unwrap(),
            },
            &acceptor,
            rate_config,
            &mut sources,
            &mut global,
            &mut tasks,
            &counters,
        );
        assert_eq!(counters.global_rate_limited.load(Ordering::Relaxed), 1);
        assert_eq!(started.load(AtomicOrdering::SeqCst), 1);

        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop((client_one, client_two, client_three));
    }

    #[tokio::test]
    async fn per_source_rate_and_global_concurrency_are_independently_enforced() {
        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let acceptor = Arc::new(HoldingAcceptor {
            started: Arc::clone(&started),
            release,
        });
        let rate_config = LanListenerConfig {
            maximum_attempts_per_source: 1,
            maximum_global_attempts: 8,
            maximum_outstanding_handshakes: 2,
            maximum_per_source_handshakes: 2,
            ..LanListenerConfig::default()
        };
        let mut sources = HashMap::new();
        let mut global = GlobalAttemptState {
            window_started_at: Instant::now(),
            attempts: 0,
        };
        let mut tasks = JoinSet::new();
        let counters = ListenerCounters::default();
        let (client_one, server_one) = tcp_pair().await;
        let (client_two, server_two) = tcp_pair().await;
        for stream in [server_one, server_two] {
            start_handshake(
                RawAccepted {
                    stream,
                    source: "10.2.2.2".parse().unwrap(),
                },
                &acceptor,
                rate_config,
                &mut sources,
                &mut global,
                &mut tasks,
                &counters,
            );
        }
        wait_for_count(&started, 1).await;
        assert_eq!(counters.source_rate_limited.load(Ordering::Relaxed), 1);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}

        let concurrency_config = LanListenerConfig {
            maximum_attempts_per_source: 8,
            maximum_global_attempts: 8,
            maximum_outstanding_handshakes: 1,
            maximum_per_source_handshakes: 1,
            ..LanListenerConfig::default()
        };
        let mut sources = HashMap::new();
        let mut global = GlobalAttemptState {
            window_started_at: Instant::now(),
            attempts: 0,
        };
        let mut tasks = JoinSet::new();
        let counters = ListenerCounters::default();
        let (client_three, server_three) = tcp_pair().await;
        let (client_four, server_four) = tcp_pair().await;
        for (stream, source) in [(server_three, "10.3.3.3"), (server_four, "10.3.3.4")] {
            start_handshake(
                RawAccepted {
                    stream,
                    source: source.parse().unwrap(),
                },
                &acceptor,
                concurrency_config,
                &mut sources,
                &mut global,
                &mut tasks,
                &counters,
            );
        }
        assert_eq!(
            counters.global_concurrency_limited.load(Ordering::Relaxed),
            1
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop((client_one, client_two, client_three, client_four));
    }

    #[tokio::test]
    async fn rejection_flood_cannot_consume_authenticated_stream_queue() {
        let counters = ListenerCounters::default();
        for _ in 0..10_000 {
            record_rejection(&counters, LanListenerRejection::HandshakeFailed);
        }
        let (sender, mut receiver) = mpsc::channel(1);
        let (client, server) = tcp_pair().await;
        handle_handshake_join(
            Some(Ok((
                "10.1.1.1".parse().unwrap(),
                Ok(TestSecureStream {
                    inner: server,
                    identity: test_identity(),
                }),
            ))),
            &mut HashMap::new(),
            &sender,
            &counters,
        );
        assert!(matches!(
            receiver.recv().await,
            Some(LanListenerEvent::Accepted { .. })
        ));
        assert_eq!(counters.accepted_streams.load(Ordering::Relaxed), 1);
        assert_eq!(counters.dropped_events.load(Ordering::Relaxed), 0);
        drop(client);
    }

    #[tokio::test]
    async fn accepted_queue_saturation_drops_streams_and_reports_counts() {
        let address = unused_private_address();
        let config = LanListenerConfig {
            event_queue_capacity: 1,
            ..LanListenerConfig::default()
        };
        let (listener, mut events) = BoundedLanListener::bind(PassAcceptor, vec![address], config)
            .await
            .unwrap();
        let counters = Arc::clone(&listener.counters);
        let (shutdown_sender, shutdown) = watch::channel(false);
        let service = tokio::spawn(listener.run(shutdown));
        let mut clients = Vec::new();
        for _ in 0..8 {
            clients.push(TcpStream::connect(address).await.unwrap());
        }
        timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(LanListenerEvent::Accepted { .. }) = events.try_recv() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        wait_for_report_count(&counters.dropped_events, 1).await;
        shutdown_sender.send(true).unwrap();
        let report = service.await.unwrap();
        assert!(report.accepted_streams >= 1);
        assert!(report.dropped_events >= 1);
        drop(clients);
    }

    #[tokio::test]
    async fn shutdown_cancels_and_drains_inflight_handshake_without_emitting_stream() {
        let address = unused_private_address();
        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let acceptor = HoldingAcceptor {
            started: Arc::clone(&started),
            release,
        };
        let (listener, mut events) =
            BoundedLanListener::bind(acceptor, vec![address], LanListenerConfig::default())
                .await
                .unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let service = tokio::spawn(listener.run(shutdown));
        let mut client = TcpStream::connect(address).await.unwrap();
        wait_for_count(&started, 1).await;
        shutdown_sender.send(true).unwrap();
        let report = service.await.unwrap();
        assert!(!report.shutdown_timed_out);
        assert!(events.recv().await.is_none());
        let mut byte = [0_u8; 1];
        assert!(timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn handshake_timeout_releases_capacity_without_emitting_stream() {
        let address = unused_private_address();
        let started = Arc::new(AtomicUsize::new(0));
        let acceptor = HoldingAcceptor {
            started: Arc::clone(&started),
            release: Arc::new(Notify::new()),
        };
        let config = LanListenerConfig {
            maximum_outstanding_handshakes: 1,
            maximum_per_source_handshakes: 1,
            handshake_timeout: Duration::from_millis(10),
            ..LanListenerConfig::default()
        };
        let (listener, mut events) = BoundedLanListener::bind(acceptor, vec![address], config)
            .await
            .unwrap();
        let counters = Arc::clone(&listener.counters);
        let (shutdown_sender, shutdown) = watch::channel(false);
        let service = tokio::spawn(listener.run(shutdown));
        let _client = TcpStream::connect(address).await.unwrap();
        wait_for_count(&started, 1).await;
        wait_for_report_count(&counters.handshake_failures, 1).await;
        let _second_client = TcpStream::connect(address).await.unwrap();
        wait_for_count(&started, 2).await;
        shutdown_sender.send(true).unwrap();
        let report = service.await.unwrap();
        assert!(report.handshake_failures >= 1);
        assert_eq!(report.accepted_streams, 0);
        assert!(events.recv().await.is_none());
    }

    #[tokio::test]
    async fn dropping_the_only_stream_receiver_stops_and_drains_the_service() {
        let address = unused_private_address();
        let started = Arc::new(AtomicUsize::new(0));
        let acceptor = HoldingAcceptor {
            started: Arc::clone(&started),
            release: Arc::new(Notify::new()),
        };
        let (listener, events) =
            BoundedLanListener::bind(acceptor, vec![address], LanListenerConfig::default())
                .await
                .unwrap();
        let (_shutdown_sender, shutdown) = watch::channel(false);
        let service = tokio::spawn(listener.run(shutdown));
        let mut client = TcpStream::connect(address).await.unwrap();
        wait_for_count(&started, 1).await;
        drop(events);
        let report = timeout(Duration::from_secs(1), service)
            .await
            .unwrap()
            .unwrap();
        assert!(!report.shutdown_timed_out);
        assert_eq!(report.accepted_streams, 0);
        let mut byte = [0_u8; 1];
        assert!(timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn handshake_task_panic_is_contained_and_redacted() {
        let address = unused_private_address();
        let (listener, _events) =
            BoundedLanListener::bind(PanicAcceptor, vec![address], LanListenerConfig::default())
                .await
                .unwrap();
        let counters = Arc::clone(&listener.counters);
        let (shutdown_sender, shutdown) = watch::channel(false);
        let service = tokio::spawn(listener.run(shutdown));
        let _client = TcpStream::connect(address).await.unwrap();
        wait_for_report_count(&counters.handshake_task_panics, 1).await;
        shutdown_sender.send(true).unwrap();
        let report = service.await.unwrap();
        assert_eq!(report.handshake_task_panics, 1);
        assert_eq!(report.rejected_attempts, 1);
        assert!(!format!("{report:?}").contains("synthetic acceptor panic"));
    }

    #[tokio::test]
    async fn accept_errors_are_counted_coarsely_and_shutdown_remains_interruptible() {
        let listener = FailingAcceptListener {
            failed_once: AtomicBool::new(false),
        };
        let (raw_sender, _raw_receiver) = mpsc::channel(1);
        let counters = Arc::new(ListenerCounters::default());
        let (shutdown_sender, shutdown) = watch::channel(false);
        let task = tokio::spawn(accept_loop(
            listener,
            raw_sender,
            Arc::clone(&counters),
            shutdown,
        ));
        timeout(Duration::from_secs(1), async {
            while counters.accept_errors.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        shutdown_sender.send(true).unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let report = counters.report(false);
        assert_eq!(report.accept_errors, 1);
        assert_eq!(report.rejected_attempts, 1);
        assert!(!format!("{report:?}").contains("synthetic peer-controlled accept detail"));
    }

    #[tokio::test]
    async fn persistent_accept_errors_trip_the_bounded_terminal_circuit() {
        let (raw_sender, _raw_receiver) = mpsc::channel(1);
        let counters = Arc::new(ListenerCounters::default());
        let (_shutdown_sender, shutdown) = watch::channel(false);
        let task = tokio::spawn(accept_loop(
            PersistentlyFailingAcceptListener,
            raw_sender,
            Arc::clone(&counters),
            shutdown,
        ));
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let report = counters.report(false);
        assert_eq!(
            report.accept_errors,
            u64::from(MAX_CONSECUTIVE_ACCEPT_ERRORS)
        );
        assert_eq!(report.rejected_attempts, report.accept_errors);
        assert!(!format!("{report:?}").contains("persistent peer-controlled accept detail"));
    }
}
