use kvm_protocol::{PingV1, PongV1, WireMessage};
use std::collections::BTreeMap;
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerState {
    Connecting,
    Healthy,
    Degraded,
    Disconnected,
}

/// Observable liveness data. Times are durations from the daemon's monotonic
/// clock origin and are therefore safe from wall-clock adjustments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerHealth {
    pub state: PeerState,
    pub connected_at: Option<Duration>,
    pub last_received_at: Option<Duration>,
    pub last_sent_at: Option<Duration>,
    pub last_pong_at: Option<Duration>,
    pub last_rtt: Option<Duration>,
}

impl Default for PeerHealth {
    fn default() -> Self {
        Self {
            state: PeerState::Connecting,
            connected_at: None,
            last_received_at: None,
            last_sent_at: None,
            last_pong_at: None,
            last_rtt: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatConfig {
    pub interval: Duration,
    pub degraded_after: Duration,
    pub disconnect_after: Duration,
    pub maximum_outstanding_pings: usize,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            degraded_after: Duration::from_secs(3),
            disconnect_after: Duration::from_secs(8),
            maximum_outstanding_pings: 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HeartbeatConfigError {
    #[error("heartbeat interval must be positive")]
    ZeroInterval,
    #[error("degraded threshold must cover at least one heartbeat interval")]
    InvalidDegradedThreshold,
    #[error("disconnect threshold must exceed degraded threshold")]
    InvalidDisconnectThreshold,
    #[error("maximum outstanding pings must be positive")]
    ZeroOutstandingPingBound,
}

impl HeartbeatConfig {
    /// Validates timing relationships and the outstanding-ping memory bound.
    ///
    /// # Errors
    ///
    /// Returns a specific error for the first invalid value.
    pub fn validate(&self) -> Result<(), HeartbeatConfigError> {
        if self.interval == Duration::ZERO {
            return Err(HeartbeatConfigError::ZeroInterval);
        }
        if self.degraded_after < self.interval {
            return Err(HeartbeatConfigError::InvalidDegradedThreshold);
        }
        if self.disconnect_after <= self.degraded_after {
            return Err(HeartbeatConfigError::InvalidDisconnectThreshold);
        }
        if self.maximum_outstanding_pings == 0 {
            return Err(HeartbeatConfigError::ZeroOutstandingPingBound);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum HeartbeatAction {
    Send(WireMessage),
    StateChanged(PeerState),
    Disconnect,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HeartbeatError {
    #[error("pong nonce {0} does not match an outstanding ping")]
    UnknownPong(u64),
    #[error("pong {nonce} echoed an invalid send timestamp")]
    MismatchedTimestamp { nonce: u64 },
}

/// Drives ping/pong generation and peer health over a caller-provided
/// monotonic clock.
#[derive(Debug)]
pub struct HeartbeatController {
    config: HeartbeatConfig,
    health: PeerHealth,
    next_ping_at: Option<Duration>,
    next_nonce: u64,
    outstanding: BTreeMap<u64, (Duration, u64)>,
}

impl HeartbeatController {
    /// Creates a controller with validated timing relationships.
    ///
    /// # Panics
    ///
    /// Panics when the interval is zero, the degraded threshold is shorter
    /// than one interval, the disconnect threshold does not exceed the
    /// degraded threshold, or the outstanding-ping bound is zero.
    pub fn new(config: HeartbeatConfig) -> Self {
        assert!(config.validate().is_ok(), "invalid heartbeat configuration");
        Self::new_validated(config)
    }

    /// Creates a controller after fallible configuration validation.
    ///
    /// # Errors
    ///
    /// Returns a specific heartbeat configuration error.
    pub fn try_new(config: HeartbeatConfig) -> Result<Self, HeartbeatConfigError> {
        config.validate()?;
        Ok(Self::new_validated(config))
    }

    fn new_validated(config: HeartbeatConfig) -> Self {
        Self {
            config,
            health: PeerHealth::default(),
            next_ping_at: None,
            next_nonce: 1,
            outstanding: BTreeMap::new(),
        }
    }

    pub const fn health(&self) -> &PeerHealth {
        &self.health
    }

    pub fn connected(&mut self, now: Duration) {
        self.health = PeerHealth {
            state: PeerState::Healthy,
            connected_at: Some(now),
            last_received_at: Some(now),
            last_sent_at: None,
            last_pong_at: None,
            last_rtt: None,
        };
        self.next_ping_at = Some(now.saturating_add(self.config.interval));
        self.outstanding.clear();
    }

    /// Evaluates deadlines and creates any ping due at `now`.
    pub fn poll(&mut self, now: Duration) -> Vec<HeartbeatAction> {
        if self.health.state == PeerState::Disconnected {
            return Vec::new();
        }

        let mut actions = Vec::with_capacity(2);
        if let Some(last_received) = self.health.last_received_at {
            let silence = now.saturating_sub(last_received);
            if silence >= self.config.disconnect_after {
                self.health.state = PeerState::Disconnected;
                self.outstanding.clear();
                actions.push(HeartbeatAction::StateChanged(PeerState::Disconnected));
                actions.push(HeartbeatAction::Disconnect);
                return actions;
            }
            if silence >= self.config.degraded_after && self.health.state != PeerState::Degraded {
                self.health.state = PeerState::Degraded;
                actions.push(HeartbeatAction::StateChanged(PeerState::Degraded));
            }
        }

        if self.next_ping_at.is_some_and(|due| now >= due)
            && self.outstanding.len() < self.config.maximum_outstanding_pings
        {
            let sent_at_ns = duration_ns(now);
            let nonce = self.next_nonce;
            self.next_nonce = self.next_nonce.wrapping_add(1);
            self.outstanding.insert(nonce, (now, sent_at_ns));
            self.health.last_sent_at = Some(now);
            self.next_ping_at = Some(now.saturating_add(self.config.interval));
            actions.push(HeartbeatAction::Send(WireMessage::Ping(PingV1 {
                nonce,
                sent_at_ns,
            })));
        }
        actions
    }

    /// Records any valid inbound message and handles heartbeat messages.
    /// Returns a pong to send when the peer supplied a ping.
    ///
    /// # Errors
    ///
    /// Rejects unsolicited pongs and pongs that do not echo the exact ping
    /// timestamp, preventing unrelated traffic from corrupting RTT metrics.
    pub fn on_message(
        &mut self,
        message: &WireMessage,
        now: Duration,
    ) -> Result<Option<WireMessage>, HeartbeatError> {
        self.health.last_received_at = Some(now);
        if self.health.state == PeerState::Degraded {
            self.health.state = PeerState::Healthy;
        }

        match message {
            WireMessage::Ping(ping) => Ok(Some(WireMessage::Pong(PongV1 {
                nonce: ping.nonce,
                ping_sent_at_ns: ping.sent_at_ns,
                received_at_ns: duration_ns(now),
            }))),
            WireMessage::Pong(pong) => {
                let Some(&(sent_at, wire_sent_at)) = self.outstanding.get(&pong.nonce) else {
                    return Err(HeartbeatError::UnknownPong(pong.nonce));
                };
                if wire_sent_at != pong.ping_sent_at_ns {
                    return Err(HeartbeatError::MismatchedTimestamp { nonce: pong.nonce });
                }
                self.outstanding.remove(&pong.nonce);
                self.health.last_pong_at = Some(now);
                self.health.last_rtt = Some(now.saturating_sub(sent_at));
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

impl Default for HeartbeatController {
    fn default() -> Self {
        Self::new(HeartbeatConfig::default())
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> HeartbeatConfig {
        HeartbeatConfig {
            interval: Duration::from_secs(1),
            degraded_after: Duration::from_secs(3),
            disconnect_after: Duration::from_secs(5),
            maximum_outstanding_pings: 4,
        }
    }

    #[test]
    fn ping_pong_updates_rtt_and_restores_health() {
        let mut heartbeat = HeartbeatController::new(config());
        heartbeat.connected(Duration::ZERO);
        let actions = heartbeat.poll(Duration::from_secs(1));
        let ping = match &actions[0] {
            HeartbeatAction::Send(WireMessage::Ping(ping)) => *ping,
            other => panic!("unexpected action: {other:?}"),
        };
        let response_message = WireMessage::Pong(PongV1 {
            nonce: ping.nonce,
            ping_sent_at_ns: ping.sent_at_ns,
            received_at_ns: 1_100_000_000,
        });
        heartbeat
            .on_message(&response_message, Duration::from_millis(1_250))
            .unwrap();

        assert_eq!(heartbeat.health().state, PeerState::Healthy);
        assert_eq!(
            heartbeat.health().last_rtt,
            Some(Duration::from_millis(250))
        );
    }

    #[test]
    fn silence_degrades_then_disconnects() {
        let mut heartbeat = HeartbeatController::new(config());
        heartbeat.connected(Duration::from_secs(10));

        let degraded = heartbeat.poll(Duration::from_secs(13));
        assert!(degraded.contains(&HeartbeatAction::StateChanged(PeerState::Degraded)));
        assert_eq!(heartbeat.health().state, PeerState::Degraded);

        let disconnected = heartbeat.poll(Duration::from_secs(15));
        assert_eq!(
            disconnected,
            vec![
                HeartbeatAction::StateChanged(PeerState::Disconnected),
                HeartbeatAction::Disconnect,
            ]
        );
        assert_eq!(heartbeat.health().state, PeerState::Disconnected);
    }

    #[test]
    fn responds_to_ping_with_echoed_values() {
        let mut heartbeat = HeartbeatController::new(config());
        heartbeat.connected(Duration::ZERO);
        let response = heartbeat
            .on_message(
                &WireMessage::Ping(PingV1 {
                    nonce: 42,
                    sent_at_ns: 7,
                }),
                Duration::from_nanos(11),
            )
            .unwrap();
        assert_eq!(
            response,
            Some(WireMessage::Pong(PongV1 {
                nonce: 42,
                ping_sent_at_ns: 7,
                received_at_ns: 11,
            }))
        );
    }

    #[test]
    fn reconnect_clears_old_outstanding_pings() {
        let mut heartbeat = HeartbeatController::new(config());
        heartbeat.connected(Duration::ZERO);
        heartbeat.poll(Duration::from_secs(1));
        heartbeat.poll(Duration::from_secs(5));
        heartbeat.connected(Duration::from_secs(6));

        let stale = WireMessage::Pong(PongV1 {
            nonce: 1,
            ping_sent_at_ns: 1_000_000_000,
            received_at_ns: 6_000_000_000,
        });
        assert_eq!(
            heartbeat.on_message(&stale, Duration::from_secs(6)),
            Err(HeartbeatError::UnknownPong(1))
        );
        assert_eq!(heartbeat.health().state, PeerState::Healthy);
        assert_eq!(heartbeat.health().last_rtt, None);
    }

    #[test]
    fn invalid_echo_does_not_consume_the_outstanding_ping() {
        let mut heartbeat = HeartbeatController::new(config());
        heartbeat.connected(Duration::ZERO);
        let actions = heartbeat.poll(Duration::from_secs(1));
        let ping = match &actions[0] {
            HeartbeatAction::Send(WireMessage::Ping(ping)) => *ping,
            other => panic!("unexpected action: {other:?}"),
        };

        let invalid_response = WireMessage::Pong(PongV1 {
            nonce: ping.nonce,
            ping_sent_at_ns: ping.sent_at_ns + 1,
            received_at_ns: 1_100_000_000,
        });
        assert_eq!(
            heartbeat.on_message(&invalid_response, Duration::from_millis(1_100)),
            Err(HeartbeatError::MismatchedTimestamp { nonce: ping.nonce })
        );

        let valid_response = WireMessage::Pong(PongV1 {
            nonce: ping.nonce,
            ping_sent_at_ns: ping.sent_at_ns,
            received_at_ns: 1_200_000_000,
        });
        assert_eq!(
            heartbeat.on_message(&valid_response, Duration::from_millis(1_200)),
            Ok(None)
        );
        assert_eq!(
            heartbeat.health().last_rtt,
            Some(Duration::from_millis(200))
        );
    }

    #[test]
    fn outstanding_pings_are_strictly_bounded() {
        let mut bounded = config();
        bounded.maximum_outstanding_pings = 2;
        let mut heartbeat = HeartbeatController::new(bounded);
        heartbeat.connected(Duration::ZERO);

        assert!(matches!(
            heartbeat.poll(Duration::from_secs(1)).as_slice(),
            [HeartbeatAction::Send(WireMessage::Ping(_))]
        ));
        assert!(matches!(
            heartbeat.poll(Duration::from_secs(2)).as_slice(),
            [HeartbeatAction::Send(WireMessage::Ping(_))]
        ));
        assert!(heartbeat.poll(Duration::from_millis(2_500)).is_empty());
        assert_eq!(heartbeat.outstanding.len(), 2);
    }

    #[test]
    fn fallible_constructor_rejects_invalid_config() {
        let mut invalid = config();
        invalid.maximum_outstanding_pings = 0;
        assert!(matches!(
            HeartbeatController::try_new(invalid),
            Err(HeartbeatConfigError::ZeroOutstandingPingBound)
        ));
    }
}
