//! Development-only input-event-rate instrumentation (spec §35 "input event
//! rate").
//!
//! Gated by the `event-rate` Cargo feature (off by default). Provides a
//! lock-free sliding-window meter that answers "input events per second right
//! now" in a single read — the §35 metric flagged absent in the cycle-7 audit.
//!
//! Hard constraints honoured:
//! - **Development-only.** Compiled only with `--features event-rate`; release
//!   builds pay nothing.
//! - **No disk I/O.** The meter is an in-memory ring of atomic buckets.
//! - **Hot-path safe.** [`EventRateMeter::record`] is a single atomic
//!   read-modify-write with no locks and no allocation. Time is passed in by the
//!   caller as monotonic nanoseconds (the same origin as
//!   [`crate::InputEvent::timestamp_ns`]), so recording can reuse the capture
//!   timestamp instead of reading the clock a second time.
//!
//! The meter doubles as a monotonic counter ([`EventRateMeter::total_events`])
//! for counter-style sampling (delta-over-time), the idiomatic diagnostics
//! pattern. This module provides the meter only; exposing it to the control
//! panel is deferred to the diagnostics surface (itself blocked on the daemon
//! IPC transport — see cycle-9 audit).

// `now_ns`/`now_ms`/`now_epoch` intentionally distinguish the time unit at the
// binding site; the ns↔ms distinction is the whole point.
#![allow(clippy::similar_names)]

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

const COUNT_MASK: u64 = 0xFFFF_FFFF;
const EPOCH_SHIFT: u32 = 32;

#[inline]
fn pack(epoch: u32, count: u32) -> u64 {
    (u64::from(epoch) << EPOCH_SHIFT) | u64::from(count)
}

#[inline]
fn high32(value: u64) -> u32 {
    u32::try_from(value >> EPOCH_SHIFT).unwrap_or(u32::MAX)
}

#[inline]
fn low32(value: u64) -> u32 {
    u32::try_from(value & COUNT_MASK).unwrap_or(u32::MAX)
}

/// Sliding-window configuration for [`EventRateMeter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventRateConfig {
    /// Width of each bucket in milliseconds.
    pub bucket_ms: u64,
    /// Number of buckets in the ring. The window spans
    /// `bucket_ms * bucket_count` milliseconds.
    pub bucket_count: usize,
}

impl Default for EventRateConfig {
    fn default() -> Self {
        // A 6-second window in 100 ms buckets — coarse enough to smooth jitter,
        // short enough to feel current.
        Self {
            bucket_ms: 100,
            bucket_count: 60,
        }
    }
}

/// Error raised by invalid [`EventRateConfig`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRateConfigError;

impl std::fmt::Display for EventRateConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bucket_ms must be positive and bucket_count >= 2")
    }
}

impl std::error::Error for EventRateConfigError {}

impl EventRateConfig {
    /// Validates the window shape.
    ///
    /// # Errors
    ///
    /// Returns [`EventRateConfigError`] when `bucket_ms == 0` or
    /// `bucket_count < 2` (a single bucket is a cumulative total, not a window).
    pub fn validate(self) -> Result<(), EventRateConfigError> {
        if self.bucket_ms == 0 || self.bucket_count < 2 {
            Err(EventRateConfigError)
        } else {
            Ok(())
        }
    }

    /// Total window length in nanoseconds.
    #[must_use]
    pub fn window_ns(self) -> u64 {
        self.bucket_ms
            .saturating_mul(self.bucket_count as u64)
            .saturating_mul(1_000_000)
    }
}

/// One input-event-rate sample over the configured window.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventRateSnapshot {
    /// Events counted within the current window.
    pub window_events: u64,
    /// Monotonically increasing total since the meter was created or reset.
    pub total_events: u64,
    /// Window length in seconds.
    pub window_seconds: f64,
    /// `window_events / window_seconds`.
    pub events_per_second: f64,
}

/// Lock-free sliding-window input-event-rate meter (spec §35).
///
/// Buckets are a ring indexed by `now_ms / bucket_ms`; each bucket packs its
/// owning epoch and its count into one [`AtomicU64`] so updates are a single
/// compare-exchange with no locking. Recording reuses a caller-supplied
/// monotonic timestamp, so the hot path reads no clock of its own.
#[derive(Debug)]
pub struct EventRateMeter {
    buckets: Vec<AtomicU64>,
    total: AtomicU64,
    config: EventRateConfig,
}

impl EventRateMeter {
    /// Creates a meter, panicking on an invalid config.
    ///
    /// Prefer [`Self::try_new`] for externally supplied configuration.
    ///
    /// # Panics
    ///
    /// Panics when the configuration fails [`EventRateConfig::validate`].
    #[must_use]
    pub fn new(config: EventRateConfig) -> Self {
        assert!(
            config.validate().is_ok(),
            "invalid event-rate configuration"
        );
        Self::new_validated(config)
    }

    /// Fallible constructor.
    ///
    /// # Errors
    ///
    /// Returns [`EventRateConfigError`] for an invalid configuration.
    pub fn try_new(config: EventRateConfig) -> Result<Self, EventRateConfigError> {
        config.validate()?;
        Ok(Self::new_validated(config))
    }

    fn new_validated(config: EventRateConfig) -> Self {
        let mut buckets = Vec::with_capacity(config.bucket_count);
        buckets.resize_with(config.bucket_count, || AtomicU64::new(0));
        Self {
            buckets,
            total: AtomicU64::new(0),
            config,
        }
    }

    /// Records one event at monotonic time `now_ns`.
    ///
    /// Reuse the event's capture timestamp (`InputEvent::timestamp_ns`) here so
    /// the hot path does not read a clock. The update is a single lock-free
    /// compare-exchange.
    pub fn record(&self, now_ns: u64) {
        let now_ms = now_ns / 1_000_000;
        let epoch = u32::try_from(now_ms / self.config.bucket_ms).unwrap_or(u32::MAX);
        let idx = (epoch as usize) % self.config.bucket_count;
        let slot = &self.buckets[idx];
        let reset = pack(epoch, 1);
        let mut current = slot.load(Ordering::Relaxed);
        loop {
            let new = if high32(current) == epoch {
                // Same epoch: increment the low (count) half. `current + 1`
                // cannot carry into the epoch half because we saturate below.
                if low32(current) == u32::MAX {
                    return; // bucket count saturated; drop this event's count
                }
                current + 1
            } else {
                reset
            };
            match slot.compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    /// Monotonically increasing total events recorded since creation or
    /// [`Self::reset`].
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Events counted within the trailing window ending at `now_ns`.
    #[must_use]
    pub fn events_in_window(&self, now_ns: u64) -> u64 {
        let now_ms = now_ns / 1_000_000;
        let now_epoch = u32::try_from(now_ms / self.config.bucket_ms).unwrap_or(u32::MAX);
        let span = u32::try_from(self.config.bucket_count).unwrap_or(u32::MAX);
        let mut total = 0u64;
        for slot in &self.buckets {
            let packed = slot.load(Ordering::Relaxed);
            let epoch = high32(packed);
            // Age in bucket units; wrapping-sub excludes future/stale epochs.
            if now_epoch.wrapping_sub(epoch) < span {
                total += u64::from(low32(packed));
            }
        }
        total
    }

    /// Events per second over the trailing window at `now_ns`.
    #[must_use]
    pub fn events_per_second(&self, now_ns: u64) -> f64 {
        let window_ns = self.config.window_ns();
        let seconds = f64::from(u32::try_from(window_ns / 1_000_000_000).unwrap_or(u32::MAX));
        if seconds <= 0.0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.events_in_window(now_ns)).unwrap_or(u32::MAX)) / seconds
        // NOTE: u32 cast on window_events is bounded by realistic event rates;
        // for pathological rates use `events_in_window` / `total_events` directly.
    }

    /// A full snapshot over the window at `now_ns`.
    #[must_use]
    pub fn snapshot(&self, now_ns: u64) -> EventRateSnapshot {
        let window_seconds =
            f64::from(u32::try_from(self.config.window_ns() / 1_000_000_000).unwrap_or(u32::MAX));
        let window_events = self.events_in_window(now_ns);
        let total_events = self.total_events();
        let events_per_second = if window_seconds > 0.0 {
            f64::from(u32::try_from(window_events).unwrap_or(u32::MAX)) / window_seconds
        } else {
            0.0
        };
        EventRateSnapshot {
            window_events,
            total_events,
            window_seconds,
            events_per_second,
        }
    }

    /// Clears all buckets and the running total.
    pub fn reset(&self) {
        for slot in &self.buckets {
            slot.store(0, Ordering::Relaxed);
        }
        self.total.store(0, Ordering::Relaxed);
    }
}

impl Default for EventRateMeter {
    fn default() -> Self {
        Self::new(EventRateConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn default_config_is_a_six_second_window() {
        let meter = EventRateMeter::default();
        assert_eq!(meter.config.window_ns(), 6_000 * MS);
    }

    #[test]
    fn records_within_one_bucket_sum() {
        let meter = EventRateMeter::new(EventRateConfig {
            bucket_ms: 100,
            bucket_count: 10,
        });
        meter.record(0); // epoch 0
        meter.record(50 * MS); // 50ms → still epoch 0
        meter.record(0);
        assert_eq!(meter.events_in_window(0), 3);
        assert_eq!(meter.total_events(), 3);
    }

    #[test]
    fn rate_matches_count_over_window() {
        // 1-second window in 100ms buckets.
        let meter = EventRateMeter::new(EventRateConfig {
            bucket_ms: 100,
            bucket_count: 10,
        });
        for _ in 0..50 {
            meter.record(0);
        }
        // 50 events over a 1.0s window → 50 events/s.
        let snap = meter.snapshot(0);
        assert_eq!(snap.window_events, 50);
        assert!((snap.events_per_second - 50.0).abs() < 1e-6, "{snap:?}");
        assert!((snap.window_seconds - 1.0).abs() < 1e-6);
    }

    #[test]
    fn stale_buckets_expire_outside_the_window() {
        let meter = EventRateMeter::new(EventRateConfig {
            bucket_ms: 100,
            bucket_count: 4, // 400ms window
        });
        for _ in 0..7 {
            meter.record(0); // epoch 0
        }
        // Still inside the 4-bucket window.
        assert_eq!(meter.events_in_window(300 * MS), 7);
        // Epoch 0 is age 5 buckets at 500ms → outside the 4-bucket window.
        assert_eq!(meter.events_in_window(500 * MS), 0);
        // Total is unaffected by window expiry.
        assert_eq!(meter.total_events(), 7);
    }

    #[test]
    fn new_epoch_overwrites_stale_bucket_via_ring() {
        // bucket_count 2: idx = epoch % 2. Epochs 0 and 2 collide on idx 0.
        let meter = EventRateMeter::new(EventRateConfig {
            bucket_ms: 100,
            bucket_count: 2,
        });
        meter.record(0); // epoch 0 → idx 0, count 1
        meter.record(0); // epoch 0 → idx 0, count 2
        meter.record(200 * MS); // epoch 2 → idx 0 resets to count 1
                                // Now: idx0(epoch2)=1, idx1 empty. Window at 200ms (epoch2) spans
                                // epochs {2,1}; epoch 0 is overwritten, so only the epoch-2 count shows.
        assert_eq!(meter.events_in_window(200 * MS), 1);
        assert_eq!(meter.total_events(), 3);
    }

    #[test]
    fn total_keeps_growing_across_window_rotation() {
        let meter = EventRateMeter::new(EventRateConfig {
            bucket_ms: 100,
            bucket_count: 3,
        });
        for ms in [0u64, 100, 200, 300, 400] {
            meter.record(ms * MS);
        }
        assert_eq!(meter.total_events(), 5);
    }

    #[test]
    fn reset_clears_buckets_and_total() {
        let meter = EventRateMeter::default();
        meter.record(0);
        meter.record(0);
        assert_eq!(meter.total_events(), 2);
        meter.reset();
        assert_eq!(meter.total_events(), 0);
        assert_eq!(meter.events_in_window(0), 0);
    }

    #[test]
    fn empty_meter_reports_zero_rate() {
        let meter = EventRateMeter::default();
        let snap = meter.snapshot(0);
        assert_eq!(snap.window_events, 0);
        assert_eq!(snap.total_events, 0);
        assert!((snap.events_per_second).abs() < 1e-6);
    }

    #[test]
    fn fallible_constructor_rejects_invalid_config() {
        assert!(EventRateMeter::try_new(EventRateConfig {
            bucket_ms: 0,
            bucket_count: 10
        })
        .is_err());
        assert!(EventRateMeter::try_new(EventRateConfig {
            bucket_ms: 100,
            bucket_count: 1
        })
        .is_err());
    }

    #[test]
    #[should_panic(expected = "invalid event-rate configuration")]
    fn infallible_constructor_panics_on_invalid_config() {
        let _ = EventRateMeter::new(EventRateConfig {
            bucket_ms: 0,
            bucket_count: 10,
        });
    }

    #[test]
    fn event_rate_snapshot_round_trips_through_serde() {
        // The snapshot is what a diagnostics consumer reads over the wire; its
        // representation must round-trip and the float field must survive.
        let snap = EventRateSnapshot {
            window_events: 42,
            total_events: 1_000,
            window_seconds: 6.0,
            events_per_second: 7.0,
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let back: EventRateSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snap, back);
        assert!(json.contains("\"events_per_second\""));
    }

    #[test]
    fn event_rate_config_round_trips_through_serde() {
        let config = EventRateConfig {
            bucket_ms: 100,
            bucket_count: 60,
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: EventRateConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, back);
        // Validate still rejects a deserialized-then-corrupted config.
        let bad = EventRateConfig {
            bucket_ms: 0,
            bucket_count: 60,
        };
        assert!(bad.validate().is_err());
    }
}
