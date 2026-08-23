use std::time::Duration;
use thiserror::Error;

/// Deterministic exponential reconnect parameters. Delays derived here are
/// exact; production callers that must avoid synchronized reconnect storms
/// layer the optional ±25% jitter from
/// [`ReconnectBackoff::next_delay_with_jitter`] on top using an injected
/// uniform sample (tests and the plain [`ReconnectBackoff::next_delay`] stay
/// fully deterministic).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectPolicy {
    pub initial_delay: Duration,
    pub maximum_delay: Duration,
    pub multiplier: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            maximum_delay: Duration::from_secs(30),
            multiplier: 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReconnectPolicyError {
    #[error("initial reconnect delay must be positive")]
    ZeroInitialDelay,
    #[error("maximum reconnect delay must not be shorter than initial delay")]
    MaximumBelowInitial,
    #[error("reconnect multiplier must be positive")]
    ZeroMultiplier,
}

impl ReconnectPolicy {
    /// Validates reconnect timing relationships.
    ///
    /// # Errors
    ///
    /// Returns a specific error for the first invalid value.
    pub fn validate(&self) -> Result<(), ReconnectPolicyError> {
        if self.initial_delay == Duration::ZERO {
            return Err(ReconnectPolicyError::ZeroInitialDelay);
        }
        if self.maximum_delay < self.initial_delay {
            return Err(ReconnectPolicyError::MaximumBelowInitial);
        }
        if self.multiplier == 0 {
            return Err(ReconnectPolicyError::ZeroMultiplier);
        }
        Ok(())
    }
}

/// Stateful reconnect attempt counter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnectBackoff {
    policy: ReconnectPolicy,
    attempts: u32,
}

impl ReconnectBackoff {
    /// Creates backoff, panicking for an invalid policy.
    ///
    /// Prefer [`Self::try_new`] for externally supplied policy.
    ///
    /// # Panics
    ///
    /// Panics when the policy is invalid.
    pub const fn new(policy: ReconnectPolicy) -> Self {
        assert!(
            policy.initial_delay.as_nanos() > 0
                && policy.maximum_delay.as_nanos() >= policy.initial_delay.as_nanos()
                && policy.multiplier > 0,
            "invalid reconnect policy"
        );
        Self {
            policy,
            attempts: 0,
        }
    }

    /// Creates backoff after fallible policy validation.
    ///
    /// # Errors
    ///
    /// Returns a specific reconnect policy error.
    pub fn try_new(policy: ReconnectPolicy) -> Result<Self, ReconnectPolicyError> {
        policy.validate()?;
        Ok(Self {
            policy,
            attempts: 0,
        })
    }

    /// Returns the next delay and advances the failed-attempt counter.
    pub fn next_delay(&mut self) -> Duration {
        let exponent = self.attempts.min(31);
        let factor = self.policy.multiplier.saturating_pow(exponent);
        let delay = self.policy.initial_delay.saturating_mul(factor);
        self.attempts = self.attempts.saturating_add(1);
        delay.min(self.policy.maximum_delay)
    }

    /// Returns the next delay with up to ±25% jitter around the deterministic
    /// base and advances the failed-attempt counter.
    ///
    /// `sample` is a uniform variate on `[0, 1]` supplied by the caller, so
    /// production code injects its own (seeded) RNG while tests inject fixed
    /// values — `0.5` reproduces the unjittered delay exactly. The result is
    /// clamped back to `policy.maximum_delay` so the configured ceiling
    /// remains a ceiling, and non-finite or out-of-range samples fall back to
    /// the deterministic delay.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub fn next_delay_with_jitter(&mut self, sample: f64) -> Duration {
        let base = self.next_delay();
        if !sample.is_finite() {
            return base;
        }
        // Integer nanosecond arithmetic keeps the midpoint sample exactly on
        // the base delay; `Duration`'s float conversions round to the nearest
        // nanosecond and would drift off the deterministic value.
        let quarter = base.as_nanos() / 4;
        let offset = (sample.clamp(0.0, 1.0) * 2.0 - 1.0) * quarter as f64;
        let jittered = base.as_nanos() as i128 + offset.round() as i128;
        if jittered <= 0 {
            return Duration::ZERO;
        }
        Duration::from_nanos(jittered as u64).min(self.policy.maximum_delay)
    }

    /// Resets backoff after a connection has been accepted as healthy.
    pub const fn reset(&mut self) {
        self.attempts = 0;
    }

    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
}

impl Default for ReconnectBackoff {
    fn default() -> Self {
        Self::new(ReconnectPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_caps_and_resets_after_reconnection() {
        let policy = ReconnectPolicy {
            initial_delay: Duration::from_millis(100),
            maximum_delay: Duration::from_millis(450),
            multiplier: 2,
        };
        let mut backoff = ReconnectBackoff::new(policy);

        assert_eq!(backoff.next_delay(), Duration::from_millis(100));
        assert_eq!(backoff.next_delay(), Duration::from_millis(200));
        assert_eq!(backoff.next_delay(), Duration::from_millis(400));
        assert_eq!(backoff.next_delay(), Duration::from_millis(450));
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    }

    #[test]
    fn jitter_stays_within_bounds_and_is_exact_at_the_midpoint() {
        let policy = ReconnectPolicy {
            initial_delay: Duration::from_millis(100),
            maximum_delay: Duration::from_millis(450),
            multiplier: 2,
        };
        // Each `next_delay_with_jitter` call consumes one retry attempt, so a
        // fresh backoff keeps every assertion anchored to the 100 ms base.
        let mut backoff = ReconnectBackoff::new(policy);
        assert_eq!(
            backoff.next_delay_with_jitter(0.5),
            Duration::from_millis(100)
        );

        let mut backoff = ReconnectBackoff::new(policy);
        assert_eq!(
            backoff.next_delay_with_jitter(0.0),
            Duration::from_millis(75)
        );

        let mut backoff = ReconnectBackoff::new(policy);
        assert_eq!(
            backoff.next_delay_with_jitter(1.0),
            Duration::from_millis(125)
        );

        // Out-of-range samples clamp; non-finite samples keep the base delay.
        let mut backoff = ReconnectBackoff::new(policy);
        assert_eq!(
            backoff.next_delay_with_jitter(-3.0),
            Duration::from_millis(75)
        );

        let mut backoff = ReconnectBackoff::new(policy);
        assert_eq!(
            backoff.next_delay_with_jitter(7.0),
            Duration::from_millis(125)
        );

        let mut backoff = ReconnectBackoff::new(policy);
        assert_eq!(
            backoff.next_delay_with_jitter(f64::NAN),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn jitter_never_exceeds_the_configured_maximum_delay() {
        let policy = ReconnectPolicy {
            initial_delay: Duration::from_millis(100),
            maximum_delay: Duration::from_millis(450),
            multiplier: 2,
        };
        let mut backoff = ReconnectBackoff::new(policy);

        for _ in 0..3 {
            backoff.next_delay();
        }
        assert_eq!(
            backoff.next_delay_with_jitter(1.0),
            Duration::from_millis(450)
        );
    }

    #[test]
    fn fallible_constructor_rejects_invalid_policy() {
        let invalid = ReconnectPolicy {
            initial_delay: Duration::ZERO,
            ..ReconnectPolicy::default()
        };
        assert!(matches!(
            ReconnectBackoff::try_new(invalid),
            Err(ReconnectPolicyError::ZeroInitialDelay)
        ));
    }
}
