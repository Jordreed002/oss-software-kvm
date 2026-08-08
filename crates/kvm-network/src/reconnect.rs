use std::time::Duration;
use thiserror::Error;

/// Deterministic exponential reconnect parameters. The persistent-session
/// scheduler applies its injected `ReconnectJitter` source to these base
/// delays.
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
