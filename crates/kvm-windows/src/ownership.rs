#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClaimError {
    AlreadyOwned,
    GenerationExhausted,
}

/// Process-global Raw Input registration state.
///
/// Windows permits only one registration per top-level collection per process.
/// Generations make late cleanup harmless: a stale owner can never clear a
/// newer owner's claim.
#[derive(Debug)]
pub(crate) struct RegistrationState {
    next_generation: u64,
    active_generation: Option<u64>,
}

impl RegistrationState {
    pub(crate) const fn new() -> Self {
        Self {
            next_generation: 1,
            active_generation: None,
        }
    }

    pub(crate) fn claim(&mut self) -> Result<u64, ClaimError> {
        if self.active_generation.is_some() {
            return Err(ClaimError::AlreadyOwned);
        }
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ClaimError::GenerationExhausted)?;
        self.active_generation = Some(generation);
        Ok(generation)
    }

    pub(crate) fn is_owner(&self, generation: u64) -> bool {
        self.active_generation == Some(generation)
    }

    /// Releases only the matching generation.
    pub(crate) fn release(&mut self, generation: u64) -> bool {
        if !self.is_owner(generation) {
            return false;
        }
        self.active_generation = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_registration_cannot_replace_the_active_owner() {
        let mut state = RegistrationState::new();
        let first = state.claim().unwrap();
        assert_eq!(state.claim(), Err(ClaimError::AlreadyOwned));
        assert!(state.is_owner(first));
    }

    #[test]
    fn stale_cleanup_cannot_release_a_newer_generation() {
        let mut state = RegistrationState::new();
        let first = state.claim().unwrap();
        assert!(state.release(first));
        let second = state.claim().unwrap();

        assert!(!state.release(first));
        assert!(state.is_owner(second));
    }

    #[test]
    fn timed_out_owner_blocks_replacement_until_real_release() {
        let mut state = RegistrationState::new();
        let timed_out = state.claim().unwrap();
        assert_eq!(state.claim(), Err(ClaimError::AlreadyOwned));
        assert!(state.release(timed_out));
        assert!(state.claim().is_ok());
    }
}
