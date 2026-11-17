//! Bounded held controls and owner-confirmed cleanup, without transport policy.

use crate::{DeviceId, KeyCode, PointerButton};

/// A held control on one device. Motion and scroll cannot enter the ledger.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HeldControl {
    /// A physical key.
    Key { device: DeviceId, code: KeyCode },
    /// A physical pointer button.
    Button {
        device: DeviceId,
        button: PointerButton,
    },
}

impl core::fmt::Debug for HeldControl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HeldControl([REDACTED])")
    }
}

/// A rejected ledger operation. Rejections leave the ledger unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeldError {
    /// No free slot remains.
    Full,
    /// Cleanup has sealed press/release mutation, or another token owns cleanup.
    Busy,
    /// No cleanup is active for the supplied token.
    WrongToken,
    /// The acknowledgement does not match the current release head.
    WrongControl,
    /// Held controls still require acknowledgement.
    NotEmpty,
}

/// Inline storage for one owner's held controls, with no allocation or locks.
///
/// The lifecycle owner supplies opaque `Copy + Eq` cleanup tokens. Tokens MUST
/// be fresh across owner/session cleanup generations, including replacement
/// owners. Reusing a token can make a delayed acknowledgement indistinguishable
/// from current work. This container cannot enforce token freshness.
///
/// Cleanup seals ordinary mutations. Peeking never removes work; a failed send
/// needs no action. Confirm only when the owner confirms the exact cleanup work.
/// Polling or queue admission is not delivery. This ledger provides no native
/// delivery or transport proof and confers no routing authority.
pub struct HeldSet<T: Copy + Eq, const N: usize> {
    slots: [Option<HeldControl>; N],
    len: usize,
    cleanup: Option<T>,
}

impl<T: Copy + Eq, const N: usize> core::fmt::Debug for HeldSet<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeldSet")
            .field("len", &self.len)
            .field("capacity", &N)
            .field("sealed", &self.cleanup.is_some())
            .finish_non_exhaustive()
    }
}

impl<T: Copy + Eq, const N: usize> Default for HeldSet<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Eq, const N: usize> HeldSet<T, N> {
    /// Creates an empty open ledger, including for capacity zero.
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            len: 0,
            cleanup: None,
        }
    }

    /// Number of held controls.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether all controls have been released.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Records a press. Returns whether a new slot was consumed.
    ///
    /// # Errors
    /// Returns `Busy` during cleanup or `Full` for a new control at capacity.
    pub fn press(&mut self, control: HeldControl) -> Result<bool, HeldError> {
        if self.cleanup.is_some() {
            return Err(HeldError::Busy);
        }
        if self.slots[..self.len].contains(&Some(control)) {
            return Ok(false);
        }
        if self.len == N {
            return Err(HeldError::Full);
        }
        self.slots[self.len] = Some(control);
        self.len += 1;
        Ok(true)
    }

    /// Records a release. Unmatched releases return `false` without mutation.
    ///
    /// # Errors
    /// Returns `Busy` during cleanup, even for unmatched releases.
    pub fn release(&mut self, control: HeldControl) -> Result<bool, HeldError> {
        if self.cleanup.is_some() {
            return Err(HeldError::Busy);
        }
        let Some(index) = self.slots[..self.len]
            .iter()
            .position(|slot| *slot == Some(control))
        else {
            return Ok(false);
        };
        self.remove(index);
        Ok(true)
    }

    /// Seals the ledger. Repeating the active token is idempotent.
    ///
    /// # Errors
    /// Returns `Busy` if another token owns cleanup.
    pub fn begin_cleanup(&mut self, token: T) -> Result<(), HeldError> {
        match self.cleanup {
            Some(current) if current != token => Err(HeldError::Busy),
            _ => {
                self.cleanup = Some(token);
                Ok(())
            }
        }
    }

    /// Returns the oldest held control during cleanup without removing it.
    /// Returns `None` when open or empty. Repeated peeks retain failed sends.
    pub fn peek_release(&self) -> Option<HeldControl> {
        self.cleanup?;
        self.slots.first().copied().flatten()
    }

    /// Acknowledges only the current cleanup's exact release head.
    ///
    /// # Errors
    /// Returns `WrongToken` for inactive/stale cleanup, or `WrongControl` if
    /// `expected_control` is not the current head, including an empty ledger.
    pub fn confirm_release(
        &mut self,
        token: T,
        expected_control: HeldControl,
    ) -> Result<(), HeldError> {
        self.check_token(token)?;
        if self.peek_release() != Some(expected_control) {
            return Err(HeldError::WrongControl);
        }
        self.remove(0);
        Ok(())
    }

    /// Reopens an empty ledger after cleanup.
    ///
    /// # Errors
    /// Returns `WrongToken` for inactive/stale cleanup or `NotEmpty` if pending.
    pub fn finish_cleanup(&mut self, token: T) -> Result<(), HeldError> {
        self.check_token(token)?;
        if !self.is_empty() {
            return Err(HeldError::NotEmpty);
        }
        self.cleanup = None;
        Ok(())
    }

    fn check_token(&self, token: T) -> Result<(), HeldError> {
        if self.cleanup == Some(token) {
            Ok(())
        } else {
            Err(HeldError::WrongToken)
        }
    }

    fn remove(&mut self, index: usize) {
        self.slots.copy_within(index + 1..self.len, index);
        self.len -= 1;
        self.slots[self.len] = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(device: u32, code: u16) -> HeldControl {
        HeldControl::Key {
            device: DeviceId::from_raw(device),
            code: KeyCode::from_raw(code),
        }
    }
    fn button(device: u32) -> HeldControl {
        HeldControl::Button {
            device: DeviceId::from_raw(device),
            button: PointerButton::Primary,
        }
    }

    #[test]
    fn full_duplicate_and_release_are_lossless() {
        let mut set = HeldSet::<u64, 2>::new();
        assert_eq!(set.press(key(1, 10)), Ok(true));
        assert_eq!(set.press(button(1)), Ok(true));
        assert_eq!(set.press(key(1, 10)), Ok(false));
        assert_eq!(set.press(key(2, 10)), Err(HeldError::Full));
        assert_eq!(set.release(key(2, 10)), Ok(false));
        assert_eq!(set.len(), 2);
        assert_eq!(set.release(key(1, 10)), Ok(true));
        assert_eq!(set.release(key(1, 10)), Ok(false));
        assert_eq!(set.press(key(2, 10)), Ok(true));
        set.begin_cleanup(1).unwrap();
        assert_eq!(set.peek_release(), Some(button(1)));
        set.confirm_release(1, button(1)).unwrap();
        assert_eq!(set.peek_release(), Some(key(2, 10)));
    }

    #[test]
    fn distinct_devices_and_control_families_have_distinct_slots() {
        let mut set = HeldSet::<u8, 4>::new();
        for control in [key(1, 1), key(2, 1), button(1), button(2)] {
            assert_eq!(set.press(control), Ok(true));
        }
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn zero_capacity_can_complete_empty_cleanup() {
        let mut set = HeldSet::<u8, 0>::default();
        assert_eq!(set.press(key(1, 1)), Err(HeldError::Full));
        assert_eq!(set.release(key(1, 1)), Ok(false));
        set.begin_cleanup(1).unwrap();
        assert_eq!(set.peek_release(), None);
        assert_eq!(
            set.confirm_release(1, key(1, 1)),
            Err(HeldError::WrongControl)
        );
        set.finish_cleanup(1).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn cleanup_freezes_mutations_and_failed_send_retains_head() {
        let mut set = HeldSet::<u8, 2>::new();
        set.press(key(1, 1)).unwrap();
        set.press(button(1)).unwrap();
        assert_eq!(set.peek_release(), None);
        set.begin_cleanup(7).unwrap();
        set.begin_cleanup(7).unwrap();
        assert_eq!(set.begin_cleanup(8), Err(HeldError::Busy));
        assert_eq!(set.press(key(1, 1)), Err(HeldError::Busy));
        assert_eq!(set.release(button(1)), Err(HeldError::Busy));
        assert_eq!(set.release(key(9, 9)), Err(HeldError::Busy));
        assert_eq!(set.finish_cleanup(7), Err(HeldError::NotEmpty));
        for _ in 0..3 {
            assert_eq!(set.peek_release(), Some(key(1, 1)));
        }
        assert_eq!(set.len(), 2);
        assert_eq!(
            set.confirm_release(8, key(1, 1)),
            Err(HeldError::WrongToken)
        );
        assert_eq!(
            set.confirm_release(7, button(1)),
            Err(HeldError::WrongControl)
        );
        assert_eq!(set.peek_release(), Some(key(1, 1)));
        set.confirm_release(7, key(1, 1)).unwrap();
        assert_eq!(
            set.confirm_release(7, key(1, 1)),
            Err(HeldError::WrongControl)
        );
        set.confirm_release(7, button(1)).unwrap();
        set.finish_cleanup(7).unwrap();
        assert_eq!(set.finish_cleanup(7), Err(HeldError::WrongToken));
        assert_eq!(set.press(button(2)), Ok(true));
    }

    #[test]
    fn stale_acknowledgements_cannot_change_a_new_cleanup() {
        let mut set = HeldSet::<u8, 2>::new();
        set.press(key(1, 1)).unwrap();
        set.begin_cleanup(1).unwrap();
        set.confirm_release(1, key(1, 1)).unwrap();
        set.finish_cleanup(1).unwrap();
        set.press(button(1)).unwrap();
        set.press(key(1, 1)).unwrap();
        set.begin_cleanup(2).unwrap();
        assert_eq!(
            set.confirm_release(1, button(1)),
            Err(HeldError::WrongToken)
        );
        assert_eq!(
            set.confirm_release(2, key(1, 1)),
            Err(HeldError::WrongControl)
        );
        assert_eq!(set.finish_cleanup(1), Err(HeldError::WrongToken));
        assert_eq!(set.len(), 2);
        assert_eq!(set.peek_release(), Some(button(1)));
        set.confirm_release(2, button(1)).unwrap();
        set.confirm_release(2, key(1, 1)).unwrap();
        set.finish_cleanup(2).unwrap();
        set.begin_cleanup(3).unwrap();
        set.finish_cleanup(3).unwrap();
        assert_eq!(
            set.confirm_release(3, key(1, 1)),
            Err(HeldError::WrongToken)
        );
    }

    #[test]
    fn debug_redacts_controls_devices_and_opaque_tokens() {
        #[derive(Clone, Copy, Eq, PartialEq)]
        struct Token(u64);
        let mut set = HeldSet::<Token, 1>::new();
        let control = key(12345, 54321);
        set.press(control).unwrap();
        set.begin_cleanup(Token(987_654)).unwrap();
        assert_eq!(format!("{control:?}"), "HeldControl([REDACTED])");
        assert_eq!(
            format!("{set:?}"),
            "HeldSet { len: 1, capacity: 1, sealed: true, .. }"
        );
    }
}
