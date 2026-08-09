//! Bounded, platform-neutral state for plain-text clipboard synchronization.
//!
//! This crate performs no I/O, waits, locking, or channel operations. Platform
//! clipboard watchers and network tasks feed observations into
//! [`ClipboardSynchronizer`] and act on its explicit [`ClipboardDecision`]s.

use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::fmt;

use kvm_types::HostId;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Default maximum size of a text update: 256 KiB of UTF-8 bytes.
pub const DEFAULT_MAX_TEXT_BYTES: usize = 256 * 1024;

/// Default number of update IDs and expected local echoes retained in memory.
pub const DEFAULT_RECENT_UPDATE_CAPACITY: usize = 256;

/// Runtime policy and memory bounds for clipboard synchronization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClipboardPolicy {
    enabled: bool,
    max_text_bytes: usize,
    recent_update_capacity: usize,
}

impl ClipboardPolicy {
    /// Creates a validated clipboard policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when either bound is zero.
    pub fn new(
        enabled: bool,
        max_text_bytes: usize,
        recent_update_capacity: usize,
    ) -> Result<Self, PolicyError> {
        if max_text_bytes == 0 {
            return Err(PolicyError::ZeroMaximumTextBytes);
        }
        if recent_update_capacity == 0 {
            return Err(PolicyError::ZeroRecentUpdateCapacity);
        }

        Ok(Self {
            enabled,
            max_text_bytes,
            recent_update_capacity,
        })
    }

    #[must_use]
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn max_text_bytes(self) -> usize {
        self.max_text_bytes
    }

    #[must_use]
    pub const fn recent_update_capacity(self) -> usize {
        self.recent_update_capacity
    }
}

impl Default for ClipboardPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            recent_update_capacity: DEFAULT_RECENT_UPDATE_CAPACITY,
        }
    }
}

/// Invalid memory or payload bounds in a [`ClipboardPolicy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    ZeroMaximumTextBytes,
    ZeroRecentUpdateCapacity,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaximumTextBytes => {
                formatter.write_str("maximum text bytes must be non-zero")
            }
            Self::ZeroRecentUpdateCapacity => {
                formatter.write_str("recent update capacity must be non-zero")
            }
        }
    }
}

impl Error for PolicyError {}

/// SHA-256 digest of the UTF-8 bytes in a clipboard update.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    #[must_use]
    pub fn for_text(text: &str) -> Self {
        Self(Sha256::digest(text.as_bytes()).into())
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Clipboard payload supported by the initial protocol.
#[derive(Clone, Eq, PartialEq)]
pub enum ClipboardContent {
    Text(String),
}

impl fmt::Debug for ClipboardContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // F-11: never surface clipboard text (passwords/tokens) via Debug.
        match self {
            Self::Text(text) => formatter
                .debug_struct("ClipboardContent::Text")
                .field("len", &text.len())
                .finish(),
        }
    }
}

impl ClipboardContent {
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Text(text) => text,
        }
    }

    #[must_use]
    pub fn utf8_len(&self) -> usize {
        self.text().len()
    }
}

/// One origin-authored clipboard update and its integrity metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct ClipboardUpdate {
    id: Uuid,
    origin: HostId,
    content_hash: ContentHash,
    content: ClipboardContent,
}

impl fmt::Debug for ClipboardUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // F-11: redact content text; show only non-sensitive metadata. HostId's
        // own Debug already redacts (see kvm-types).
        formatter
            .debug_struct("ClipboardUpdate")
            .field("id", &self.id)
            .field("origin", &self.origin)
            .field("content_hash", &self.content_hash)
            .field("content_len", &self.content.utf8_len())
            .finish_non_exhaustive()
    }
}

impl ClipboardUpdate {
    /// Creates an update with a random ID and a calculated content hash.
    #[must_use]
    pub fn new(origin: HostId, text: impl Into<String>) -> Self {
        Self::with_id(Uuid::new_v4(), origin, text)
    }

    /// Creates an update with a supplied ID and a calculated content hash.
    #[must_use]
    pub fn with_id(id: Uuid, origin: HostId, text: impl Into<String>) -> Self {
        let text = text.into();
        let content_hash = ContentHash::for_text(&text);
        Self {
            id,
            origin,
            content_hash,
            content: ClipboardContent::Text(text),
        }
    }

    /// Reconstructs an update from wire metadata.
    ///
    /// The hash is deliberately not trusted here. [`ClipboardSynchronizer`]
    /// validates it before accepting the update, which lets callers represent
    /// and explicitly reject malformed network input.
    #[must_use]
    pub fn from_parts(
        id: Uuid,
        origin: HostId,
        content_hash: ContentHash,
        content: ClipboardContent,
    ) -> Self {
        Self {
            id,
            origin,
            content_hash,
            content,
        }
    }

    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    #[must_use]
    pub const fn origin(&self) -> HostId {
        self.origin
    }

    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    #[must_use]
    pub const fn content(&self) -> &ClipboardContent {
        &self.content
    }

    #[must_use]
    pub fn text(&self) -> &str {
        self.content.text()
    }
}

/// Required side effect, or explicit refusal, after a state transition.
#[derive(Clone, Eq, PartialEq)]
pub enum ClipboardDecision {
    /// Publish this locally authored update to peers.
    Publish(ClipboardUpdate),
    /// Apply this peer-authored update to the local OS clipboard.
    Apply(ClipboardUpdate),
    /// Do nothing because the update is disabled, redundant, or a replay.
    Ignore(IgnoreReason),
    /// Drop malformed or policy-violating content.
    Reject(RejectReason),
}

impl fmt::Debug for ClipboardDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // F-11: delegate to the redacting ClipboardUpdate Debug; Ignore/Reject
        // reasons carry only an id/enum and no payload text.
        match self {
            Self::Publish(update) => formatter.debug_tuple("Publish").field(update).finish(),
            Self::Apply(update) => formatter.debug_tuple("Apply").field(update).finish(),
            Self::Ignore(reason) => formatter.debug_tuple("Ignore").field(reason).finish(),
            Self::Reject(reason) => formatter.debug_tuple("Reject").field(reason).finish(),
        }
    }
}

/// Reasons an otherwise valid observation requires no action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoreReason {
    Disabled,
    DuplicateUpdate { update_id: Uuid },
    LocallyOriginated { update_id: Uuid },
    LocalEcho { update_id: Uuid },
    UnchangedContent,
}

/// Reasons content must be rejected rather than silently ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    PayloadTooLarge {
        actual: usize,
        maximum: usize,
    },
    HashMismatch {
        declared: ContentHash,
        calculated: ContentHash,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedEcho {
    update_id: Uuid,
    content_hash: ContentHash,
    previous_hash: Option<ContentHash>,
}

#[derive(Debug)]
struct RecentUpdateIds {
    capacity: usize,
    order: VecDeque<Uuid>,
    members: HashSet<Uuid>,
}

impl RecentUpdateIds {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            members: HashSet::with_capacity(capacity),
        }
    }

    fn contains(&self, id: &Uuid) -> bool {
        self.members.contains(id)
    }

    fn insert(&mut self, id: Uuid) {
        if !self.members.insert(id) {
            return;
        }

        self.order.push_back(id);
        if self.order.len() > self.capacity {
            // F-32: pop_front is Some whenever len() > capacity (capacity >= 1),
            // but handle None defensively rather than .expect() — panic-free goal.
            if let Some(evicted) = self.order.pop_front() {
                self.members.remove(&evicted);
            }
        }
    }

    fn remove(&mut self, id: &Uuid) -> bool {
        if !self.members.remove(id) {
            return false;
        }

        // F-32: the invariant guarantees the id is present, but handle None
        // defensively rather than .expect() — panic-free goal.
        if let Some(position) = self.order.iter().position(|candidate| candidate == id) {
            self.order.remove(position);
        }
        true
    }

    fn len(&self) -> usize {
        self.order.len()
    }
}

/// Synchronous, bounded clipboard synchronization state.
///
/// Receiving an `Apply` decision also registers the expected OS clipboard
/// notification. Feed that notification to [`Self::observe_local_text`]; it
/// will be consumed as `Ignore(LocalEcho)` instead of being rebroadcast. If an
/// OS clipboard write fails, call [`Self::cancel_expected_echo`].
#[derive(Debug)]
pub struct ClipboardSynchronizer {
    local_host: HostId,
    policy: ClipboardPolicy,
    recent_updates: RecentUpdateIds,
    expected_echoes: VecDeque<ExpectedEcho>,
    current_hash: Option<ContentHash>,
}

impl ClipboardSynchronizer {
    #[must_use]
    pub fn new(local_host: HostId, policy: ClipboardPolicy) -> Self {
        Self {
            local_host,
            policy,
            recent_updates: RecentUpdateIds::new(policy.recent_update_capacity),
            expected_echoes: VecDeque::with_capacity(policy.recent_update_capacity),
            current_hash: None,
        }
    }

    #[must_use]
    pub const fn local_host(&self) -> HostId {
        self.local_host
    }

    #[must_use]
    pub const fn policy(&self) -> ClipboardPolicy {
        self.policy
    }

    /// Enables or disables synchronization, returning the previous value.
    ///
    /// Changing the mode clears content and echo state so clipboard changes
    /// made while disabled cannot be mistaken for remote echoes after re-enable.
    pub fn set_enabled(&mut self, enabled: bool) -> bool {
        let previous = self.policy.enabled;
        if previous != enabled {
            self.policy.enabled = enabled;
            self.current_hash = None;
            self.expected_echoes.clear();
        }
        previous
    }

    /// Processes text reported by the local platform clipboard watcher.
    ///
    /// This operation only hashes bounded input and updates in-memory state. It
    /// never performs clipboard or network I/O.
    #[must_use]
    pub fn observe_local_text(&mut self, text: impl Into<String>) -> ClipboardDecision {
        if !self.policy.enabled {
            return ClipboardDecision::Ignore(IgnoreReason::Disabled);
        }

        let text = text.into();
        if let Some(rejection) = self.size_rejection(text.len()) {
            return ClipboardDecision::Reject(rejection);
        }

        let content_hash = ContentHash::for_text(&text);
        if let Some(position) = self
            .expected_echoes
            .iter()
            .position(|expected| expected.content_hash == content_hash)
        {
            if let Some(expected) = self.expected_echoes.remove(position) {
                self.current_hash = Some(content_hash);
                return ClipboardDecision::Ignore(IgnoreReason::LocalEcho {
                    update_id: expected.update_id,
                });
            }
        }

        if self.current_hash == Some(content_hash) {
            return ClipboardDecision::Ignore(IgnoreReason::UnchangedContent);
        }

        let update = ClipboardUpdate::new(self.local_host, text);
        self.current_hash = Some(content_hash);
        self.recent_updates.insert(update.id);
        ClipboardDecision::Publish(update)
    }

    /// Processes one peer-authored update received from the clipboard channel.
    ///
    /// An accepted update is remembered before `Apply` is returned, preventing
    /// concurrent duplicate delivery and preparing deterministic echo
    /// suppression. Call [`Self::cancel_expected_echo`] if applying it fails.
    #[must_use]
    pub fn receive_remote(&mut self, update: ClipboardUpdate) -> ClipboardDecision {
        if !self.policy.enabled {
            return ClipboardDecision::Ignore(IgnoreReason::Disabled);
        }

        if let Some(rejection) = self.size_rejection(update.content.utf8_len()) {
            return ClipboardDecision::Reject(rejection);
        }

        let calculated = ContentHash::for_text(update.content.text());
        if calculated != update.content_hash {
            return ClipboardDecision::Reject(RejectReason::HashMismatch {
                declared: update.content_hash,
                calculated,
            });
        }

        if update.origin == self.local_host {
            return ClipboardDecision::Ignore(IgnoreReason::LocallyOriginated {
                update_id: update.id,
            });
        }

        if self.recent_updates.contains(&update.id) {
            return ClipboardDecision::Ignore(IgnoreReason::DuplicateUpdate {
                update_id: update.id,
            });
        }
        self.recent_updates.insert(update.id);

        if self.current_hash == Some(update.content_hash) {
            return ClipboardDecision::Ignore(IgnoreReason::UnchangedContent);
        }

        let previous_hash = self.current_hash.replace(update.content_hash);
        self.expected_echoes.push_back(ExpectedEcho {
            update_id: update.id,
            content_hash: update.content_hash,
            previous_hash,
        });
        if self.expected_echoes.len() > self.policy.recent_update_capacity {
            self.expected_echoes.pop_front();
        }

        ClipboardDecision::Apply(update)
    }

    /// Rolls back state after the corresponding OS clipboard write fails.
    ///
    /// Returns whether an expectation was removed. The update ID becomes
    /// eligible for retry. Content state is restored when no later update has
    /// superseded the failed one.
    pub fn cancel_expected_echo(&mut self, update_id: Uuid) -> bool {
        let Some(position) = self
            .expected_echoes
            .iter()
            .position(|expected| expected.update_id == update_id)
        else {
            return false;
        };
        let Some(expected) = self.expected_echoes.remove(position) else {
            return false;
        };
        self.recent_updates.remove(&update_id);
        if self.current_hash == Some(expected.content_hash) {
            self.current_hash = expected.previous_hash;
        }
        true
    }

    #[must_use]
    pub fn recent_update_count(&self) -> usize {
        self.recent_updates.len()
    }

    #[must_use]
    pub fn expected_echo_count(&self) -> usize {
        self.expected_echoes.len()
    }

    fn size_rejection(&self, actual: usize) -> Option<RejectReason> {
        (actual > self.policy.max_text_bytes).then_some(RejectReason::PayloadTooLarge {
            actual,
            maximum: self.policy.max_text_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_A: HostId = HostId::from_bytes([0x0a; 16]);
    const HOST_B: HostId = HostId::from_bytes([0x0b; 16]);

    fn policy(enabled: bool, maximum: usize, capacity: usize) -> ClipboardPolicy {
        ClipboardPolicy::new(enabled, maximum, capacity).unwrap()
    }

    fn fixed_update(number: u8, origin: HostId, text: &str) -> ClipboardUpdate {
        ClipboardUpdate::with_id(Uuid::from_bytes([number; 16]), origin, text)
    }

    fn published(decision: ClipboardDecision) -> ClipboardUpdate {
        let ClipboardDecision::Publish(update) = decision else {
            panic!("expected publish decision, got {decision:?}");
        };
        update
    }

    #[test]
    fn debug_never_exposes_clipboard_text() {
        // F-11: payload text must not reach Debug output for any sensitive type.
        const SECRET: &str = "SUPER-SECRET-CLIPBOARD-TOKEN";
        let update = fixed_update(1, HOST_A, SECRET);
        let content = ClipboardContent::Text(SECRET.to_owned());
        let decisions = [
            ClipboardDecision::Publish(update.clone()),
            ClipboardDecision::Apply(update.clone()),
            ClipboardDecision::Ignore(IgnoreReason::UnchangedContent),
            ClipboardDecision::Reject(RejectReason::PayloadTooLarge {
                actual: 999,
                maximum: 256,
            }),
        ];

        assert!(!format!("{update:?}").contains(SECRET));
        assert!(!format!("{content:?}").contains(SECRET));
        for decision in &decisions {
            assert!(!format!("{decision:?}").contains(SECRET));
        }
    }

    #[test]
    fn synchronizes_new_text_bidirectionally() {
        let mut a = ClipboardSynchronizer::new(HOST_A, ClipboardPolicy::default());
        let mut b = ClipboardSynchronizer::new(HOST_B, ClipboardPolicy::default());

        let a_update = published(a.observe_local_text("from a"));
        assert_eq!(
            b.receive_remote(a_update.clone()),
            ClipboardDecision::Apply(a_update.clone())
        );
        assert_eq!(
            b.observe_local_text("from a"),
            ClipboardDecision::Ignore(IgnoreReason::LocalEcho {
                update_id: a_update.id()
            })
        );

        let b_update = published(b.observe_local_text("from b"));
        assert_eq!(
            a.receive_remote(b_update.clone()),
            ClipboardDecision::Apply(b_update)
        );
    }

    #[test]
    fn repeated_local_content_is_not_republished() {
        let mut state = ClipboardSynchronizer::new(HOST_A, ClipboardPolicy::default());

        assert!(matches!(
            state.observe_local_text("same"),
            ClipboardDecision::Publish(_)
        ));
        assert_eq!(
            state.observe_local_text("same"),
            ClipboardDecision::Ignore(IgnoreReason::UnchangedContent)
        );
    }

    #[test]
    fn distinct_remote_updates_with_current_content_are_not_reapplied() {
        let mut state = ClipboardSynchronizer::new(HOST_A, ClipboardPolicy::default());
        let first = fixed_update(1, HOST_B, "same");
        let second = fixed_update(2, HOST_B, "same");

        assert!(matches!(
            state.receive_remote(first),
            ClipboardDecision::Apply(_)
        ));
        assert_eq!(
            state.receive_remote(second),
            ClipboardDecision::Ignore(IgnoreReason::UnchangedContent)
        );
        assert_eq!(state.recent_update_count(), 2);
    }

    #[test]
    fn local_notification_after_remote_apply_is_consumed_once() {
        let mut state = ClipboardSynchronizer::new(HOST_A, ClipboardPolicy::default());
        let update = fixed_update(3, HOST_B, "remote");
        let id = update.id();

        assert!(matches!(
            state.receive_remote(update),
            ClipboardDecision::Apply(_)
        ));
        assert_eq!(state.expected_echo_count(), 1);
        assert_eq!(
            state.observe_local_text("remote"),
            ClipboardDecision::Ignore(IgnoreReason::LocalEcho { update_id: id })
        );
        assert_eq!(state.expected_echo_count(), 0);
        assert_eq!(
            state.observe_local_text("remote"),
            ClipboardDecision::Ignore(IgnoreReason::UnchangedContent)
        );
    }

    #[test]
    fn own_update_returning_from_a_peer_is_ignored_even_after_history_eviction() {
        let mut state = ClipboardSynchronizer::new(HOST_A, policy(true, 100, 1));
        let own = fixed_update(4, HOST_A, "loop");
        let _ = state.receive_remote(fixed_update(5, HOST_B, "other"));

        assert_eq!(
            state.receive_remote(own.clone()),
            ClipboardDecision::Ignore(IgnoreReason::LocallyOriginated {
                update_id: own.id()
            })
        );
    }

    #[test]
    fn disabled_mode_neither_publishes_nor_applies() {
        let mut state = ClipboardSynchronizer::new(HOST_A, policy(false, 4, 2));

        assert_eq!(
            state.observe_local_text("far too long"),
            ClipboardDecision::Ignore(IgnoreReason::Disabled)
        );
        assert_eq!(
            state.receive_remote(fixed_update(6, HOST_B, "far too long")),
            ClipboardDecision::Ignore(IgnoreReason::Disabled)
        );
        assert_eq!(state.recent_update_count(), 0);
    }

    #[test]
    fn disabling_clears_echo_state_before_reenable() {
        let mut state = ClipboardSynchronizer::new(HOST_A, ClipboardPolicy::default());
        let _ = state.receive_remote(fixed_update(7, HOST_B, "remote"));
        assert_eq!(state.expected_echo_count(), 1);

        assert!(state.set_enabled(false));
        assert!(!state.set_enabled(true));
        assert_eq!(state.expected_echo_count(), 0);
        assert!(matches!(
            state.observe_local_text("remote"),
            ClipboardDecision::Publish(_)
        ));
    }

    #[test]
    fn utf8_payload_limit_is_measured_in_bytes() {
        let mut state = ClipboardSynchronizer::new(HOST_A, policy(true, 4, 2));

        assert!(matches!(
            state.observe_local_text("éé"),
            ClipboardDecision::Publish(_)
        ));
        assert_eq!(
            state.observe_local_text("ééx"),
            ClipboardDecision::Reject(RejectReason::PayloadTooLarge {
                actual: 5,
                maximum: 4
            })
        );

        let oversized = fixed_update(8, HOST_B, "12345");
        assert_eq!(
            state.receive_remote(oversized),
            ClipboardDecision::Reject(RejectReason::PayloadTooLarge {
                actual: 5,
                maximum: 4
            })
        );
    }

    #[test]
    fn rejects_mismatched_content_hash() {
        let mut state = ClipboardSynchronizer::new(HOST_A, ClipboardPolicy::default());
        let declared = ContentHash::for_text("declared");
        let malformed = ClipboardUpdate::from_parts(
            Uuid::from_bytes([9; 16]),
            HOST_B,
            declared,
            ClipboardContent::Text("actual".to_owned()),
        );

        assert_eq!(
            state.receive_remote(malformed),
            ClipboardDecision::Reject(RejectReason::HashMismatch {
                declared,
                calculated: ContentHash::for_text("actual")
            })
        );
    }

    #[test]
    fn duplicate_id_is_ignored_before_same_content_check() {
        let mut state = ClipboardSynchronizer::new(HOST_A, ClipboardPolicy::default());
        let update = fixed_update(10, HOST_B, "once");

        let _ = state.receive_remote(update.clone());
        assert_eq!(
            state.receive_remote(update.clone()),
            ClipboardDecision::Ignore(IgnoreReason::DuplicateUpdate {
                update_id: update.id()
            })
        );
    }

    #[test]
    fn replay_window_is_bounded_and_oldest_id_is_evicted() {
        let mut state = ClipboardSynchronizer::new(HOST_A, policy(true, 100, 2));
        let first = fixed_update(11, HOST_B, "first");
        let second = fixed_update(12, HOST_B, "second");
        let third = fixed_update(13, HOST_B, "third");

        let _ = state.receive_remote(first.clone());
        let _ = state.receive_remote(second);
        assert_eq!(
            state.receive_remote(first.clone()),
            ClipboardDecision::Ignore(IgnoreReason::DuplicateUpdate {
                update_id: first.id()
            })
        );
        let _ = state.receive_remote(third);

        assert_eq!(state.recent_update_count(), 2);
        assert_eq!(
            state.receive_remote(first.clone()),
            ClipboardDecision::Apply(first)
        );
        assert_eq!(state.recent_update_count(), 2);
        assert!(state.expected_echo_count() <= 2);
    }

    #[test]
    fn failed_apply_rolls_back_and_same_update_can_be_retried() {
        let mut state = ClipboardSynchronizer::new(HOST_A, ClipboardPolicy::default());
        let local = published(state.observe_local_text("previous"));
        let update = fixed_update(14, HOST_B, "failed");
        let id = update.id();
        assert_eq!(
            state.receive_remote(update.clone()),
            ClipboardDecision::Apply(update.clone())
        );

        assert!(state.cancel_expected_echo(id));
        assert!(!state.cancel_expected_echo(id));
        assert_eq!(state.expected_echo_count(), 0);
        assert_eq!(
            state.observe_local_text("previous"),
            ClipboardDecision::Ignore(IgnoreReason::UnchangedContent)
        );
        assert_eq!(
            state.receive_remote(update.clone()),
            ClipboardDecision::Apply(update)
        );
        assert_eq!(state.recent_update_count(), 2);
        assert_ne!(local.id(), id);
    }

    #[test]
    fn policy_rejects_unbounded_zero_values() {
        assert_eq!(
            ClipboardPolicy::new(true, 0, 1),
            Err(PolicyError::ZeroMaximumTextBytes)
        );
        assert_eq!(
            ClipboardPolicy::new(true, 1, 0),
            Err(PolicyError::ZeroRecentUpdateCapacity)
        );
    }
}
