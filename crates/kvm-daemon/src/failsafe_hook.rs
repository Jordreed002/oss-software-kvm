//! Process-global panic failsafe.
//!
//! The daemon's core safety invariant is fail-open: any failure must release
//! logically-pressed remote keys/buttons and stop suppressing local input. A
//! panic on any thread is such a failure. The default panic hook only prints
//! and unwinds — it cannot reach the manager, because the manager lives behind
//! a `std::sync::Mutex` that may be held by (or poisoned by) the panicking
//! thread.
//!
//! This module therefore installs a hook that performs only lock-free work:
//!
//! 1. it forwards to the previous hook so default panic output (and any
//!    subscriber already installed by the runtime) is preserved, then
//! 2. it atomically sets the trip flag and invokes a pre-registered lock-free
//!    waker (if any).
//!
//! The daemon's serialized authority observes the flag on its existing
//! synchronous entry points — `PeerManager::route_selected_capture` (every
//! capture callback) and `PeerManager::selected_lifecycle_tick` (the runtime's
//! ~8 ms service tick). Both reuse the exact cleanup path driven by
//! [`crate::PeerManager::native_capture_discontinued`], so a tripped failsafe
//! gates suppression and releases held input within one tick even if no
//! further capture events arrive.
//!
//! Observation is opt-in per manager via [`crate::PeerManager::arm_panic_failsafe`]
//! so embedded users (and parallel tests) that never arm a manager are
//! unaffected by the process-global flag. Production composition must arm the
//! manager and call [`install`] once; the daemon binary does both.

use std::panic;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{Once, OnceLock};

/// Process-global trip flag set by the panic hook and by [`trip`].
static FAILSAFE_TRIPPED: AtomicBool = AtomicBool::new(false);

/// Guards one-time hook installation so repeated [`install`] calls never wrap
/// the hook chain more than once.
static INSTALL: Once = Once::new();

/// 0 = never installed, 1 = installed. Lets tests restore the prior hook.
static INSTALLED: AtomicU8 = AtomicU8::new(0);

/// Lock-free wake callback invoked by [`trip`]. Registered once; never
/// unregistered. Must not acquire locks or allocate.
static WAKER: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Serializes tests that trip or clear the process-global flag. Rust's default
/// test harness runs tests in parallel within one binary; without this guard a
/// flag set by one test could be observed by another test's manager.
#[cfg(test)]
pub(crate) static TEST_TRIP_GUARD: Mutex<()> = Mutex::new(());

/// Installs the panic failsafe hook, preserving the previous hook's output.
///
/// Idempotent: the second and later calls are no-ops. The hook forwards every
/// panic to the previous hook before tripping the failsafe, so panic messages
/// and `tracing` output are unchanged.
pub fn install() {
    INSTALL.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            previous(info);
            trip();
        }));
        INSTALLED.store(1, Ordering::Release);
    });
}

/// Returns whether the panic failsafe hook has been installed.
#[must_use]
pub fn installed() -> bool {
    INSTALLED.load(Ordering::Acquire) == 1
}

/// Trips the process failsafe: sets the global flag and wakes the registered
/// waker.
///
/// The daemon runtime may call this explicitly for failures that are not
/// panics but must produce the same fail-open release. The panic hook itself
/// calls this on every panic. Only lock-free work happens here.
pub fn trip() {
    FAILSAFE_TRIPPED.store(true, Ordering::Release);
    if let Some(wake) = WAKER.get() {
        wake();
    }
}

/// Returns whether the process failsafe has tripped. Once tripped, the flag is
/// never cleared in production: recovery is a process restart.
#[must_use]
pub fn tripped() -> bool {
    FAILSAFE_TRIPPED.load(Ordering::Acquire)
}

/// Registers the one lock-free waker invoked by [`trip`].
///
/// Intended for the daemon runtime: the waker can, for example, kick the
/// select loop that drives `PeerManager::selected_lifecycle_tick`, so cleanup
/// starts immediately instead of waiting for the next periodic tick. The waker
/// must not acquire locks, allocate, or unwind; a second registration is
/// rejected in favour of the first.
///
/// # Errors
///
/// Returns the rejected callback when a waker is already registered.
pub fn register_waker(
    wake: Box<dyn Fn() + Send + Sync>,
) -> Result<(), Box<dyn Fn() + Send + Sync>> {
    WAKER.set(wake)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use super::*;

    /// Clears the trip flag. Test-only: production never clears a tripped
    /// failsafe. Callers must hold [`TEST_TRIP_GUARD`].
    fn clear_trip_for_test() {
        FAILSAFE_TRIPPED.store(false, Ordering::Release);
    }

    #[test]
    fn explicit_trip_sets_the_flag_and_waker_stays_invocable() {
        let _guard = TEST_TRIP_GUARD.lock().ok();
        clear_trip_for_test();
        assert!(!tripped());

        let woken = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&woken);
        // The first registration wins process-wide, so a later test may find
        // a waker already present; both paths must remain lock-free callable.
        if register_waker(Box::new(move || {
            observed.store(true, Ordering::Release);
        }))
        .is_ok()
        {
            trip();
            assert!(tripped());
            assert!(
                woken.load(Ordering::Acquire),
                "the registered waker must run on trip"
            );
        } else if let Some(wake) = WAKER.get() {
            trip();
            assert!(tripped());
            wake();
        }
        clear_trip_for_test();
    }

    #[test]
    fn at_most_one_waker_registration_wins() {
        let _guard = TEST_TRIP_GUARD.lock().ok();
        let first = register_waker(Box::new(|| {}));
        let second = register_waker(Box::new(|| {}));
        assert!(
            !(first.is_ok() && second.is_ok()),
            "a second waker must never replace the first"
        );
        if first.is_ok() {
            assert!(second.is_err());
        }
    }

    #[test]
    fn panic_through_the_hook_trips_the_failsafe_and_preserves_output() {
        let _guard = TEST_TRIP_GUARD.lock().ok();
        clear_trip_for_test();

        let previous_ran = Arc::new(AtomicBool::new(false));
        {
            let marker = Arc::clone(&previous_ran);
            panic::set_hook(Box::new(move |_info| {
                marker.store(true, Ordering::Release);
            }));
        }
        install();
        assert!(installed());
        assert!(!tripped(), "installation alone must not trip the failsafe");

        let joining = std::thread::spawn(|| {
            panic!("expected hook-installation failure");
        });
        let _ = joining.join();

        assert!(
            previous_ran.load(Ordering::Acquire),
            "the previous hook's output path must be preserved"
        );
        assert!(tripped(), "a panic through the hook must trip");
        // Leave a quiet hook behind so later panics in this test binary cannot
        // trip the flag under other tests. `Once` cannot re-arm `install`.
        let _ = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        clear_trip_for_test();
    }
}
