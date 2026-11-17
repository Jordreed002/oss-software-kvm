//! Bounded input admission with route generations for the Software KVM Rust
//! rebuild.
//!
//! This crate implements the direction set by
//! `docs/adr/0004-bounded-input-admission.md`: a synchronous, single-owner
//! admission engine that stages [`kvm_foundation`] input events behind an
//! exact route epoch, with no I/O, threads, timers, synchronization,
//! `unsafe` code or heap allocation. Its only dependency is the replacement
//! foundation; nothing from the legacy router, runtime or platform
//! orchestration is imported.
//!
//! # Standing invariants
//!
//! * Nothing here is synchronized. [`InputEngine`] holds no locks or atomics;
//!   one owning session context serializes every call, and concurrent use
//!   requires external synchronization owned by the caller.
//! * Route epochs carry identity (process instance, peer, generation), not
//!   cryptographic authentication and not installed application identity.
//! * Successful admission proves only that one bounded, currently-valid event
//!   entered the queue. It does not prove peer delivery and does not by itself
//!   authorize native input suppression: a native adapter may suppress only
//!   after successful bounded admission while its committed generation remains
//!   current. This crate implements no native callback and solves no
//!   cross-thread publication.
//! * Event timestamps and the caller-supplied current time are host-local
//!   readings of one monotonic clock. This crate never compares timestamps
//!   across hosts.
//! * A fault latches admission closed for the life of the engine. There is no
//!   unlatch, no coalescing, no priority reordering and no catch-up burst in
//!   this increment: all event families share one ordered FIFO.
//! * The engine never forwards queued input after close or fault. Removing an
//!   event from the queue is not delivery: the owner must separately fence
//!   already-consumed work and reconcile remote held input, and clearing the
//!   queue is not cleanup confirmation.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

pub mod engine;
pub mod identity;

pub use engine::{
    ActivateError, CloseError, ConsumeError, DiscardError, EngineSnapshot, EngineState,
    EnqueueError, FaultReason, InputEngine, MaxEventAge,
};
pub use identity::{InstanceId, PeerId, RouteEpoch};
