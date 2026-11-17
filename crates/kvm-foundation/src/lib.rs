//! Dependency-free foundation values and bounded storage for the Software KVM
//! Rust rebuild.
//!
//! This crate is the first increment of the ground-up rebuild described in
//! `docs/adr/0003-ground-up-rebuild.md`: compact, `Copy` physical input event
//! values and a fixed-capacity, single-owner FIFO ring used to stage them. It
//! has no dependencies, no platform code and no runtime; capture, transport,
//! session ownership and routing authority all live elsewhere.
//!
//! # Standing invariants
//!
//! * Nothing in this crate is synchronized. [`RingFifo`] uses no locks or
//!   atomics; its owner serializes every access, and concurrent use requires
//!   external synchronization owned by the caller.
//! * Event timestamps are host-local. They support comparison only within one
//!   host's clock, and can never establish cross-host latency by subtraction.
//! * Event values confer no routing authority. They are observations of
//!   physical input, not permissions, and they do not imply that capture or
//!   injection succeeded anywhere.

pub mod event;
pub mod queue;

pub use event::{DeviceId, EventKind, InputEvent, KeyCode, PointerButton, Timestamp, Transition};
pub use queue::RingFifo;
