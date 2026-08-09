//! Canonical, platform-neutral input representation.
//!
//! Native backends should translate events into these physical key positions
//! immediately. Windows virtual-key codes and macOS key codes must never enter
//! shared routing or protocol logic.

mod event;
mod key;
mod pressed;
mod semantic;

#[cfg(feature = "latency")]
mod instrumentation;

#[cfg(feature = "event-rate")]
mod event_rate;

pub use event::{ButtonState, InputEvent, InputPayload, KeyState, PointerButton};
pub use key::KeyCode;
pub use pressed::PressedState;
pub use semantic::{
    native_binding, resolve, translate, ModifierTracker, Modifiers, SemanticCommand, Shortcut,
};
pub use kvm_types::KeyboardMode;

#[cfg(feature = "latency")]
pub use instrumentation::{LatencyHistory, LatencyStage, LatencyStamps, LatencyStats};

#[cfg(feature = "event-rate")]
pub use event_rate::{EventRateConfig, EventRateConfigError, EventRateMeter, EventRateSnapshot};
