//! Canonical, platform-neutral input representation.
//!
//! Native backends should translate events into these physical key positions
//! immediately. Windows virtual-key codes and macOS key codes must never enter
//! shared routing or protocol logic.

mod event;
mod key;
mod pressed;
mod semantic;

pub use event::{ButtonState, InputEvent, InputPayload, KeyState, PointerButton};
pub use key::KeyCode;
pub use pressed::PressedState;
pub use semantic::{
    native_binding, resolve, translate, KeyboardMode, ModifierTracker, Modifiers, SemanticCommand,
    Shortcut,
};
