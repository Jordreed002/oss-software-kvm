use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{DisplayId, HostId, Point};

/// The single logical pointer shared by all follow-active-host devices.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LogicalPointer {
    pub display_id: DisplayId,
    pub x: f64,
    pub y: f64,
}

impl fmt::Debug for LogicalPointer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LogicalPointer([REDACTED])")
    }
}

impl LogicalPointer {
    #[must_use]
    pub const fn new(display_id: DisplayId, x: f64, y: f64) -> Self {
        Self { display_id, x, y }
    }

    #[must_use]
    pub const fn position(self) -> Point {
        Point::new(self.x, self.y)
    }

    pub fn set_position(&mut self, position: Point) {
        self.x = position.x;
        self.y = position.y;
    }
}

/// Router-visible state for a host's view of the shared workspace.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceState {
    pub local_host: HostId,
    pub active_host: HostId,
    pub active_display: DisplayId,
    pub pointer: LogicalPointer,
}

impl fmt::Debug for WorkspaceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkspaceState([REDACTED])")
    }
}

impl WorkspaceState {
    #[must_use]
    pub const fn new(local_host: HostId, active_host: HostId, pointer: LogicalPointer) -> Self {
        Self {
            local_host,
            active_host,
            active_display: pointer.display_id,
            pointer,
        }
    }

    /// Updates the active display and pointer atomically from the caller's view.
    pub fn set_active_pointer(&mut self, active_host: HostId, pointer: LogicalPointer) {
        self.active_host = active_host;
        self.active_display = pointer.display_id;
        self.pointer = pointer;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changing_pointer_keeps_active_display_consistent() {
        let local = HostId::from_bytes([1; 16]);
        let remote = HostId::from_bytes([2; 16]);
        let first = DisplayId::from_bytes([3; 16]);
        let second = DisplayId::from_bytes([4; 16]);
        let mut state = WorkspaceState::new(local, local, LogicalPointer::new(first, 1.0, 2.0));

        state.set_active_pointer(remote, LogicalPointer::new(second, 3.0, 4.0));

        assert_eq!(state.active_host, remote);
        assert_eq!(state.active_display, second);
        assert_eq!(state.pointer.display_id, second);
    }

    #[test]
    fn workspace_debug_omits_stable_identity_and_coordinates() {
        let marker = [0x71; 16];
        let host = HostId::from_bytes(marker);
        let display = DisplayId::from_bytes(marker);
        let pointer = LogicalPointer::new(display, 7171.25, 8383.5);
        let state = WorkspaceState::new(host, host, pointer);

        assert_eq!(format!("{pointer:?}"), "LogicalPointer([REDACTED])");
        assert_eq!(format!("{state:?}"), "WorkspaceState([REDACTED])");
    }
}
