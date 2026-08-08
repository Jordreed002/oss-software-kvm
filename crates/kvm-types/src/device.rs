use serde::{Deserialize, Serialize};

use crate::{DeviceId, HostId};

/// Coarse physical-device category used for routing and presentation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Keyboard,
    Mouse,
    Trackpad,
    Other,
}

/// Input features exposed by a physical device.
// Individual booleans are intentional here: capabilities compose independently
// and this representation stays explicit and stable in configuration data.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub pointer: bool,
    pub keyboard: bool,
    pub vertical_scroll: bool,
    pub horizontal_scroll: bool,
    pub extra_buttons: bool,
}

impl DeviceCapabilities {
    pub const NONE: Self = Self {
        pointer: false,
        keyboard: false,
        vertical_scroll: false,
        horizontal_scroll: false,
        extra_buttons: false,
    };

    pub const KEYBOARD: Self = Self {
        keyboard: true,
        ..Self::NONE
    };

    pub const POINTER: Self = Self {
        pointer: true,
        ..Self::NONE
    };

    /// Returns whether this capability set contains every feature in `required`.
    #[must_use]
    pub const fn supports(self, required: Self) -> bool {
        (!required.pointer || self.pointer)
            && (!required.keyboard || self.keyboard)
            && (!required.vertical_scroll || self.vertical_scroll)
            && (!required.horizontal_scroll || self.horizontal_scroll)
            && (!required.extra_buttons || self.extra_buttons)
    }
}

/// A physical input source detected by a platform backend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InputDevice {
    pub id: DeviceId,
    pub host_id: HostId,
    pub name: String,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub kind: DeviceKind,
    pub capabilities: DeviceCapabilities,
}

impl InputDevice {
    #[must_use]
    pub fn new(
        id: DeviceId,
        host_id: HostId,
        name: impl Into<String>,
        kind: DeviceKind,
        capabilities: DeviceCapabilities,
    ) -> Self {
        Self {
            id,
            host_id,
            name: name.into(),
            vendor_id: None,
            product_id: None,
            kind,
            capabilities,
        }
    }
}

/// Configured destination policy for one physical device.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRoute {
    FollowActiveHost,
    Local,
    Host(HostId),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_matching_requires_only_requested_features() {
        let mouse = DeviceCapabilities {
            pointer: true,
            vertical_scroll: true,
            extra_buttons: true,
            ..DeviceCapabilities::NONE
        };

        assert!(mouse.supports(DeviceCapabilities::POINTER));
        assert!(!mouse.supports(DeviceCapabilities::KEYBOARD));
    }

    #[test]
    fn new_device_leaves_optional_usb_identity_unknown() {
        let device = InputDevice::new(
            DeviceId::from_bytes([2; 16]),
            HostId::from_bytes([3; 16]),
            "Built-in Trackpad",
            DeviceKind::Trackpad,
            DeviceCapabilities::POINTER,
        );

        assert_eq!(device.vendor_id, None);
        assert_eq!(device.product_id, None);
        assert_eq!(device.name, "Built-in Trackpad");
    }
}
