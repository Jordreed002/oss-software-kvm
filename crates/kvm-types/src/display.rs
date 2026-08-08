use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{DisplayId, HostId, Rect, Size};

/// A display reported by a platform backend.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Display {
    pub id: DisplayId,
    pub host_id: HostId,
    pub name: String,
    /// Size in the platform's logical coordinate units.
    pub logical_size: Size,
    /// Physical pixel dimensions, if reported reliably.
    pub physical_size: Option<Size>,
    pub scale_factor: f64,
    /// Informational metadata only; routing must not depend on it.
    pub refresh_rate: Option<f64>,
    /// Display bounds in the owning host's native logical coordinate system.
    pub native_bounds: Rect,
    pub primary: bool,
}

impl fmt::Debug for Display {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Display([REDACTED])")
    }
}

impl Display {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.logical_size.is_valid()
            && self.logical_size.width > 0.0
            && self.logical_size.height > 0.0
            && self.physical_size.is_none_or(Size::is_valid)
            && self.scale_factor.is_finite()
            && self.scale_factor > 0.0
            && self
                .refresh_rate
                .is_none_or(|rate| rate.is_finite() && rate > 0.0)
            && self.native_bounds.is_valid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display() -> Display {
        Display {
            id: DisplayId::from_bytes([4; 16]),
            host_id: HostId::from_bytes([5; 16]),
            name: "Retina".into(),
            logical_size: Size::new(1512.0, 982.0),
            physical_size: Some(Size::new(3024.0, 1964.0)),
            scale_factor: 2.0,
            refresh_rate: Some(120.0),
            native_bounds: Rect::new(0.0, 0.0, 1512.0, 982.0),
            primary: true,
        }
    }

    #[test]
    fn realistic_display_is_valid() {
        assert!(display().is_valid());
    }

    #[test]
    fn invalid_scale_or_refresh_rate_is_rejected() {
        let mut value = display();
        value.scale_factor = 0.0;
        assert!(!value.is_valid());

        value.scale_factor = 2.0;
        value.refresh_rate = Some(f64::NAN);
        assert!(!value.is_valid());
    }

    #[test]
    fn debug_omits_name_identity_and_geometry() {
        let mut value = display();
        value.name = "peer-controlled-display-marker".into();

        let rendered = format!("{value:?}");
        assert_eq!(rendered, "Display([REDACTED])");
        assert!(!rendered.contains("peer-controlled-display-marker"));
        assert!(!rendered.contains("1512"));
    }
}
