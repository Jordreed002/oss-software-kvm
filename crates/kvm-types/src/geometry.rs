use serde::{Deserialize, Serialize};

/// A point in a two-dimensional logical coordinate space.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    #[must_use]
    pub const fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// A two-dimensional logical extent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Size {
    pub width: f64,
    pub height: f64,
}

impl Size {
    #[must_use]
    pub const fn new(width: f64, height: f64) -> Self {
        Self { width, height }
    }

    #[must_use]
    pub fn is_valid(self) -> bool {
        self.width.is_finite() && self.height.is_finite() && self.width >= 0.0 && self.height >= 0.0
    }
}

/// An axis-aligned rectangle using half-open maximum edges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Rect {
    #[must_use]
    pub const fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    #[must_use]
    pub const fn from_origin_and_size(origin: Point, size: Size) -> Self {
        Self::new(origin.x, origin.y, size.width, size.height)
    }

    #[must_use]
    pub const fn origin(self) -> Point {
        Point::new(self.x, self.y)
    }

    #[must_use]
    pub const fn size(self) -> Size {
        Size::new(self.width, self.height)
    }

    #[must_use]
    pub const fn min_x(self) -> f64 {
        self.x
    }

    #[must_use]
    pub const fn min_y(self) -> f64 {
        self.y
    }

    #[must_use]
    pub fn max_x(self) -> f64 {
        self.x + self.width
    }

    #[must_use]
    pub fn max_y(self) -> f64 {
        self.y + self.height
    }

    #[must_use]
    pub fn is_valid(self) -> bool {
        self.x.is_finite()
            && self.y.is_finite()
            && self.size().is_valid()
            && self.max_x().is_finite()
            && self.max_y().is_finite()
    }

    /// Tests containment using `[min, max)` on both axes.
    #[must_use]
    pub fn contains(self, point: Point) -> bool {
        point.x >= self.min_x()
            && point.x < self.max_x()
            && point.y >= self.min_y()
            && point.y < self.max_y()
    }

    /// Clamps a point to the closed rectangle bounds.
    #[must_use]
    pub fn clamp(self, point: Point) -> Point {
        Point::new(
            point.x.clamp(self.min_x(), self.max_x()),
            point.y.clamp(self.min_y(), self.max_y()),
        )
    }
}

/// An edge of a display in logical workspace coordinates.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edge {
    Left,
    Right,
    Top,
    Bottom,
}

impl Edge {
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
            Self::Top => Self::Bottom,
            Self::Bottom => Self::Top,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_is_half_open() {
        let bounds = Rect::new(-10.0, 5.0, 20.0, 10.0);

        assert!(bounds.contains(Point::new(-10.0, 5.0)));
        assert!(bounds.contains(Point::new(9.999, 14.999)));
        assert!(!bounds.contains(Point::new(10.0, 10.0)));
        assert!(!bounds.contains(Point::new(0.0, 15.0)));
    }

    #[test]
    fn clamp_handles_points_on_both_sides() {
        let bounds = Rect::new(10.0, 20.0, 100.0, 50.0);

        assert_eq!(
            bounds.clamp(Point::new(-1.0, 100.0)),
            Point::new(10.0, 70.0)
        );
    }

    #[test]
    fn validity_rejects_negative_and_non_finite_geometry() {
        assert!(Rect::new(-100.0, 20.0, 10.0, 10.0).is_valid());
        assert!(!Rect::new(0.0, 0.0, -1.0, 10.0).is_valid());
        assert!(!Size::new(f64::NAN, 10.0).is_valid());
    }

    #[test]
    fn every_edge_has_an_inverse() {
        for edge in [Edge::Left, Edge::Right, Edge::Top, Edge::Bottom] {
            assert_eq!(edge.opposite().opposite(), edge);
        }
    }
}
