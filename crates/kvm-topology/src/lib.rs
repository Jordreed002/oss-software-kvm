//! Deterministic display lookup, edge adjacency, and normalized transitions.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use kvm_types::{Display, DisplayId, Edge, Point, Rect};

mod configured;

pub use configured::{
    ConfiguredWorkspace, ConfiguredWorkspaceCompiler, WorkspaceCompileError, WorkspaceEpoch,
    WorkspaceLink, WorkspacePlacement, WorkspaceTransition, WorkspaceTransitionError,
    MAX_LOGICAL_DISPLAY_EXTENT, MAX_WORKSPACE_COORDINATE, MAX_WORKSPACE_DISPLAYS,
    MAX_WORKSPACE_EXTENT, MAX_WORKSPACE_HOSTS, MAX_WORKSPACE_LINKS,
};

const GEOMETRY_EPSILON: f64 = 1.0e-9;

/// A platform display placed in the shared logical workspace.
#[derive(Clone, PartialEq)]
pub struct WorkspaceDisplay {
    pub display: Display,
    pub workspace_bounds: Rect,
}

impl fmt::Debug for WorkspaceDisplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceDisplay")
            .field("display", &"[REDACTED]")
            .field("workspace_geometry", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl WorkspaceDisplay {
    /// Creates a validated display placement.
    ///
    /// # Errors
    ///
    /// Returns [`TopologyError::InvalidDisplay`] when native display metadata is
    /// invalid, or [`TopologyError::InvalidWorkspaceBounds`] when the workspace
    /// rectangle is non-finite or has no area.
    pub fn new(display: Display, workspace_bounds: Rect) -> Result<Self, TopologyError> {
        if !display.is_valid() {
            return Err(TopologyError::InvalidDisplay(display.id));
        }
        if !valid_bounds(workspace_bounds) {
            return Err(TopologyError::InvalidWorkspaceBounds(display.id));
        }
        Ok(Self {
            display,
            workspace_bounds,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TopologyError {
    InvalidDisplay(DisplayId),
    InvalidWorkspaceBounds(DisplayId),
}

impl fmt::Debug for TopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDisplay(_) => "TopologyError::InvalidDisplay",
            Self::InvalidWorkspaceBounds(_) => "TopologyError::InvalidWorkspaceBounds",
        })
    }
}

impl fmt::Display for TopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDisplay(_) => formatter.write_str("display has invalid metadata"),
            Self::InvalidWorkspaceBounds(_) => {
                formatter.write_str("display has invalid workspace bounds")
            }
        }
    }
}

impl Error for TopologyError {}

/// Result of crossing one display edge into another.
#[derive(Clone, Copy, PartialEq)]
pub struct PointerTransition {
    pub display_id: DisplayId,
    pub entry_edge: Edge,
    /// Position in destination workspace coordinates, on its entry edge.
    pub workspace_point: Point,
    /// Position in destination-display local logical coordinates.
    pub local_point: Point,
    pub normalized_position: f64,
}

impl fmt::Debug for PointerTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerTransition([REDACTED])")
    }
}

/// All displays arranged in a single logical coordinate system.
#[derive(Clone, Default, PartialEq)]
pub struct WorkspaceTopology {
    pub displays: HashMap<DisplayId, WorkspaceDisplay>,
}

impl fmt::Debug for WorkspaceTopology {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceTopology")
            .field("display_count", &self.displays.len())
            .finish_non_exhaustive()
    }
}

impl WorkspaceTopology {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a topology from validated display placements.
    ///
    /// # Errors
    ///
    /// Returns the first validation error encountered in `displays`.
    pub fn from_displays(
        displays: impl IntoIterator<Item = WorkspaceDisplay>,
    ) -> Result<Self, TopologyError> {
        let mut topology = Self::new();
        for workspace_display in displays {
            topology.insert(workspace_display)?;
        }
        Ok(topology)
    }

    /// Adds or replaces a display after validating both native and workspace geometry.
    ///
    /// # Errors
    ///
    /// Returns [`TopologyError::InvalidDisplay`] or
    /// [`TopologyError::InvalidWorkspaceBounds`] if the placement is invalid.
    pub fn insert(
        &mut self,
        workspace_display: WorkspaceDisplay,
    ) -> Result<Option<WorkspaceDisplay>, TopologyError> {
        let id = workspace_display.display.id;
        if !workspace_display.display.is_valid() {
            return Err(TopologyError::InvalidDisplay(id));
        }
        if !valid_bounds(workspace_display.workspace_bounds) {
            return Err(TopologyError::InvalidWorkspaceBounds(id));
        }
        Ok(self.displays.insert(id, workspace_display))
    }

    pub fn remove(&mut self, display: DisplayId) -> Option<WorkspaceDisplay> {
        self.displays.remove(&display)
    }

    #[must_use]
    pub fn get(&self, display: DisplayId) -> Option<&WorkspaceDisplay> {
        self.displays.get(&display)
    }

    /// Finds the display containing `point`. Overlaps resolve by stable display ID.
    #[must_use]
    pub fn display_at(&self, point: Point) -> Option<DisplayId> {
        if !point.x.is_finite() || !point.y.is_finite() {
            return None;
        }
        self.displays
            .iter()
            .filter(|(_, display)| {
                valid_bounds(display.workspace_bounds) && display.workspace_bounds.contains(point)
            })
            .map(|(id, _)| *id)
            .min()
    }

    /// Finds a display touching the requested edge at a normalized source position.
    ///
    /// A visual gap is intentionally not bridged; epsilon only absorbs floating-point noise.
    /// If overlapping candidates share the same boundary, stable ID order wins.
    #[must_use]
    pub fn adjacent_display(
        &self,
        display: DisplayId,
        edge: Edge,
        position: f64,
    ) -> Option<DisplayId> {
        if !valid_position(position) {
            return None;
        }
        let source = self.displays.get(&display)?.workspace_bounds;
        if !valid_bounds(source) {
            return None;
        }
        let coordinate = perpendicular_coordinate(source, edge, position);

        self.displays
            .iter()
            .filter(|(id, candidate)| {
                **id != display
                    && valid_bounds(candidate.workspace_bounds)
                    && touches(source, candidate.workspace_bounds, edge)
                    && covers(
                        candidate.workspace_bounds,
                        edge,
                        coordinate,
                        close(position, 1.0),
                    )
            })
            .map(|(id, _)| *id)
            .min()
    }

    /// Converts a workspace point on/near an edge to a normalized edge position.
    #[must_use]
    pub fn normalized_edge_position(
        &self,
        display: DisplayId,
        edge: Edge,
        point: Point,
    ) -> Option<f64> {
        let bounds = self.displays.get(&display)?.workspace_bounds;
        if !valid_bounds(bounds)
            || !point.x.is_finite()
            || !point.y.is_finite()
            || !point_is_on_edge(bounds, edge, point)
        {
            return None;
        }
        let position = match edge {
            Edge::Left | Edge::Right => (point.y - bounds.min_y()) / bounds.height,
            Edge::Top | Edge::Bottom => (point.x - bounds.min_x()) / bounds.width,
        };
        Some(position.clamp(0.0, 1.0))
    }

    /// Maps a normalized position to a point on a destination display edge.
    #[must_use]
    pub fn map_edge_position(
        &self,
        display: DisplayId,
        edge: Edge,
        position: f64,
    ) -> Option<Point> {
        if !valid_position(position) {
            return None;
        }
        let bounds = self.displays.get(&display)?.workspace_bounds;
        if !valid_bounds(bounds) {
            return None;
        }
        Some(point_at(bounds, edge, position))
    }

    /// Finds an adjacent display and maps the normalized position onto it.
    #[must_use]
    pub fn transition(
        &self,
        display: DisplayId,
        exit_edge: Edge,
        position: f64,
    ) -> Option<PointerTransition> {
        let destination = self.adjacent_display(display, exit_edge, position)?;
        let entry_edge = exit_edge.opposite();
        let workspace_bounds = self.displays.get(&destination)?.workspace_bounds;
        if !valid_bounds(workspace_bounds) {
            return None;
        }
        let workspace_point = point_at(workspace_bounds, entry_edge, position);
        Some(PointerTransition {
            display_id: destination,
            entry_edge,
            workspace_point,
            local_point: Point::new(
                workspace_point.x - workspace_bounds.x,
                workspace_point.y - workspace_bounds.y,
            ),
            normalized_position: position,
        })
    }
}

fn valid_bounds(bounds: Rect) -> bool {
    bounds.is_valid() && bounds.width > 0.0 && bounds.height > 0.0
}

fn valid_position(position: f64) -> bool {
    position.is_finite() && (0.0..=1.0).contains(&position)
}

fn close(left: f64, right: f64) -> bool {
    (left - right).abs() <= GEOMETRY_EPSILON
}

fn touches(source: Rect, candidate: Rect, edge: Edge) -> bool {
    match edge {
        Edge::Left => close(candidate.max_x(), source.min_x()),
        Edge::Right => close(candidate.min_x(), source.max_x()),
        Edge::Top => close(candidate.max_y(), source.min_y()),
        Edge::Bottom => close(candidate.min_y(), source.max_y()),
    }
}

fn perpendicular_coordinate(bounds: Rect, edge: Edge, position: f64) -> f64 {
    match edge {
        Edge::Left | Edge::Right => bounds.min_y() + position * bounds.height,
        Edge::Top | Edge::Bottom => bounds.min_x() + position * bounds.width,
    }
}

fn covers(bounds: Rect, edge: Edge, coordinate: f64, terminal: bool) -> bool {
    let (start, end) = match edge {
        Edge::Left | Edge::Right => (bounds.min_y(), bounds.max_y()),
        Edge::Top | Edge::Bottom => (bounds.min_x(), bounds.max_x()),
    };
    coordinate >= start - GEOMETRY_EPSILON
        && (coordinate < end - GEOMETRY_EPSILON || (terminal && close(coordinate, end)))
}

fn point_is_on_edge(bounds: Rect, edge: Edge, point: Point) -> bool {
    let (on_line, coordinate, start, end) = match edge {
        Edge::Left => (
            close(point.x, bounds.min_x()),
            point.y,
            bounds.min_y(),
            bounds.max_y(),
        ),
        Edge::Right => (
            close(point.x, bounds.max_x()),
            point.y,
            bounds.min_y(),
            bounds.max_y(),
        ),
        Edge::Top => (
            close(point.y, bounds.min_y()),
            point.x,
            bounds.min_x(),
            bounds.max_x(),
        ),
        Edge::Bottom => (
            close(point.y, bounds.max_y()),
            point.x,
            bounds.min_x(),
            bounds.max_x(),
        ),
    };
    on_line && coordinate >= start - GEOMETRY_EPSILON && coordinate <= end + GEOMETRY_EPSILON
}

fn point_at(bounds: Rect, edge: Edge, position: f64) -> Point {
    match edge {
        Edge::Left => Point::new(bounds.min_x(), bounds.min_y() + position * bounds.height),
        Edge::Right => Point::new(bounds.max_x(), bounds.min_y() + position * bounds.height),
        Edge::Top => Point::new(bounds.min_x() + position * bounds.width, bounds.min_y()),
        Edge::Bottom => Point::new(bounds.min_x() + position * bounds.width, bounds.max_y()),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod configured_tests;
