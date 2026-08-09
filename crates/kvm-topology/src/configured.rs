use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use kvm_types::{Display, DisplayId, Edge, HostId, Point, Rect, Size};
use sha2::{Digest, Sha256};

use crate::{close, covers, perpendicular_coordinate, touches, valid_position, GEOMETRY_EPSILON};

/// Positive bound for hosts represented by one compiled workspace.
pub const MAX_WORKSPACE_HOSTS: usize = 32;
/// Positive bound for inventory displays represented by one compiled workspace.
pub const MAX_WORKSPACE_DISPLAYS: usize = 256;
/// Positive bound for directed configured edge links.
pub const MAX_WORKSPACE_LINKS: usize = MAX_WORKSPACE_DISPLAYS * 4;
/// Maximum logical width or height of one display.
pub const MAX_LOGICAL_DISPLAY_EXTENT: f64 = 131_072.0;
/// Maximum absolute placement coordinate or rectangle boundary.
pub const MAX_WORKSPACE_COORDINATE: f64 = 1_000_000.0;
/// Maximum width or height of the complete workspace envelope.
pub const MAX_WORKSPACE_EXTENT: f64 = 1_000_000.0;

/// Nonzero monotonically increasing identity of one compiled workspace.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspaceEpoch(u64);

impl WorkspaceEpoch {
    /// Restores a nonzero epoch supplied by a trusted local state boundary.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for WorkspaceEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkspaceEpoch(..)")
    }
}

/// Explicit origin assigned to one current inventory display.
#[derive(Clone, Copy, PartialEq)]
pub struct WorkspacePlacement {
    display_id: DisplayId,
    origin: Point,
}

impl WorkspacePlacement {
    #[must_use]
    pub const fn new(display_id: DisplayId, origin: Point) -> Self {
        Self { display_id, origin }
    }

    #[must_use]
    pub const fn display_id(self) -> DisplayId {
        self.display_id
    }

    #[must_use]
    pub const fn origin(self) -> Point {
        self.origin
    }
}

impl fmt::Debug for WorkspacePlacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkspacePlacement([REDACTED])")
    }
}

/// One directed, explicit configured display-edge link.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WorkspaceLink {
    source_display: DisplayId,
    source_edge: Edge,
    destination_display: DisplayId,
    destination_edge: Edge,
}

impl WorkspaceLink {
    #[must_use]
    pub const fn new(
        source_display: DisplayId,
        source_edge: Edge,
        destination_display: DisplayId,
        destination_edge: Edge,
    ) -> Self {
        Self {
            source_display,
            source_edge,
            destination_display,
            destination_edge,
        }
    }

    #[must_use]
    pub const fn source_display(self) -> DisplayId {
        self.source_display
    }

    #[must_use]
    pub const fn source_edge(self) -> Edge {
        self.source_edge
    }

    #[must_use]
    pub const fn destination_display(self) -> DisplayId {
        self.destination_display
    }

    #[must_use]
    pub const fn destination_edge(self) -> Edge {
        self.destination_edge
    }
}

impl fmt::Debug for WorkspaceLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkspaceLink([REDACTED])")
    }
}

#[derive(Clone, PartialEq)]
struct InventoryDisplay {
    host_id: HostId,
    logical_size: Size,
}

#[derive(Clone, PartialEq)]
struct CompiledDisplay {
    host_id: HostId,
    logical_size: Size,
    workspace_bounds: Rect,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LinkTarget {
    display_id: DisplayId,
    edge: Edge,
}

#[derive(Clone, PartialEq)]
struct CompiledWorkspaceData {
    epoch: WorkspaceEpoch,
    protocol_epoch: u64,
    displays: BTreeMap<DisplayId, CompiledDisplay>,
    links: BTreeMap<(DisplayId, u8), LinkTarget>,
    host_count: usize,
}

/// Immutable, bounded logical workspace compiled from authenticated inventory.
#[derive(Clone, PartialEq)]
pub struct ConfiguredWorkspace {
    data: Arc<CompiledWorkspaceData>,
}

impl ConfiguredWorkspace {
    #[must_use]
    pub fn epoch(&self) -> WorkspaceEpoch {
        self.data.epoch
    }

    /// Deterministic nonzero identity shared by peers that compiled the same
    /// authenticated display geometry and links. Unlike [`Self::epoch`], this
    /// value is independent of how many local recompilations occurred.
    #[must_use]
    pub fn protocol_epoch(&self) -> u64 {
        self.data.protocol_epoch
    }

    #[must_use]
    pub fn owner_of(&self, display_id: DisplayId) -> Option<HostId> {
        self.data
            .displays
            .get(&display_id)
            .map(|entry| entry.host_id)
    }

    /// Reports whether a point is inside one display's local logical extent.
    ///
    /// The maximum edges are included because an exact configured transition
    /// may land on a destination's right or bottom seam. Unknown displays,
    /// non-finite coordinates, and points outside the bounded extent fail
    /// closed.
    #[must_use]
    pub fn contains_local_point(&self, display_id: DisplayId, point: Point) -> bool {
        let Some(display) = self.data.displays.get(&display_id) else {
            return false;
        };
        point.x.is_finite()
            && point.y.is_finite()
            && point.x >= 0.0
            && point.y >= 0.0
            && point.x <= display.logical_size.width
            && point.y <= display.logical_size.height
    }

    #[must_use]
    pub fn display_count(&self) -> usize {
        self.data.displays.len()
    }

    #[must_use]
    pub fn host_count(&self) -> usize {
        self.data.host_count
    }

    #[must_use]
    pub fn link_count(&self) -> usize {
        self.data.links.len()
    }

    /// Resolves only an explicit configured link whose destination covers the
    /// normalized source crossing coordinate.
    ///
    /// # Errors
    ///
    /// Returns a coarse error for an invalid normalized position, unavailable
    /// source display, unconfigured source edge, or inconsistent geometry.
    pub fn transition(
        &self,
        source_display: DisplayId,
        source_edge: Edge,
        normalized_position: f64,
    ) -> Result<WorkspaceTransition, WorkspaceTransitionError> {
        if !valid_position(normalized_position) {
            return Err(WorkspaceTransitionError::InvalidPosition);
        }
        let source = self
            .data
            .displays
            .get(&source_display)
            .ok_or(WorkspaceTransitionError::UnknownDisplay)?;
        let target = self
            .data
            .links
            .get(&(source_display, edge_key(source_edge)))
            .copied()
            .ok_or(WorkspaceTransitionError::NotLinked)?;
        let destination = self
            .data
            .displays
            .get(&target.display_id)
            .ok_or(WorkspaceTransitionError::InvalidWorkspace)?;
        let crossing =
            perpendicular_coordinate(source.workspace_bounds, source_edge, normalized_position);
        if target.edge != source_edge.opposite()
            || !touches(
                source.workspace_bounds,
                destination.workspace_bounds,
                source_edge,
            )
            || !covers(
                destination.workspace_bounds,
                source_edge,
                crossing,
                close(normalized_position, 1.0),
            )
        {
            return Err(WorkspaceTransitionError::InvalidWorkspace);
        }

        let logical_size = destination.logical_size;
        let destination_point = match target.edge {
            Edge::Left => Point::new(0.0, normalized_position * logical_size.height),
            Edge::Right => Point::new(
                logical_size.width,
                normalized_position * logical_size.height,
            ),
            Edge::Top => Point::new(normalized_position * logical_size.width, 0.0),
            Edge::Bottom => Point::new(
                normalized_position * logical_size.width,
                logical_size.height,
            ),
        };
        if !destination_point.x.is_finite() || !destination_point.y.is_finite() {
            return Err(WorkspaceTransitionError::InvalidWorkspace);
        }

        Ok(WorkspaceTransition {
            epoch: self.data.epoch,
            source_display,
            source_host: source.host_id,
            source_edge,
            destination_display: target.display_id,
            destination_host: destination.host_id,
            destination_edge: target.edge,
            normalized_position,
            destination_point,
        })
    }
}

impl fmt::Debug for ConfiguredWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredWorkspace")
            .field("epoch", &self.data.epoch)
            .field("host_count", &self.data.host_count)
            .field("display_count", &self.data.displays.len())
            .field("link_count", &self.data.links.len())
            .finish_non_exhaustive()
    }
}

/// Atomic compiler retaining the last valid immutable workspace.
#[derive(Default)]
pub struct ConfiguredWorkspaceCompiler {
    active: Option<ConfiguredWorkspace>,
    last_epoch: u64,
}

impl ConfiguredWorkspaceCompiler {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: None,
            last_epoch: 0,
        }
    }

    #[must_use]
    pub const fn active(&self) -> Option<&ConfiguredWorkspace> {
        self.active.as_ref()
    }

    /// Compiles and atomically installs one complete candidate.
    ///
    /// Failed validation or epoch exhaustion leaves the previous workspace active.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when a resource bound, identity, placement, link,
    /// geometry, or epoch invariant is not satisfied.
    pub fn compile_candidate<D, P, L>(
        &mut self,
        displays: D,
        placements: P,
        links: L,
    ) -> Result<ConfiguredWorkspace, WorkspaceCompileError>
    where
        D: IntoIterator<Item = Display>,
        P: IntoIterator<Item = WorkspacePlacement>,
        L: IntoIterator<Item = WorkspaceLink>,
    {
        let next_epoch = self
            .last_epoch
            .checked_add(1)
            .and_then(WorkspaceEpoch::new)
            .ok_or(WorkspaceCompileError::EpochExhausted)?;
        let candidate = compile_workspace(next_epoch, displays, placements, links)?;
        self.active = Some(candidate.clone());
        self.last_epoch = next_epoch.get();
        Ok(candidate)
    }
}

impl fmt::Debug for ConfiguredWorkspaceCompiler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredWorkspaceCompiler")
            .field("has_active_workspace", &self.active.is_some())
            .finish_non_exhaustive()
    }
}

fn compile_workspace<D, P, L>(
    epoch: WorkspaceEpoch,
    displays: D,
    placements: P,
    links: L,
) -> Result<ConfiguredWorkspace, WorkspaceCompileError>
where
    D: IntoIterator<Item = Display>,
    P: IntoIterator<Item = WorkspacePlacement>,
    L: IntoIterator<Item = WorkspaceLink>,
{
    let displays = collect_bounded(displays, MAX_WORKSPACE_DISPLAYS)?;
    if displays.is_empty() {
        return Err(WorkspaceCompileError::MissingDisplay);
    }
    let placements = collect_bounded(placements, MAX_WORKSPACE_DISPLAYS)?;
    let links = collect_bounded(links, MAX_WORKSPACE_LINKS)?;

    let (inventory, host_count) = compile_inventory(displays)?;
    let compiled_displays = compile_placements(&inventory, placements)?;
    validate_workspace_extent(
        compiled_displays
            .values()
            .map(|entry| entry.workspace_bounds),
    )?;
    let compiled_links = compile_links(&compiled_displays, links)?;
    let protocol_epoch = protocol_epoch(&compiled_displays, &compiled_links);

    Ok(ConfiguredWorkspace {
        data: Arc::new(CompiledWorkspaceData {
            epoch,
            protocol_epoch,
            displays: compiled_displays,
            links: compiled_links,
            host_count,
        }),
    })
}

fn protocol_epoch(
    displays: &BTreeMap<DisplayId, CompiledDisplay>,
    links: &BTreeMap<(DisplayId, u8), LinkTarget>,
) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"software-kvm-workspace-v1\0");
    digest.update((displays.len() as u64).to_be_bytes());
    for (display_id, display) in displays {
        digest.update(display_id.into_bytes());
        digest.update(display.host_id.into_bytes());
        for value in [
            display.logical_size.width,
            display.logical_size.height,
            display.workspace_bounds.x,
            display.workspace_bounds.y,
            display.workspace_bounds.width,
            display.workspace_bounds.height,
        ] {
            digest.update(canonical_float_bits(value).to_be_bytes());
        }
    }
    digest.update((links.len() as u64).to_be_bytes());
    for ((source_display, source_edge), target) in links {
        digest.update(source_display.into_bytes());
        digest.update([*source_edge]);
        digest.update(target.display_id.into_bytes());
        digest.update([edge_key(target.edge)]);
    }
    let bytes: [u8; 32] = digest.finalize().into();
    u64::from_be_bytes(bytes[..8].try_into().expect("fixed digest prefix")).max(1)
}

fn canonical_float_bits(value: f64) -> u64 {
    if value == 0.0 {
        0
    } else {
        value.to_bits()
    }
}

fn compile_inventory(
    displays: Vec<Display>,
) -> Result<(BTreeMap<DisplayId, InventoryDisplay>, usize), WorkspaceCompileError> {
    let mut inventory = BTreeMap::new();
    let mut hosts = BTreeSet::new();
    for display in displays {
        if nil_display(display.id)
            || nil_host(display.host_id)
            || !valid_inventory_geometry(&display)
        {
            return Err(WorkspaceCompileError::InvalidDisplay);
        }
        let host_id = display.host_id;
        let inventory_display = InventoryDisplay {
            host_id,
            logical_size: display.logical_size,
        };
        if inventory.insert(display.id, inventory_display).is_some() {
            return Err(WorkspaceCompileError::DuplicateDisplay);
        }
        hosts.insert(host_id);
        if hosts.len() > MAX_WORKSPACE_HOSTS {
            return Err(WorkspaceCompileError::CapacityExceeded);
        }
    }
    Ok((inventory, hosts.len()))
}

fn compile_placements(
    inventory: &BTreeMap<DisplayId, InventoryDisplay>,
    placements: Vec<WorkspacePlacement>,
) -> Result<BTreeMap<DisplayId, CompiledDisplay>, WorkspaceCompileError> {
    let mut compiled_displays = BTreeMap::new();
    for placement in placements {
        let display = inventory
            .get(&placement.display_id)
            .ok_or(WorkspaceCompileError::DanglingReference)?;
        if compiled_displays.contains_key(&placement.display_id) {
            return Err(WorkspaceCompileError::DuplicatePlacement);
        }
        let bounds = Rect::from_origin_and_size(placement.origin, display.logical_size);
        if !valid_workspace_bounds(bounds) {
            return Err(WorkspaceCompileError::InvalidGeometry);
        }
        compiled_displays.insert(
            placement.display_id,
            CompiledDisplay {
                host_id: display.host_id,
                logical_size: display.logical_size,
                workspace_bounds: bounds,
            },
        );
    }
    if compiled_displays.len() != inventory.len() {
        return Err(WorkspaceCompileError::MissingPlacement);
    }
    Ok(compiled_displays)
}

fn compile_links(
    compiled_displays: &BTreeMap<DisplayId, CompiledDisplay>,
    links: Vec<WorkspaceLink>,
) -> Result<BTreeMap<(DisplayId, u8), LinkTarget>, WorkspaceCompileError> {
    let mut compiled_links = BTreeMap::new();
    for link in links {
        if link.source_display == link.destination_display {
            return Err(WorkspaceCompileError::SelfLink);
        }
        let source = compiled_displays
            .get(&link.source_display)
            .ok_or(WorkspaceCompileError::DanglingReference)?;
        let destination = compiled_displays
            .get(&link.destination_display)
            .ok_or(WorkspaceCompileError::DanglingReference)?;
        if link.destination_edge != link.source_edge.opposite()
            || !touches(
                source.workspace_bounds,
                destination.workspace_bounds,
                link.source_edge,
            )
            || overlap_length(
                source.workspace_bounds,
                destination.workspace_bounds,
                link.source_edge,
            ) <= GEOMETRY_EPSILON
        {
            return Err(WorkspaceCompileError::InvalidLinkGeometry);
        }
        let key = (link.source_display, edge_key(link.source_edge));
        let target = LinkTarget {
            display_id: link.destination_display,
            edge: link.destination_edge,
        };
        if compiled_links.insert(key, target).is_some() {
            return Err(WorkspaceCompileError::DuplicateSourceEdge);
        }
    }

    for ((source_display, source_edge), target) in &compiled_links {
        if let Some(reverse) = compiled_links.get(&(target.display_id, edge_key(target.edge))) {
            let expected = LinkTarget {
                display_id: *source_display,
                edge: edge_from_key(*source_edge),
            };
            if *reverse != expected {
                return Err(WorkspaceCompileError::ConflictingReciprocalLink);
            }
        }
    }
    Ok(compiled_links)
}

fn collect_bounded<T>(
    values: impl IntoIterator<Item = T>,
    maximum: usize,
) -> Result<Vec<T>, WorkspaceCompileError> {
    let mut collected = Vec::with_capacity(maximum.min(16));
    for value in values {
        if collected.len() == maximum {
            return Err(WorkspaceCompileError::CapacityExceeded);
        }
        collected.push(value);
    }
    Ok(collected)
}

fn valid_inventory_geometry(display: &Display) -> bool {
    display.is_valid()
        && display.logical_size.width <= MAX_LOGICAL_DISPLAY_EXTENT
        && display.logical_size.height <= MAX_LOGICAL_DISPLAY_EXTENT
}

fn valid_workspace_bounds(bounds: Rect) -> bool {
    bounds.is_valid()
        && bounds.width > 0.0
        && bounds.height > 0.0
        && bounds.x.abs() <= MAX_WORKSPACE_COORDINATE
        && bounds.y.abs() <= MAX_WORKSPACE_COORDINATE
        && bounds.max_x().abs() <= MAX_WORKSPACE_COORDINATE
        && bounds.max_y().abs() <= MAX_WORKSPACE_COORDINATE
}

fn validate_workspace_extent(
    bounds: impl IntoIterator<Item = Rect>,
) -> Result<(), WorkspaceCompileError> {
    let mut bounds = bounds.into_iter();
    let first = bounds.next().ok_or(WorkspaceCompileError::MissingDisplay)?;
    let (mut min_x, mut min_y, mut max_x, mut max_y) =
        (first.min_x(), first.min_y(), first.max_x(), first.max_y());
    for value in bounds {
        min_x = min_x.min(value.min_x());
        min_y = min_y.min(value.min_y());
        max_x = max_x.max(value.max_x());
        max_y = max_y.max(value.max_y());
    }
    let width = max_x - min_x;
    let height = max_y - min_y;
    if !width.is_finite()
        || !height.is_finite()
        || width > MAX_WORKSPACE_EXTENT
        || height > MAX_WORKSPACE_EXTENT
    {
        return Err(WorkspaceCompileError::InvalidGeometry);
    }
    Ok(())
}

fn overlap_length(source: Rect, destination: Rect, edge: Edge) -> f64 {
    let (source_start, source_end, destination_start, destination_end) = match edge {
        Edge::Left | Edge::Right => (
            source.min_y(),
            source.max_y(),
            destination.min_y(),
            destination.max_y(),
        ),
        Edge::Top | Edge::Bottom => (
            source.min_x(),
            source.max_x(),
            destination.min_x(),
            destination.max_x(),
        ),
    };
    source_end.min(destination_end) - source_start.max(destination_start)
}

const fn edge_key(edge: Edge) -> u8 {
    match edge {
        Edge::Left => 0,
        Edge::Right => 1,
        Edge::Top => 2,
        Edge::Bottom => 3,
    }
}

const fn edge_from_key(key: u8) -> Edge {
    match key {
        0 => Edge::Left,
        1 => Edge::Right,
        2 => Edge::Top,
        _ => Edge::Bottom,
    }
}

fn nil_display(display_id: DisplayId) -> bool {
    display_id.into_bytes() == [0; 16]
}

fn nil_host(host_id: HostId) -> bool {
    host_id.into_bytes() == [0; 16]
}

/// Complete, deterministic transition derived from the active workspace.
#[derive(Clone, Copy, PartialEq)]
pub struct WorkspaceTransition {
    epoch: WorkspaceEpoch,
    source_display: DisplayId,
    source_host: HostId,
    source_edge: Edge,
    destination_display: DisplayId,
    destination_host: HostId,
    destination_edge: Edge,
    normalized_position: f64,
    destination_point: Point,
}

impl WorkspaceTransition {
    #[must_use]
    pub const fn epoch(self) -> WorkspaceEpoch {
        self.epoch
    }
    #[must_use]
    pub const fn source_display(self) -> DisplayId {
        self.source_display
    }
    #[must_use]
    pub const fn source_host(self) -> HostId {
        self.source_host
    }
    #[must_use]
    pub const fn source_edge(self) -> Edge {
        self.source_edge
    }
    #[must_use]
    pub const fn destination_display(self) -> DisplayId {
        self.destination_display
    }
    #[must_use]
    pub const fn destination_host(self) -> HostId {
        self.destination_host
    }
    #[must_use]
    pub const fn destination_edge(self) -> Edge {
        self.destination_edge
    }
    #[must_use]
    pub const fn normalized_position(self) -> f64 {
        self.normalized_position
    }
    #[must_use]
    pub const fn destination_point(self) -> Point {
        self.destination_point
    }
}

impl fmt::Debug for WorkspaceTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkspaceTransition([REDACTED])")
    }
}

/// Coarse candidate compilation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceCompileError {
    CapacityExceeded,
    MissingDisplay,
    InvalidDisplay,
    DuplicateDisplay,
    DanglingReference,
    DuplicatePlacement,
    MissingPlacement,
    InvalidGeometry,
    SelfLink,
    DuplicateSourceEdge,
    ConflictingReciprocalLink,
    InvalidLinkGeometry,
    EpochExhausted,
}

impl fmt::Display for WorkspaceCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CapacityExceeded => "workspace candidate exceeds a resource bound",
            Self::MissingDisplay => "workspace candidate has no displays",
            Self::InvalidDisplay => "workspace candidate contains invalid display metadata",
            Self::DuplicateDisplay => "workspace candidate contains duplicate display identity",
            Self::DanglingReference => "workspace candidate contains a dangling reference",
            Self::DuplicatePlacement => "workspace candidate contains duplicate placement",
            Self::MissingPlacement => "workspace candidate leaves a display unplaced",
            Self::InvalidGeometry => "workspace candidate geometry is invalid",
            Self::SelfLink => "workspace candidate contains a self-link",
            Self::DuplicateSourceEdge => "workspace candidate reuses a source edge",
            Self::ConflictingReciprocalLink => "workspace candidate links conflict",
            Self::InvalidLinkGeometry => "workspace candidate link geometry is invalid",
            Self::EpochExhausted => "workspace epoch is exhausted",
        })
    }
}

impl Error for WorkspaceCompileError {}

/// Coarse explicit-transition lookup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceTransitionError {
    InvalidPosition,
    UnknownDisplay,
    NotLinked,
    InvalidWorkspace,
}

impl fmt::Display for WorkspaceTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPosition => "workspace transition position is invalid",
            Self::UnknownDisplay => "workspace transition display is unavailable",
            Self::NotLinked => "workspace transition edge is not configured",
            Self::InvalidWorkspace => "workspace transition geometry is invalid",
        })
    }
}

impl Error for WorkspaceTransitionError {}

#[cfg(test)]
mod internal_tests {
    use super::*;

    #[test]
    fn epoch_exhaustion_is_reported_before_candidate_state_changes() {
        let mut compiler = ConfiguredWorkspaceCompiler {
            active: None,
            last_epoch: u64::MAX,
        };
        assert_eq!(
            compiler.compile_candidate(
                std::iter::empty::<Display>(),
                std::iter::empty::<WorkspacePlacement>(),
                std::iter::empty::<WorkspaceLink>(),
            ),
            Err(WorkspaceCompileError::EpochExhausted)
        );
        assert!(compiler.active().is_none());
    }
}
