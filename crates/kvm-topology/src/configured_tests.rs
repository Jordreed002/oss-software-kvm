use kvm_types::{Display, DisplayId, Edge, HostId, Point, Rect, Size};

use super::*;

fn display_id(value: u8) -> DisplayId {
    DisplayId::from_bytes([value; 16])
}

fn host_id(value: u8) -> HostId {
    HostId::from_bytes([value; 16])
}

fn display(value: u8, host: u8, size: Size) -> Display {
    Display {
        id: display_id(value),
        host_id: host_id(host),
        name: format!("private-display-marker-{value}"),
        logical_size: size,
        physical_size: Some(Size::new(size.width * 2.0, size.height * 2.0)),
        scale_factor: 2.0,
        refresh_rate: Some(144.0),
        native_bounds: Rect::new(9_000.0, 8_000.0, size.width, size.height),
        primary: value == 1,
    }
}

fn placement(value: u8, x: f64, y: f64) -> WorkspacePlacement {
    WorkspacePlacement::new(display_id(value), Point::new(x, y))
}

fn link(source: u8, source_edge: Edge, destination: u8, destination_edge: Edge) -> WorkspaceLink {
    WorkspaceLink::new(
        display_id(source),
        source_edge,
        display_id(destination),
        destination_edge,
    )
}

fn two_display_candidate() -> (Vec<Display>, Vec<WorkspacePlacement>, Vec<WorkspaceLink>) {
    (
        vec![
            display(1, 10, Size::new(1920.0, 1080.0)),
            display(2, 20, Size::new(1512.0, 982.0)),
        ],
        vec![placement(1, 0.0, 0.0), placement(2, 1920.0, 0.0)],
        vec![
            link(1, Edge::Right, 2, Edge::Left),
            link(2, Edge::Left, 1, Edge::Right),
        ],
    )
}

fn compile_two() -> ConfiguredWorkspace {
    let (displays, placements, links) = two_display_candidate();
    ConfiguredWorkspaceCompiler::new()
        .compile_candidate(displays, placements, links)
        .unwrap()
}

fn assert_close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() <= 1.0e-9,
        "{actual} != {expected}"
    );
}

#[test]
fn explicit_links_are_the_only_transition_authority() {
    let workspace = compile_two();

    assert_eq!(workspace.epoch().get(), 1);
    assert_eq!(workspace.owner_of(display_id(1)), Some(host_id(10)));
    assert_eq!(workspace.owner_of(display_id(2)), Some(host_id(20)));
    assert_eq!(workspace.owner_of(display_id(99)), None);
    assert_eq!(workspace.host_count(), 2);
    assert_eq!(workspace.display_count(), 2);
    assert_eq!(workspace.link_count(), 2);

    let transition = workspace
        .transition(display_id(1), Edge::Right, 0.75)
        .unwrap();
    assert_eq!(transition.epoch(), workspace.epoch());
    assert_eq!(transition.source_display(), display_id(1));
    assert_eq!(transition.source_host(), host_id(10));
    assert_eq!(transition.source_edge(), Edge::Right);
    assert_eq!(transition.destination_display(), display_id(2));
    assert_eq!(transition.destination_host(), host_id(20));
    assert_eq!(transition.destination_edge(), Edge::Left);
    assert_close(transition.normalized_position(), 0.75);
    assert_eq!(transition.destination_point(), Point::new(0.0, 736.5));

    assert_eq!(
        workspace.transition(display_id(1), Edge::Bottom, 0.5),
        Err(WorkspaceTransitionError::NotLinked)
    );
    assert_eq!(
        workspace.transition(display_id(99), Edge::Right, 0.5),
        Err(WorkspaceTransitionError::UnknownDisplay)
    );
    assert_eq!(
        workspace.transition(display_id(1), Edge::Right, f64::NAN),
        Err(WorkspaceTransitionError::InvalidPosition)
    );
}

#[test]
fn local_point_containment_is_finite_bounded_and_includes_seam_endpoints() {
    let workspace = compile_two();
    let first = display_id(1);

    for point in [
        Point::new(0.0, 0.0),
        Point::new(1920.0, 0.0),
        Point::new(0.0, 1080.0),
        Point::new(1920.0, 1080.0),
        Point::new(960.0, 540.0),
    ] {
        assert!(workspace.contains_local_point(first, point));
    }
    for point in [
        Point::new(-f64::EPSILON, 0.0),
        Point::new(0.0, -f64::EPSILON),
        Point::new(1920.001, 0.0),
        Point::new(0.0, 1080.001),
        Point::new(f64::MAX, 0.0),
        Point::new(0.0, f64::MAX),
        Point::new(f64::NAN, 0.0),
        Point::new(0.0, f64::INFINITY),
    ] {
        assert!(!workspace.contains_local_point(first, point));
    }
    assert!(!workspace.contains_local_point(display_id(99), Point::new(0.0, 0.0)));
}

#[test]
fn mixed_dpi_mapping_uses_only_normalized_logical_size() {
    let mut first = display(1, 10, Size::new(1000.0, 800.0));
    first.physical_size = Some(Size::new(1000.0, 800.0));
    first.scale_factor = 1.0;
    first.refresh_rate = Some(60.0);
    let mut second = display(2, 20, Size::new(500.0, 1200.0));
    second.physical_size = Some(Size::new(3000.0, 7200.0));
    second.scale_factor = 6.0;
    second.refresh_rate = Some(240.0);

    let workspace = ConfiguredWorkspaceCompiler::new()
        .compile_candidate(
            [first, second],
            [placement(1, 0.0, 0.0), placement(2, 1000.0, 0.0)],
            [link(1, Edge::Right, 2, Edge::Left)],
        )
        .unwrap();
    let transition = workspace
        .transition(display_id(1), Edge::Right, 0.25)
        .unwrap();
    assert_eq!(transition.destination_point(), Point::new(0.0, 300.0));
}

#[test]
fn names_physical_geometry_scale_and_refresh_are_not_retained_as_workspace_state() {
    let (displays, placements, links) = two_display_candidate();
    let mut informationally_different = displays.clone();
    for display in &mut informationally_different {
        display.name = "another-private-name".repeat(4);
        display.physical_size = Some(Size::new(16_000.0, 9_000.0));
        display.scale_factor = 8.0;
        display.refresh_rate = Some(30.0);
        display.native_bounds = Rect::new(-50_000.0, 70_000.0, 100.0, 100.0);
        display.primary = !display.primary;
    }
    let first = ConfiguredWorkspaceCompiler::new()
        .compile_candidate(displays, placements.clone(), links.clone())
        .unwrap();
    let second = ConfiguredWorkspaceCompiler::new()
        .compile_candidate(informationally_different, placements, links)
        .unwrap();

    assert_eq!(first, second);
}

#[test]
fn asymmetric_partial_overlap_gates_geometry_then_maps_normalized_logical_position() {
    let workspace = ConfiguredWorkspaceCompiler::new()
        .compile_candidate(
            [
                display(1, 10, Size::new(1000.0, 1000.0)),
                display(2, 20, Size::new(400.0, 500.0)),
            ],
            [placement(1, 0.0, 0.0), placement(2, 1000.0, 250.0)],
            [link(1, Edge::Right, 2, Edge::Left)],
        )
        .unwrap();

    let transition = workspace
        .transition(display_id(1), Edge::Right, 0.3)
        .unwrap();
    // The workspace seam crossing is y=300 and is covered by the destination
    // at y=250..750. Mapping deliberately remains normalized logical mapping,
    // so destination y is 30% of its own 500-unit logical height.
    assert_eq!(transition.destination_point(), Point::new(0.0, 150.0));
    assert_eq!(
        workspace.transition(display_id(1), Edge::Right, 0.75),
        Err(WorkspaceTransitionError::InvalidWorkspace)
    );
}

#[test]
fn partial_overlap_must_cover_the_crossing_and_supports_seam_endpoints() {
    let workspace = ConfiguredWorkspaceCompiler::new()
        .compile_candidate(
            [
                display(1, 10, Size::new(100.0, 100.0)),
                display(2, 20, Size::new(100.0, 50.0)),
            ],
            [placement(1, 0.0, 0.0), placement(2, 100.0, 50.0)],
            [link(1, Edge::Right, 2, Edge::Left)],
        )
        .unwrap();

    assert_eq!(
        workspace.transition(display_id(1), Edge::Right, 0.49),
        Err(WorkspaceTransitionError::InvalidWorkspace)
    );
    assert!(workspace
        .transition(display_id(1), Edge::Right, 0.5)
        .is_ok());
    assert!(workspace
        .transition(display_id(1), Edge::Right, 1.0)
        .is_ok());
}

#[test]
fn gaps_corner_contacts_and_wrong_destination_edges_are_rejected() {
    let displays = [
        display(1, 10, Size::new(100.0, 100.0)),
        display(2, 20, Size::new(100.0, 100.0)),
    ];
    for (destination, expected) in [
        (
            WorkspacePlacement::new(display_id(2), Point::new(100.01, 0.0)),
            WorkspaceCompileError::InvalidLinkGeometry,
        ),
        (
            WorkspacePlacement::new(display_id(2), Point::new(100.0, 100.0)),
            WorkspaceCompileError::InvalidLinkGeometry,
        ),
    ] {
        let result = ConfiguredWorkspaceCompiler::new().compile_candidate(
            displays.clone(),
            [placement(1, 0.0, 0.0), destination],
            [link(1, Edge::Right, 2, Edge::Left)],
        );
        assert_eq!(result, Err(expected));
    }

    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            displays,
            [placement(1, 0.0, 0.0), placement(2, 100.0, 0.0)],
            [link(1, Edge::Right, 2, Edge::Top)],
        ),
        Err(WorkspaceCompileError::InvalidLinkGeometry)
    );
}

#[test]
fn identity_placement_and_link_references_fail_closed() {
    let valid = display(1, 10, Size::new(100.0, 100.0));
    let mut nil_display_value = valid.clone();
    nil_display_value.id = DisplayId::from_bytes([0; 16]);
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            [nil_display_value],
            [WorkspacePlacement::new(
                DisplayId::from_bytes([0; 16]),
                Point::new(0.0, 0.0),
            )],
            [],
        ),
        Err(WorkspaceCompileError::InvalidDisplay)
    );

    let mut nil_owner = valid.clone();
    nil_owner.host_id = HostId::from_bytes([0; 16]);
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            [nil_owner],
            [placement(1, 0.0, 0.0)],
            [],
        ),
        Err(WorkspaceCompileError::InvalidDisplay)
    );

    let mut collided = valid.clone();
    collided.host_id = host_id(99);
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            [valid.clone(), collided],
            [placement(1, 0.0, 0.0)],
            [],
        ),
        Err(WorkspaceCompileError::DuplicateDisplay)
    );
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate([valid.clone()], [], [],),
        Err(WorkspaceCompileError::MissingPlacement)
    );
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            [valid.clone()],
            [placement(2, 0.0, 0.0)],
            [],
        ),
        Err(WorkspaceCompileError::DanglingReference)
    );
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            [valid],
            [placement(1, 0.0, 0.0), placement(1, 1.0, 1.0)],
            [],
        ),
        Err(WorkspaceCompileError::DuplicatePlacement)
    );
}

#[test]
fn self_duplicate_dangling_and_conflicting_links_are_rejected() {
    let displays = [
        display(1, 10, Size::new(100.0, 100.0)),
        display(2, 20, Size::new(100.0, 100.0)),
        display(3, 30, Size::new(100.0, 100.0)),
    ];
    let placements = [
        placement(1, 0.0, 0.0),
        placement(2, 100.0, 0.0),
        placement(3, 0.0, 0.0),
    ];
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            displays.clone(),
            placements,
            [link(1, Edge::Right, 1, Edge::Left)],
        ),
        Err(WorkspaceCompileError::SelfLink)
    );
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            displays.clone(),
            placements,
            [
                link(1, Edge::Right, 2, Edge::Left),
                link(1, Edge::Right, 2, Edge::Left),
            ],
        ),
        Err(WorkspaceCompileError::DuplicateSourceEdge)
    );
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            displays.clone(),
            placements,
            [link(1, Edge::Right, 9, Edge::Left)],
        ),
        Err(WorkspaceCompileError::DanglingReference)
    );
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            displays,
            placements,
            [
                link(1, Edge::Right, 2, Edge::Left),
                link(2, Edge::Left, 3, Edge::Right),
            ],
        ),
        Err(WorkspaceCompileError::ConflictingReciprocalLink)
    );
}

#[test]
fn coordinates_display_size_workspace_extent_and_capacity_are_bounded() {
    let mut oversized = display(1, 10, Size::new(MAX_LOGICAL_DISPLAY_EXTENT + 1.0, 100.0));
    oversized.native_bounds.width = oversized.logical_size.width;
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            [oversized],
            [placement(1, 0.0, 0.0)],
            [],
        ),
        Err(WorkspaceCompileError::InvalidDisplay)
    );
    let valid = display(1, 10, Size::new(100.0, 100.0));
    for origin in [
        Point::new(f64::NAN, 0.0),
        Point::new(MAX_WORKSPACE_COORDINATE, 0.0),
    ] {
        assert_eq!(
            ConfiguredWorkspaceCompiler::new().compile_candidate(
                [valid.clone()],
                [WorkspacePlacement::new(display_id(1), origin)],
                [],
            ),
            Err(WorkspaceCompileError::InvalidGeometry)
        );
    }

    let far = MAX_WORKSPACE_EXTENT / 2.0 + 1.0;
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            [valid, display(2, 20, Size::new(100.0, 100.0)),],
            [placement(1, -far, 0.0), placement(2, far, 0.0)],
            [],
        ),
        Err(WorkspaceCompileError::InvalidGeometry)
    );

    let too_many = (0..=MAX_WORKSPACE_DISPLAYS).map(|index| {
        let byte = u8::try_from(index % 255 + 1).unwrap();
        display(byte, byte, Size::new(1.0, 1.0))
    });
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            too_many,
            std::iter::empty(),
            std::iter::empty(),
        ),
        Err(WorkspaceCompileError::CapacityExceeded)
    );

    let too_many_hosts = (1..=u8::try_from(MAX_WORKSPACE_HOSTS + 1).unwrap())
        .map(|value| display(value, value, Size::new(1.0, 1.0)));
    let host_placements = (1..=u8::try_from(MAX_WORKSPACE_HOSTS + 1).unwrap())
        .map(|value| placement(value, f64::from(value), 0.0));
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            too_many_hosts,
            host_placements,
            std::iter::empty(),
        ),
        Err(WorkspaceCompileError::CapacityExceeded)
    );

    let excessive_links = (0..=MAX_WORKSPACE_LINKS).map(|_| link(1, Edge::Right, 2, Edge::Left));
    assert_eq!(
        ConfiguredWorkspaceCompiler::new().compile_candidate(
            [
                display(1, 10, Size::new(100.0, 100.0)),
                display(2, 20, Size::new(100.0, 100.0)),
            ],
            [placement(1, 0.0, 0.0), placement(2, 100.0, 0.0)],
            excessive_links,
        ),
        Err(WorkspaceCompileError::CapacityExceeded)
    );
}

#[test]
fn finite_negative_placements_compile_without_implicit_links() {
    let workspace = ConfiguredWorkspaceCompiler::new()
        .compile_candidate(
            [
                display(1, 10, Size::new(100.0, 100.0)),
                display(2, 20, Size::new(100.0, 100.0)),
            ],
            [placement(1, -200.0, -100.0), placement(2, -100.0, -100.0)],
            [],
        )
        .unwrap();
    assert_eq!(
        workspace.transition(display_id(1), Edge::Right, 0.5),
        Err(WorkspaceTransitionError::NotLinked)
    );
}

#[test]
fn failed_candidate_never_replaces_active_or_consumes_an_epoch() {
    let mut compiler = ConfiguredWorkspaceCompiler::new();
    let (displays, placements, links) = two_display_candidate();
    let first = compiler
        .compile_candidate(displays.clone(), placements.clone(), links.clone())
        .unwrap();
    assert_eq!(first.epoch().get(), 1);

    assert_eq!(
        compiler.compile_candidate(
            displays.clone(),
            placements.clone(),
            [link(1, Edge::Bottom, 2, Edge::Top)],
        ),
        Err(WorkspaceCompileError::InvalidLinkGeometry)
    );
    assert_eq!(compiler.active().unwrap().epoch(), first.epoch());
    assert_eq!(
        compiler
            .active()
            .unwrap()
            .transition(display_id(1), Edge::Right, 0.5)
            .unwrap()
            .destination_display(),
        display_id(2)
    );

    let second = compiler
        .compile_candidate(displays, placements, links)
        .unwrap();
    assert_eq!(second.epoch().get(), 2);
}

#[test]
fn configured_and_legacy_diagnostics_redact_identifiers_names_and_coordinates() {
    let workspace = compile_two();
    let transition = workspace
        .transition(display_id(1), Edge::Right, 0.123_456_789)
        .unwrap();
    let placement = placement(1, 12_345.0, 54_321.0);
    let configured_link = link(1, Edge::Right, 2, Edge::Left);
    let invalid = WorkspaceDisplay::new(
        display(7, 8, Size::new(100.0, 100.0)),
        Rect::new(0.0, 0.0, 0.0, 1.0),
    )
    .unwrap_err();
    let legacy_display = WorkspaceDisplay::new(
        display(7, 8, Size::new(100.0, 100.0)),
        Rect::new(12_345.0, 54_321.0, 100.0, 100.0),
    )
    .unwrap();
    let legacy_transition = PointerTransition {
        display_id: display_id(7),
        entry_edge: Edge::Left,
        workspace_point: Point::new(12_345.0, 54_321.0),
        local_point: Point::new(0.0, 54_321.0),
        normalized_position: 0.123_456_789,
    };
    let legacy_topology = WorkspaceTopology::from_displays([legacy_display.clone()]).unwrap();
    let rendered = format!(
        "{workspace:?} {transition:?} {placement:?} {configured_link:?} {invalid:?} {invalid} \
         {legacy_display:?} {legacy_transition:?} {legacy_topology:?}"
    );
    for marker in [
        "private-display-marker",
        "12345",
        "54321",
        "0.123456789",
        &display_id(7).to_string(),
        &host_id(8).to_string(),
    ] {
        assert!(!rendered.contains(marker), "diagnostic leaked {marker}");
    }
}
