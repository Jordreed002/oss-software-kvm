use kvm_types::{Display, DisplayId, Edge, HostId, Point, Rect, Size};

use super::*;

const HOST: HostId = HostId::from_bytes([1; 16]);

fn id(value: u8) -> DisplayId {
    DisplayId::from_bytes([value; 16])
}

fn placed(value: u8, bounds: Rect, logical_size: Size, scale_factor: f64) -> WorkspaceDisplay {
    WorkspaceDisplay::new(
        Display {
            id: id(value),
            host_id: HOST,
            name: format!("Display {value}"),
            logical_size,
            physical_size: Some(Size::new(
                logical_size.width * scale_factor,
                logical_size.height * scale_factor,
            )),
            scale_factor,
            refresh_rate: Some(60.0),
            native_bounds: Rect::new(0.0, 0.0, logical_size.width, logical_size.height),
            primary: value == 1,
        },
        bounds,
    )
    .unwrap()
}

fn topology(displays: impl IntoIterator<Item = WorkspaceDisplay>) -> WorkspaceTopology {
    WorkspaceTopology::from_displays(displays).unwrap()
}

fn assert_close(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1.0e-9, "{actual} != {expected}");
}

#[test]
fn display_lookup_is_half_open_and_handles_negative_workspace_coordinates() {
    let topology = topology([
        placed(
            1,
            Rect::new(-1920.0, 0.0, 1920.0, 1080.0),
            Size::new(1920.0, 1080.0),
            1.0,
        ),
        placed(
            2,
            Rect::new(0.0, 0.0, 2560.0, 1440.0),
            Size::new(2560.0, 1440.0),
            1.0,
        ),
    ]);

    assert_eq!(topology.display_at(Point::new(-1.0, 100.0)), Some(id(1)));
    assert_eq!(topology.display_at(Point::new(0.0, 100.0)), Some(id(2)));
    assert_eq!(topology.display_at(Point::new(2560.0, 100.0)), None);
    assert_eq!(topology.display_at(Point::new(f64::NAN, 0.0)), None);
}

#[test]
fn horizontal_and_vertical_edges_find_touching_displays() {
    let topology = topology([
        placed(
            1,
            Rect::new(0.0, 0.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
        placed(
            2,
            Rect::new(100.0, 0.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
        placed(
            3,
            Rect::new(0.0, 100.0, 100.0, 80.0),
            Size::new(100.0, 80.0),
            2.0,
        ),
    ]);

    assert_eq!(
        topology.adjacent_display(id(1), Edge::Right, 0.5),
        Some(id(2))
    );
    assert_eq!(
        topology.adjacent_display(id(2), Edge::Left, 0.5),
        Some(id(1))
    );
    assert_eq!(
        topology.adjacent_display(id(1), Edge::Bottom, 0.5),
        Some(id(3))
    );
    assert_eq!(
        topology.adjacent_display(id(3), Edge::Top, 0.5),
        Some(id(1))
    );
    assert_eq!(topology.adjacent_display(id(1), Edge::Top, 0.5), None);
}

#[test]
fn normalized_mapping_handles_mismatched_resolution_and_retina_dpi() {
    let topology = topology([
        placed(
            1,
            Rect::new(0.0, 0.0, 1920.0, 1080.0),
            Size::new(1920.0, 1080.0),
            1.0,
        ),
        placed(
            2,
            Rect::new(1920.0, 0.0, 1512.0, 982.0),
            Size::new(1512.0, 982.0),
            2.0,
        ),
    ]);

    let normalized = topology
        .normalized_edge_position(id(1), Edge::Right, Point::new(1920.0, 810.0))
        .unwrap();
    assert_close(normalized, 0.75);

    let transition = topology.transition(id(1), Edge::Right, normalized).unwrap();
    assert_eq!(transition.display_id, id(2));
    assert_eq!(transition.entry_edge, Edge::Left);
    assert_eq!(transition.workspace_point, Point::new(1920.0, 736.5));
    assert_eq!(transition.local_point, Point::new(0.0, 736.5));
    assert_close(transition.normalized_position, 0.75);
}

#[test]
fn a_gap_does_not_create_an_implicit_connection() {
    let topology = topology([
        placed(
            1,
            Rect::new(0.0, 0.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
        placed(
            2,
            Rect::new(100.01, 0.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
    ]);

    assert_eq!(topology.adjacent_display(id(1), Edge::Right, 0.5), None);
    assert_eq!(topology.transition(id(1), Edge::Right, 0.5), None);
}

#[test]
fn partial_edge_overlap_only_connects_where_the_target_exists() {
    let topology = topology([
        placed(
            1,
            Rect::new(0.0, 0.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
        placed(
            2,
            Rect::new(100.0, 50.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
    ]);

    assert_eq!(topology.adjacent_display(id(1), Edge::Right, 0.25), None);
    assert_eq!(
        topology.adjacent_display(id(1), Edge::Right, 0.75),
        Some(id(2))
    );
}

#[test]
fn overlap_lookup_and_ambiguous_adjacency_are_deterministic() {
    let topology = topology([
        placed(
            9,
            Rect::new(0.0, 0.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
        placed(
            3,
            Rect::new(50.0, 50.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
        placed(
            7,
            Rect::new(100.0, 0.0, 80.0, 100.0),
            Size::new(80.0, 100.0),
            1.0,
        ),
        placed(
            2,
            Rect::new(100.0, 0.0, 90.0, 100.0),
            Size::new(90.0, 100.0),
            1.0,
        ),
    ]);

    assert_eq!(topology.display_at(Point::new(75.0, 75.0)), Some(id(3)));
    assert_eq!(
        topology.adjacent_display(id(9), Edge::Right, 0.25),
        Some(id(2))
    );
}

#[test]
fn exact_seams_use_half_open_spans_and_final_endpoint_is_supported() {
    let topology = topology([
        placed(
            1,
            Rect::new(0.0, 0.0, 100.0, 100.0),
            Size::new(100.0, 100.0),
            1.0,
        ),
        placed(
            2,
            Rect::new(100.0, 0.0, 100.0, 50.0),
            Size::new(100.0, 50.0),
            1.0,
        ),
        placed(
            3,
            Rect::new(100.0, 50.0, 100.0, 50.0),
            Size::new(100.0, 50.0),
            1.0,
        ),
    ]);

    assert_eq!(
        topology.adjacent_display(id(1), Edge::Right, 0.0),
        Some(id(2))
    );
    assert_eq!(
        topology.adjacent_display(id(1), Edge::Right, 0.5),
        Some(id(3))
    );
    assert_eq!(
        topology.adjacent_display(id(1), Edge::Right, 1.0),
        Some(id(3))
    );
    assert_eq!(topology.adjacent_display(id(1), Edge::Right, -0.01), None);
    assert_eq!(
        topology.adjacent_display(id(1), Edge::Right, f64::NAN),
        None
    );
}

#[test]
fn invalid_workspace_geometry_is_rejected() {
    let display = placed(
        1,
        Rect::new(0.0, 0.0, 100.0, 100.0),
        Size::new(100.0, 100.0),
        1.0,
    )
    .display;

    assert_eq!(
        WorkspaceDisplay::new(display, Rect::new(0.0, 0.0, 0.0, 100.0)),
        Err(TopologyError::InvalidWorkspaceBounds(id(1)))
    );
}
