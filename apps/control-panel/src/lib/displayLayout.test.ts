import { describe, expect, it } from "vitest";
import { makeDisplay, makeSnapshot } from "../test/fixtures";
import {
  defaultDisplayLayout, hasCrossHostEdge, hasDisplayOverlap, mappedDisplays, snapDisplay,
} from "./displayLayout";

/** One local 1000x800 display plus one peer 1000x800 display — the smallest
 *  desk where every edge/snap rule is exercisable. */
function twoHostDesk(overrides: Partial<Parameters<typeof makeSnapshot>[0]> = {}) {
  const base = makeSnapshot();
  const snapshot = makeSnapshot({
    displays: [makeDisplay("local-1", { name: "Built-in display" })],
    peer: base.peer ? { ...base.peer, displays: [makeDisplay("peer-1", { name: "Studio monitor" })] } : null,
    ...overrides,
  });
  return { snapshot, displays: mappedDisplays(snapshot) };
}

describe("mappedDisplays", () => {
  it("tags each display with its owner, host name, and sequential number", () => {
    const { snapshot, displays } = twoHostDesk();
    expect(displays).toHaveLength(2);
    expect(displays[0]).toMatchObject({ id: "local-1", owner: "local", hostName: "Jordan’s Mac", number: 1 });
    expect(displays[1]).toMatchObject({ id: "peer-1", owner: "peer", hostName: "Office Windows", number: 2 });
  });

  it("falls back to generic host names when identities are missing", () => {
    const snapshot = makeSnapshot({ local: null, peer: null });
    const displays = mappedDisplays(snapshot);
    expect(displays).toHaveLength(1);
    expect(displays[0].hostName).toBe("This computer");
  });
});

describe("defaultDisplayLayout", () => {
  it("lays local displays out left of the peer for local_left placement", () => {
    const { snapshot, displays } = twoHostDesk();
    expect(defaultDisplayLayout(snapshot, displays)).toEqual([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_000, y: 0 },
    ]);
  });

  it("puts the peer group first for local_right placement", () => {
    const { snapshot, displays } = twoHostDesk({ placement: "local_right" });
    expect(defaultDisplayLayout(snapshot, displays)).toEqual([
      { displayId: "peer-1", x: 0, y: 0 },
      { displayId: "local-1", x: 1_000, y: 0 },
    ]);
  });

  it("reuses a stored layout when it covers the same displays, normalized to origin", () => {
    const { snapshot, displays } = twoHostDesk({
      displayLayout: [
        { displayId: "local-1", x: 120, y: 40 },
        { displayId: "peer-1", x: 1_120, y: 60 },
      ],
    });
    expect(defaultDisplayLayout(snapshot, displays)).toEqual([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_000, y: 20 },
    ]);
  });

  it("ignores a stored layout that does not match the current display set", () => {
    const { snapshot, displays } = twoHostDesk({
      displayLayout: [{ displayId: "gone", x: 5, y: 5 }],
    });
    expect(defaultDisplayLayout(snapshot, displays)).toEqual([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_000, y: 0 },
    ]);
  });
});

describe("hasCrossHostEdge", () => {
  it("detects local and peer displays sharing a vertical edge", () => {
    const { displays } = twoHostDesk();
    const layout = [
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_000, y: 0 },
    ];
    expect(hasCrossHostEdge(layout, displays)).toBe(true);
  });

  it("detects a horizontal shared edge (screens stacked)", () => {
    const { displays } = twoHostDesk();
    const layout = [
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 0, y: 800 },
    ];
    expect(hasCrossHostEdge(layout, displays)).toBe(true);
  });

  it("rejects a gap, a diagonal offset, and same-host edges", () => {
    const { displays } = twoHostDesk();
    expect(hasCrossHostEdge([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_200, y: 0 },
    ], displays)).toBe(false);
    expect(hasCrossHostEdge([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_000, y: 900 },
    ], displays)).toBe(false);
    // Touching edges that belong to the same host do not create a handoff edge.
    expect(hasCrossHostEdge([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "local-1", x: 1_000, y: 0 },
    ], displays)).toBe(false);
  });
});

describe("hasDisplayOverlap", () => {
  it("flags intersecting rectangles but not edge-adjacent ones", () => {
    const { displays } = twoHostDesk();
    expect(hasDisplayOverlap([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 500, y: 0 },
    ], displays)).toBe(true);
    expect(hasDisplayOverlap([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_000, y: 0 },
    ], displays)).toBe(false);
  });
});

describe("snapDisplay", () => {
  it("snaps a display that lands within the horizontal threshold", () => {
    const { displays } = twoHostDesk();
    const snapped = snapDisplay([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 990, y: 10 },
    ], "peer-1", displays, 1);
    expect(snapped).toEqual([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_000, y: 10 },
    ]);
  });

  it("snaps vertically for stacked screens", () => {
    const { displays } = twoHostDesk();
    const snapped = snapDisplay([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 150, y: 790 },
    ], "peer-1", displays, 1);
    expect(snapped[1]).toEqual({ displayId: "peer-1", x: 150, y: 800 });
  });

  it("leaves a display outside the snap threshold where it was dropped", () => {
    const { displays } = twoHostDesk();
    const snapped = snapDisplay([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_030, y: 10 },
    ], "peer-1", displays, 1);
    expect(snapped[1]).toEqual({ displayId: "peer-1", x: 1_030, y: 10 });
  });

  it("normalizes the layout back to the origin after snapping", () => {
    const { displays } = twoHostDesk();
    const snapped = snapDisplay([
      { displayId: "local-1", x: 400, y: 200 },
      { displayId: "peer-1", x: 1_390, y: 210 },
    ], "peer-1", displays, 1);
    expect(snapped).toEqual([
      { displayId: "local-1", x: 0, y: 0 },
      { displayId: "peer-1", x: 1_000, y: 10 },
    ]);
  });
});
