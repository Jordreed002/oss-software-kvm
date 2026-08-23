import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ArrangeStep } from "./DisplayLayoutEditor";
import { makeDisplay, makeSnapshot } from "../test/fixtures";
import type { SetupSnapshot } from "../types";

/** One 1000x800 local display + one 1000x800 peer display. With two such
 *  displays the editor's auto-fit scale is min(0.16, 690/2000, 285/800) = 0.16,
 *  which the drag test relies on when converting pixel deltas to map units. */
function deskSnapshot(overrides: Partial<SetupSnapshot> = {}): SetupSnapshot {
  const base = makeSnapshot();
  return makeSnapshot({
    displays: [makeDisplay("local-1", { name: "Built-in display" })],
    peer: base.peer ? { ...base.peer, displays: [makeDisplay("peer-1", { name: "Studio monitor" })] } : null,
    ...overrides,
  });
}

const saveButton = () => screen.getByRole("button", { name: /Save display map/ });

beforeAll(() => {
  // jsdom has no pointer capture; the editor calls it on pointer-down.
  Element.prototype.setPointerCapture = vi.fn();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("ArrangeStep (display-layout editor)", () => {
  it("shows a ready handoff edge and enables saving for the default side-by-side map", () => {
    render(<ArrangeStep snapshot={deskSnapshot()} busy={null} onContinue={vi.fn()} />);
    expect(screen.getByText("HANDOFF EDGE READY")).toBeInTheDocument();
    expect(saveButton()).toBeEnabled();
  });

  it("demands an edge link when the stored layout separates the two hosts", () => {
    render(
      <ArrangeStep
        snapshot={deskSnapshot({
          displayLayout: [
            { displayId: "local-1", x: 0, y: 0 },
            { displayId: "peer-1", x: 3_000, y: 0 },
          ],
        })}
        busy={null}
        onContinue={vi.fn()}
      />,
    );
    expect(screen.getByText("CONNECT THE TWO COMPUTERS")).toBeInTheDocument();
    expect(saveButton()).toBeDisabled();
  });

  it("rejects overlapping screens even though an edge exists", () => {
    render(
      <ArrangeStep
        snapshot={deskSnapshot({
          displayLayout: [
            { displayId: "local-1", x: 0, y: 0 },
            { displayId: "peer-1", x: 500, y: 0 },
          ],
        })}
        busy={null}
        onContinue={vi.fn()}
      />,
    );
    expect(screen.getByText("SCREENS CANNOT OVERLAP")).toBeInTheDocument();
    expect(saveButton()).toBeDisabled();
  });

  it("locks the map to the leader's copy when following a peer", () => {
    render(<ArrangeStep snapshot={deskSnapshot({ workspaceRole: "follower" })} busy={null} onContinue={vi.fn()} />);
    expect(screen.getByText("FOLLOWING THE PAIRING LEADER")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Reset arrangement/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Waiting for leader map/ })).toBeDisabled();
  });

  it("drags a display across the map, snaps it to the far edge, and saves the layout", () => {
    const onContinue = vi.fn();
    render(
      <ArrangeStep
        snapshot={deskSnapshot({
          displayLayout: [
            { displayId: "local-1", x: 0, y: 0 },
            { displayId: "peer-1", x: 3_000, y: 0 },
          ],
        })}
        busy={null}
        onContinue={onContinue}
      />,
    );
    expect(screen.getByText("CONNECT THE TWO COMPUTERS")).toBeInTheDocument();

    // Drag the peer display left by 2000 map units = 320 px at scale 0.16.
    const peerDisplay = screen.getByRole("button", { name: /Office Windows/ });
    fireEvent.pointerDown(peerDisplay, { pointerId: 7, clientX: 0, clientY: 0 });
    fireEvent.pointerMove(peerDisplay, { pointerId: 7, clientX: -320, clientY: 0 });
    fireEvent.pointerUp(peerDisplay, { pointerId: 7, clientX: -320, clientY: 0 });

    expect(screen.getByText("HANDOFF EDGE READY")).toBeInTheDocument();
    fireEvent.click(saveButton());
    expect(onContinue).toHaveBeenCalledTimes(1);
    expect(onContinue).toHaveBeenCalledWith(
      "local_left",
      [
        { displayId: "local-1", x: 0, y: 0 },
        { displayId: "peer-1", x: 1_000, y: 0 },
      ],
    );
  });
});
