import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { CaptureTable } from "./CaptureTable";
import { makeCapture, makeReport } from "../../test/fixtures";

const localReport = makeReport({
  capture: makeCapture({
    observed: 12_000,
    suppressed: 8_000,
    allowedLocal: 3_990,
    pointerObservations: 9_000,
    pointerTransitions: 0,
    cursorHides: 0,
    cursorShows: 0,
    cursorWarps: 8,
    lockContention: 2,
    callbackPanics: 0,
    pointerObservationFailures: 0,
  }),
});

function rowLabels(): string[] {
  const table = screen.getByRole("table");
  return within(table)
    .getAllByRole("row")
    .slice(1) // header row
    .map((row) => (row as HTMLTableRowElement).cells[0]?.textContent ?? "");
}

describe("CaptureTable", () => {
  it("lists every counter sorted alphabetically by default", () => {
    render(<CaptureTable label="Native input capture · aggregate counters" local={localReport} peer={null} />);
    expect(rowLabels()).toEqual([
      "Allowed locally (fail-open)",
      "Callback panics",
      "Cursor hides",
      "Cursor shows",
      "Cursor warps",
      "Events observed",
      "Lock contention",
      "Pointer handoff transitions",
      "Pointer observation failures",
      "Pointer observations",
      "Suppressed (remote routing)",
    ]);
  });

  it("sorts by the raw counter, descending, when a host column is clicked", () => {
    render(<CaptureTable label="Counters" local={localReport} peer={null} />);
    fireEvent.click(screen.getByRole("button", { name: /This computer/ }));
    const labels = rowLabels();
    expect(labels.slice(0, 6)).toEqual([
      "Events observed", // 12000
      "Pointer observations", // 9000
      "Suppressed (remote routing)", // 8000
      "Allowed locally (fail-open)", // 3990
      "Cursor warps", // 8
      "Lock contention", // 2
    ]);
    // All-zero counters tie and keep their CAPTURE_ROWS order at the tail.
    expect(labels.slice(6)).toEqual([
      "Pointer handoff transitions",
      "Cursor hides",
      "Cursor shows",
      "Callback panics",
      "Pointer observation failures",
    ]);
  });

  it("marks non-zero failure counters with the negative highlight class", () => {
    render(<CaptureTable label="Counters" local={localReport} peer={null} />);
    const table = screen.getByRole("table");
    const lockRow = within(table)
      .getAllByRole("row")
      .find((row) => row.textContent?.includes("Lock contention")) as HTMLTableRowElement;
    expect(lockRow.cells[1]).toHaveClass("neg");
    const warpsRow = within(table)
      .getAllByRole("row")
      .find((row) => row.textContent?.includes("Cursor warps")) as HTMLTableRowElement;
    expect(warpsRow.cells[1]).not.toHaveClass("neg");
  });

  it("shows the waiting row with em-dash placeholders before either supervisor reports", () => {
    render(<CaptureTable label="Counters" local={null} peer={null} />);
    // Every counter is present but em-dashed, and the waiting row is appended last.
    const labels = rowLabels();
    expect(labels).toHaveLength(12);
    expect(labels[11]).toBe("Waiting for capture supervisor…");
    // 11 counter rows + the waiting row, two value cells each.
    expect(screen.getAllByText("—")).toHaveLength(24);
  });
});
