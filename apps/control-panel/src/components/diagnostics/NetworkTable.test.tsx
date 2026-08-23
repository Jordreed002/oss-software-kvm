import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { NetworkTable } from "./NetworkTable";
import { makeNetwork, makeReport } from "../../test/fixtures";

const localRate = { outBps: 2_048, inBps: 1_024, outFps: 10, inFps: 8 };
const peerRate = { outBps: 512, inBps: 9_216, outFps: 4, inFps: 30 };

function setup(localRateValue: typeof localRate | null = localRate, peerRateValue: typeof peerRate | null = peerRate) {
  render(
    <NetworkTable
      label="Network activity"
      local={makeReport({ network: makeNetwork({ lastRttMs: 40, coalescedMoves: 100, outboundFrames: 8_400, inboundFrames: 7_600 }) })}
      peer={makeReport({ network: makeNetwork({ lastRttMs: 8, coalescedMoves: 500, outboundFrames: 1_000, inboundFrames: 2_000 }) })}
      localRate={localRateValue}
      peerRate={peerRateValue}
    />,
  );
}

function rowMetrics(): string[] {
  const table = screen.getByRole("table");
  return within(table)
    .getAllByRole("row")
    .slice(1) // header row
    .map((row) => (row as HTMLTableRowElement).cells[0]?.textContent ?? "");
}

describe("NetworkTable", () => {
  it("renders all metric rows sorted alphabetically by default", () => {
    setup();
    expect(rowMetrics()).toEqual([
      "Coalesced pointer moves",
      "Inbound throughput",
      "Last RTT",
      "Outbound throughput",
    ]);
  });

  it("sorts by magnitude, descending, when a host column header is clicked", () => {
    setup();
    fireEvent.click(screen.getByRole("button", { name: /This computer/ }));
    expect(rowMetrics()).toEqual([
      "Outbound throughput", // 2048 B/s
      "Inbound throughput", // 1024 B/s
      "Coalesced pointer moves", // 100
      "Last RTT", // 40 ms
    ]);
    fireEvent.click(screen.getByRole("button", { name: /Paired computer/ }));
    expect(rowMetrics()).toEqual([
      "Inbound throughput", // 9216 B/s
      "Outbound throughput", // 512 B/s
      "Coalesced pointer moves", // 500
      "Last RTT", // 8 ms
    ]);
  });

  it("flips to ascending when the active column is clicked again", () => {
    setup();
    const header = screen.getByRole("button", { name: /This computer/ });
    fireEvent.click(header);
    fireEvent.click(header);
    expect(rowMetrics()).toEqual([
      "Last RTT", // 40
      "Coalesced pointer moves", // 100
      "Inbound throughput", // 1024
      "Outbound throughput", // 2048
    ]);
  });

  it("sinks missing values (—) below present ones when sorting a sparse column", () => {
    setup(localRate, null); // no peer rates: both throughput rows are missing for the peer
    fireEvent.click(screen.getByRole("button", { name: /Paired computer/ }));
    expect(rowMetrics()).toEqual([
      "Coalesced pointer moves", // 500
      "Last RTT", // 8 ms
      "Outbound throughput", // missing
      "Inbound throughput", // missing (stable original order)
    ]);
  });
});
