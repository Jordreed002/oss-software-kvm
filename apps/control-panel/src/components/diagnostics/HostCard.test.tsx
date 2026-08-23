import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { HostCard } from "./HostCard";
import { makeNetwork, makeReport } from "../../test/fixtures";
import type { NetRate } from "./model";

const rate: NetRate = { outBps: 2_048, inBps: 1_024, outFps: 10, inFps: 8 };

describe("HostCard", () => {
  it("renders the live state with formatted headline stats", () => {
    render(
      <HostCard
        kind="local"
        name="Jordan’s Mac"
        platform="macos"
        report={makeReport({ uptimeMs: 3_723_000, network: makeNetwork({ lastRttMs: 4, outboundBytes: 1_200_000 }) })}
        rate={rate}
        hasPeer
        dropSeries={[]}
      />,
    );
    expect(screen.getByText("Jordan’s Mac")).toBeInTheDocument();
    expect(screen.getByText("THIS COMPUTER")).toBeInTheDocument();
    expect(screen.getByText("LIVE")).toBeInTheDocument();
    expect(screen.getByText("1h 2m 3s")).toBeInTheDocument(); // uptime
    expect(screen.getByText("4 ms")).toBeInTheDocument(); // last RTT
    expect(screen.getByText("2.0 KiB/s")).toBeInTheDocument(); // outbound rate
    expect(screen.getByText("1.14 MiB")).toBeInTheDocument(); // cumulative outbound total
    expect(screen.getByText("00000001")).toBeInTheDocument(); // host id prefix
    expect(screen.getByText("UDP ACTIVE")).toBeInTheDocument(); // pointer fast path
  });

  it("renders the offline state with em-dash placeholders", () => {
    render(
      <HostCard kind="local" name="Jordan’s Mac" platform="macos" report={null} rate={null} hasPeer dropSeries={[]} />,
    );
    expect(screen.getByText("OFFLINE")).toBeInTheDocument();
    // Every stat and meta value falls back to an em-dash when offline.
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(8);
  });

  it("distinguishes a missing peer from an offline one", () => {
    render(
      <HostCard kind="peer" name="Paired computer" platform="windows" report={null} rate={null} hasPeer={false} dropSeries={[]} />,
    );
    expect(screen.getByText("NO PEER")).toBeInTheDocument();
  });

  it("renders a sparkline only when a drop-rate series exists", () => {
    const { container, rerender, unmount } = render(
      <HostCard kind="local" name="Local" platform="macos" report={makeReport()} rate={null} hasPeer dropSeries={[1, 2, 3]} />,
    );
    expect(container.querySelector("svg.dash-spark")).not.toBeNull();
    rerender(
      <HostCard kind="local" name="Local" platform="macos" report={makeReport()} rate={null} hasPeer dropSeries={[]} />,
    );
    expect(container.querySelector("svg.dash-spark")).toBeNull();
    unmount();
  });
});
