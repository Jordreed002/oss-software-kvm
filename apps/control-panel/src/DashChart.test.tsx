import { describe, expect, it } from "vitest";
import { act, render, renderHook } from "@testing-library/react";
import { CompositionBar, HealthMeter, Sparkline, TimeSeriesChart, useHistory } from "./DashChart";

function fixedSeries() {
  const now = Date.now();
  const point = (i: number, y: number | null) => ({ t: now - (4 - i) * 10_000, y });
  return [
    { id: "local", label: "Local", color: "#a9e5c8", points: [point(0, 2), point(1, 4), point(2, 3), point(3, 6), point(4, 5)] },
    { id: "peer", label: "Peer", color: "#ff6b35", points: [point(0, null), point(1, 1), point(2, null), point(3, 2), point(4, 3)] },
  ];
}

describe("TimeSeriesChart", () => {
  it("renders an SVG plot with per-series paths for a fixed series", () => {
    const { container, getByRole } = render(
      <TimeSeriesChart title="Round-trip latency" windowMs={90_000} series={fixedSeries()} yFormat={(v) => `${Math.round(v)} ms`} />,
    );
    expect(getByRole("img", { name: "Round-trip latency time series" })).toBeInTheDocument();
    const paths = container.querySelectorAll("svg path");
    // Two area fills + two line strokes, one pair per series.
    expect(paths).toHaveLength(4);
  });

  it("tolerates empty data by showing the placeholder and no chart", () => {
    const { container, getByText } = render(
      <TimeSeriesChart title="Throughput" windowMs={90_000} series={[]} yFormat={(v) => `${v}`} />,
    );
    expect(getByText("Collecting telemetry…")).toBeInTheDocument();
    expect(container.querySelector("svg")).toBeNull();
  });
});

describe("Sparkline", () => {
  it("draws a polyline for a non-trivial series", () => {
    const { container } = render(<Sparkline values={[1, 3, 2, 5]} color="#a9e5c8" />);
    const polyline = container.querySelector("svg polyline");
    expect(polyline).not.toBeNull();
    expect(polyline?.getAttribute("points")?.split(" ")).toHaveLength(4);
  });

  it("renders nothing for short or all-zero series", () => {
    const { container: short } = render(<Sparkline values={[1]} color="#a9e5c8" />);
    expect(short.querySelector("svg")).toBeNull();
    const { container: flat } = render(<Sparkline values={[0, 0, 0]} color="#a9e5c8" />);
    expect(flat.querySelector("svg")).toBeNull();
  });
});

describe("CompositionBar", () => {
  it("renders one bar per host with a shared legend and totals", () => {
    const { getByText, getByTitle } = render(
      <CompositionBar
        title="Input routing split"
        hosts={[
          { name: "Local", segments: [{ label: "Remote-routed", value: 70, color: "#ff6b35" }, { label: "Allowed locally", value: 30, color: "#a9e5c8" }] },
          { name: "Peer", segments: [{ label: "Remote-routed", value: 20, color: "#ff6b35" }, { label: "Allowed locally", value: 25, color: "#a9e5c8" }] },
        ]}
        valueFormat={(v) => `${v}`}
      />,
    );
    expect(getByText("Input routing split")).toBeInTheDocument();
    expect(getByTitle("Local")).toBeInTheDocument();
    expect(getByText("100")).toBeInTheDocument(); // local total
    expect(getByText("45")).toBeInTheDocument(); // peer total
    expect(getByText("Remote-routed")).toBeInTheDocument(); // legend
  });

  it("shows the empty placeholder when no host has capture data", () => {
    const { getByText } = render(
      <CompositionBar title="Input routing split" hosts={[]} valueFormat={(v) => `${v}`} />,
    );
    expect(getByText("No capture data yet.")).toBeInTheDocument();
  });
});

describe("HealthMeter", () => {
  it("maps drop fractions to severity bands and clamps out-of-range input", () => {
    const { getByText } = render(
      <HealthMeter
        title="Outbound drop health"
        hosts={[
          { name: "Clean host", fraction: 0, detail: "0 drops" },
          { name: "Flaky host", fraction: 0.02, detail: "2% drops" },
          { name: "Broken host", fraction: 7, detail: "way off scale" },
        ]}
      />,
    );
    expect(getByText("Healthy")).toBeInTheDocument();
    expect(getByText("Degraded")).toBeInTheDocument();
    expect(getByText("Critical")).toBeInTheDocument();
    // 7 is clamped to 1 -> "100.00%", not "700%".
    expect(getByText("100.00%")).toBeInTheDocument();
  });
});

describe("useHistory", () => {
  it("keeps only the most recent max samples and offers a stable append", () => {
    const { result } = renderHook(() => useHistory<number>(3));
    const [, firstAppend] = result.current;
    act(() => {
      result.current[1](1);
      result.current[1](2);
    });
    const [, secondAppend] = result.current;
    expect(secondAppend).toBe(firstAppend); // stable identity across renders
    act(() => {
      result.current[1](3);
      result.current[1](4);
    });
    const [history] = result.current;
    expect(history).toEqual([2, 3, 4]); // oldest sample dropped
  });
});
