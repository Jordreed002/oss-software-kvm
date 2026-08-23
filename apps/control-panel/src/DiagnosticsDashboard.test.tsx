import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

// Component tests mock at the bridge boundary: the dashboard only needs
// api.fetchDiagnostics, never a real Tauri webview.
vi.mock("./bridge", () => ({ api: { fetchDiagnostics: vi.fn() } }));

import { api } from "./bridge";
import { DiagnosticsDashboard } from "./DiagnosticsDashboard";
import { makeReport, makeSnapshot } from "./test/fixtures";

const fetchDiagnostics = vi.mocked(api.fetchDiagnostics);

/** Host-card status pills (the chart badges also read "LIVE", so query the
 *  .dash-status elements directly). */
function hostStatuses(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll(".dash-status")).map((el) => el.textContent ?? "");
}

beforeEach(() => {
  fetchDiagnostics.mockReset();
});

describe("DiagnosticsDashboard", () => {
  it("polls both hosts over the diagnostics channel and renders their live cards", async () => {
    fetchDiagnostics.mockImplementation(async (host: string) =>
      host === "192.168.1.24"
        ? makeReport({ hostName: "Jordan’s Mac" })
        : makeReport({ hostName: "Office Windows", platform: "windows" }),
    );
    const { container } = render(<DiagnosticsDashboard snapshot={makeSnapshot()} />);

    await screen.findByText("Jordan’s Mac");
    expect(hostStatuses(container)).toEqual(["LIVE", "LIVE"]);
    expect(fetchDiagnostics).toHaveBeenCalledWith("192.168.1.24");
    expect(fetchDiagnostics).toHaveBeenCalledWith("192.168.1.31");
    // The peer card plus the health gauge and composition bar all carry the name.
    expect(screen.getAllByText("Office Windows").length).toBeGreaterThanOrEqual(3);
    // Both hosts reported telemetry: refresh stays available and export unlocks.
    expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Export" })).toBeEnabled();
  });

  it("renders the offline state when both diagnostics channels are unreachable", async () => {
    fetchDiagnostics.mockResolvedValue(null);
    const { container } = render(<DiagnosticsDashboard snapshot={makeSnapshot()} />);

    await screen.findByText("No session telemetry yet.");
    expect(hostStatuses(container)).toEqual(["OFFLINE", "OFFLINE"]);
    expect(screen.getByText("No capture data yet.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export" })).toBeDisabled();
  });

  it("pauses and resumes periodic polling from the toolbar", async () => {
    fetchDiagnostics.mockResolvedValue(makeReport());
    render(<DiagnosticsDashboard snapshot={makeSnapshot()} />);
    await screen.findByText("Jordan’s Mac");

    const pauseButton = screen.getByRole("button", { name: "Pause" });
    expect(pauseButton).toHaveAttribute("aria-pressed", "false");
    fetchDiagnostics.mockClear();

    fireEvent.click(pauseButton);
    expect(screen.getByRole("button", { name: "Resume" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText(/Polling paused/)).toBeInTheDocument();

    // While paused, the periodic interval is torn down and no new polls go out.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(fetchDiagnostics).not.toHaveBeenCalled();
  });
});
