import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";

// Component tests mock at the bridge boundary: the card only needs
// api.controlStatus (poll behavior) and the real uuidToBytes parser. Never a
// real Tauri webview.
vi.mock("../bridge", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../bridge")>();
  return { ...actual, api: { ...actual.api, controlStatus: vi.fn() } };
});

import { api } from "../bridge";
import type { SetupSnapshot } from "../types";
import { DaemonStatusCard } from "./DaemonStatusCard";
import {
  LOCAL_HOST_BYTES, LOCAL_HOST_UUID, makeDaemonStatusReply, makeSnapshot,
} from "../test/fixtures";

const controlStatus = vi.mocked(api.controlStatus);

/** Snapshot whose local identity carries a canonical UUID the daemon's §31
 *  active-host bytes can be compared against. */
function snapshotWithLocal(hostId: string = LOCAL_HOST_UUID): SetupSnapshot {
  const base = makeSnapshot();
  return { ...base, local: base.local ? { ...base.local, hostId } : null };
}

beforeEach(() => {
  controlStatus.mockReset();
});

describe("DaemonStatusCard", () => {
  // Regression: the backend used to serialize the §31 status with snake_case
  // keys (kvm_enabled / peer_state / active_host), so `live.kvmEnabled` was
  // undefined and comparing `live.activeHost` crashed the card (fixed by the
  // camelCase DTO in edec6af). Feed the exact reply the backend now emits.
  it("renders the responded state from the real camelCase backend reply without crashing", async () => {
    controlStatus.mockResolvedValue({
      state: "responded",
      status: {
        kvmEnabled: true,
        clipboardEnabled: false,
        peerState: "connected",
        roundTripTimeMs: 7,
        activeHost: [17, 17, 17, 17, 34, 34, 67, 51, 132, 68, 85, 85, 85, 85, 85, 85],
        protocolVersion: 3,
      },
      error: null,
    });
    render(<DaemonStatusCard snapshot={snapshotWithLocal()} />);

    expect(await screen.findByText("Daemon is answering the local control endpoint")).toBeInTheDocument();
    expect(screen.getByText("Peer link: connected · round trip 7 ms")).toBeInTheDocument();
    expect(screen.getByText("Input routing is armed between both computers")).toBeInTheDocument();
    expect(screen.getByText("Active host is this computer (protocol v3)")).toBeInTheDocument();
    // Responded + connected + armed + local active host: every row is READY.
    expect(screen.getAllByText("READY")).toHaveLength(4);
  });

  it("attributes the active host to the peer when the §31 bytes differ from the local identity", async () => {
    controlStatus.mockResolvedValue(
      makeDaemonStatusReply({ status: { ...makeDaemonStatusReply().status!, activeHost: LOCAL_HOST_BYTES.map((byte) => byte ^ 0xff) } }),
    );
    render(<DaemonStatusCard snapshot={snapshotWithLocal()} />);

    expect(await screen.findByText("Active host is Office Windows (protocol v3)")).toBeInTheDocument();
  });

  it("reports an unknown local identity instead of conflating a malformed host id with the peer", async () => {
    // makeSnapshot's default host id ("local-host") is not a canonical UUID.
    controlStatus.mockResolvedValue(makeDaemonStatusReply());
    render(<DaemonStatusCard snapshot={makeSnapshot()} />);

    expect(await screen.findByText("Unknown local identity — the active host cannot be compared")).toBeInTheDocument();
    expect(screen.queryByText(/Active host is/)).not.toBeInTheDocument();
  });

  it("renders the unreachable state and keeps the peer row on its own detail", async () => {
    controlStatus.mockResolvedValue({ state: "unreachable", status: null, error: null });
    render(<DaemonStatusCard snapshot={snapshotWithLocal()} />);

    expect(await screen.findByText("Daemon not running at the local control endpoint")).toBeInTheDocument();
    // The peer row is not a copy of the daemon-link detail (audit L3).
    expect(screen.getByText("Peer link unknown until the daemon responds")).toBeInTheDocument();
    expect(screen.getByText("Waiting for the daemon's routing state…")).toBeInTheDocument();
    // No live status: the input-destination row is absent.
    expect(screen.queryByText(/Active host is/)).not.toBeInTheDocument();
  });

  it("renders the refused state with the daemon's error", async () => {
    controlStatus.mockResolvedValue({ state: "refused", status: null, error: "os error 2" });
    render(<DaemonStatusCard snapshot={snapshotWithLocal()} />);

    expect(await screen.findByText("Daemon refused the status request (os error 2)")).toBeInTheDocument();
    expect(screen.getByText("Peer link unknown until the daemon responds")).toBeInTheDocument();
  });

  it("transitions through responded, unreachable, and refused as later polls land", async () => {
    vi.useFakeTimers();
    try {
      controlStatus.mockResolvedValueOnce(makeDaemonStatusReply({ status: { ...makeDaemonStatusReply().status!, roundTripTimeMs: 4 } }))
        .mockResolvedValueOnce({ state: "unreachable", status: null, error: null })
        .mockResolvedValue({ state: "refused", status: null, error: "connection reset" });
      render(<DaemonStatusCard snapshot={snapshotWithLocal()} />);
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(screen.getByText("Peer link: connected · round trip 4 ms")).toBeInTheDocument();

      await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
      expect(screen.getByText("Daemon not running at the local control endpoint")).toBeInTheDocument();

      await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
      expect(screen.getByText("Daemon refused the status request (connection reset)")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("surfaces a failed status poll instead of swallowing it forever", async () => {
    controlStatus.mockRejectedValue(new Error("os error 61"));
    render(<DaemonStatusCard snapshot={snapshotWithLocal()} />);

    expect(await screen.findByText("Daemon status poll failed (os error 61)")).toBeInTheDocument();
    // The failure belongs to the control-link row; the peer row keeps its own detail.
    expect(screen.getByText("Peer link unknown until the daemon responds")).toBeInTheDocument();
  });

  it("stops polling after unmount", async () => {
    vi.useFakeTimers();
    try {
      controlStatus.mockResolvedValue(makeDaemonStatusReply());
      const { unmount } = render(<DaemonStatusCard snapshot={snapshotWithLocal()} />);
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(controlStatus).toHaveBeenCalledTimes(1);

      controlStatus.mockClear();
      unmount();
      await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
      expect(controlStatus).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
