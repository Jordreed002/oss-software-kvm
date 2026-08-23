import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";

// The Tauri boundary: everything below the api object is swapped for a spy, so
// these tests verify command names and argument shaping without a webview.
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

import { api, uuidToBytes } from "./bridge";

const invokeMock = vi.mocked(invoke);

beforeEach(() => {
  // bridge.ts gates on this marker to decide Tauri vs. web-preview mode.
  (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
  invokeMock.mockReset().mockResolvedValue({ acknowledged: true });
});

afterEach(() => {
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
});

describe("api command shaping under a mocked Tauri invoke", () => {
  it("status issues setup_status with no arguments and resolves the reply", async () => {
    invokeMock.mockResolvedValue({ platform: "macos", configured: false });
    const snapshot = await api.status();
    expect(snapshot).toEqual({ platform: "macos", configured: false });
    expect(invokeMock.mock.calls).toEqual([["setup_status", undefined]]);
  });

  it("createIdentity issues create_local_identity with camelCase fields", async () => {
    await api.createIdentity("Studio", "10.0.0.8");
    expect(invokeMock.mock.calls).toEqual([
      ["create_local_identity", { displayName: "Studio", address: "10.0.0.8" }],
    ]);
  });

  it("pairing helpers forward the peer/request identifiers", async () => {
    await api.requestNearbyPairing("peer-1");
    await api.acceptNearbyPairing("request-1");
    await api.confirmNearbyPairing("request-1");
    await api.declineNearbyPairing("request-1");
    expect(invokeMock.mock.calls.map((call) => [call[0], call[1]])).toEqual([
      ["request_nearby_pairing", { peerId: "peer-1" }],
      ["accept_nearby_pairing", { requestId: "request-1" }],
      ["confirm_nearby_pairing", { requestId: "request-1" }],
      ["decline_nearby_pairing", { requestId: "request-1" }],
    ]);
  });

  it("finalize issues finalize_setup with placement and layout", async () => {
    const layout = [{ displayId: "local-1", x: 0, y: 0 }];
    await api.finalize("local_right", layout);
    expect(invokeMock.mock.calls).toEqual([["finalize_setup", { placement: "local_right", layout }]]);
  });

  it("fetchDiagnostics targets the §31 channel host and optional port", async () => {
    await api.fetchDiagnostics("192.168.1.31", 24801);
    await api.fetchDiagnostics("192.168.1.31");
    expect(invokeMock.mock.calls.map((call) => [call[0], call[1]])).toEqual([
      ["fetch_diagnostics", { host: "192.168.1.31", port: 24801 }],
      ["fetch_diagnostics", { host: "192.168.1.31", port: undefined }],
    ]);
  });

  it("controlStatus issues control_status with no arguments and resolves the typed reply", async () => {
    invokeMock.mockResolvedValue({
      state: "responded",
      status: {
        kvmEnabled: true,
        clipboardEnabled: false,
        peerState: "connected",
        roundTripTimeMs: 4,
        activeHost: [17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17],
        protocolVersion: 3,
      },
      error: null,
    });
    const reply = await api.controlStatus();
    expect(invokeMock.mock.calls).toEqual([["control_status", undefined]]);
    expect(reply.state).toBe("responded");
    expect(reply.status?.kvmEnabled).toBe(true);
    expect(reply.status?.peerState).toBe("connected");
    expect(reply.status?.roundTripTimeMs).toBe(4);
    expect(reply.error).toBeNull();
  });

  it("uuidToBytes parses canonical uuids and rejects malformed input", () => {
    const uuid = "11111111-2222-4333-8444-555555555555";
    expect(uuidToBytes(uuid)).toEqual([
      0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33,
      0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    ]);
    expect(uuidToBytes("not-a-uuid")).toBeNull();
    expect(uuidToBytes("")).toBeNull();
  });
});

describe("api web-preview fallback", () => {
  it("serves a local snapshot after the preview delay without touching Tauri", async () => {
    vi.useFakeTimers();
    try {
      delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
      const pending = api.status();
      const inspection = vi.fn();
      pending.then(inspection);
      await vi.advanceTimersByTimeAsync(319);
      expect(inspection).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      const snapshot = await pending;
      expect(inspection).toHaveBeenCalledTimes(1);
      // jsdom reports an empty navigator.platform, so the preview machine is
      // windows — either way a complete snapshot arrives, not a rejection.
      expect(["macos", "windows"]).toContain(snapshot.platform);
      expect(snapshot.configured).toBe(false);
      expect(snapshot.runtime).toBe("stopped");
      expect(invokeMock).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("serves an unreachable §31 daemon while the runtime is stopped and a live status once running", async () => {
    vi.useFakeTimers();
    try {
      delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
      const stoppedPending = api.controlStatus();
      await vi.advanceTimersByTimeAsync(320);
      const stopped = await stoppedPending;
      expect(stopped.state).toBe("unreachable");
      expect(stopped.status).toBeNull();

      const startPending = api.start();
      await vi.advanceTimersByTimeAsync(320);
      await startPending;
      const runningPending = api.controlStatus();
      await vi.advanceTimersByTimeAsync(320);
      const running = await runningPending;
      expect(running.state).toBe("responded");
      expect(running.status?.kvmEnabled).toBe(true);
      expect(running.status?.peerState).toBe("connected");
      expect(invokeMock).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
      await api.stop().catch(() => undefined);
    }
  });
});
