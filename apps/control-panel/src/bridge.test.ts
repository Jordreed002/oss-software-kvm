import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";

// The Tauri boundary: everything below the api object is swapped for a spy, so
// these tests verify command names and argument shaping without a webview.
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

import { api } from "./bridge";

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
});
