import { describe, expect, it } from "vitest";
import { sendCommand } from "./commands";
import { isNativePreviewHost, shouldRenderUtilitySurface } from "./entry";
import { FIXTURE_IDS, fixtureSnapshot } from "./fixtures";
import { describeStatus, primaryAction, unavailableSnapshot } from "./model";

describe("utility entry gate", () => {
  it("requires both a development build and an explicit surface parameter", () => {
    expect(shouldRenderUtilitySurface(true, "?surface=utility")).toBe(true);
    expect(shouldRenderUtilitySurface(false, "?surface=utility")).toBe(false);
    expect(shouldRenderUtilitySurface(true, "")).toBe(false);
    expect(shouldRenderUtilitySurface(true, "?surface=legacy")).toBe(false);
    expect(shouldRenderUtilitySurface(true, "?utility")).toBe(false);
  });

  it("detects the native preview host only from the injected Tauri global", () => {
    expect(isNativePreviewHost({ __TAURI_INTERNALS__: {} })).toBe(true);
    expect(isNativePreviewHost({})).toBe(false);
    expect(isNativePreviewHost({ __TAURI__: {} })).toBe(false);
  });
});

describe("unavailable agent state", () => {
  const s = unavailableSnapshot();

  it("claims no connection, destination or sharing state", () => {
    const status = describeStatus(s);
    expect(s.sharing).toBe("unknown");
    expect(s.destination).toBe("unknown");
    expect(s.peer).toBeNull();
    expect(`${status.headline} ${status.detail}`).not.toMatch(/\bconnected to\b|controlling|sharing is on|ready/i);
    expect(status.tone).toBe("neutral");
  });

  it("offers no enabled mutation and explains why", () => {
    const action = primaryAction(s);
    expect(action.kind).not.toBe("none");
    if (action.kind === "none") return;
    expect(action.enabled).toBe(false);
    if (!action.enabled) expect(action.reason).toMatch(/no software kvm agent/i);
    for (const cap of Object.values(s.capabilities)) expect(cap.supported).toBe(false);
  });
});

describe("status wording", () => {
  it("keeps 'connected' and 'controlling' as different facts", () => {
    const ready = describeStatus(fixtureSnapshot("ready"));
    const controlling = describeStatus(fixtureSnapshot("controlling"));
    expect(ready.headline).not.toMatch(/controlling/i);
    expect(controlling.headline).toBe("Controlling Desk PC");
  });

  it("never reports control of an unreachable peer", () => {
    const offline = { ...fixtureSnapshot("controlling"), peer: { ...fixtureSnapshot("controlling").peer!, link: "offline" as const } };
    expect(describeStatus(offline).headline).toBe("Waiting for Desk PC");
  });

  it("shows pending and unconfirmed states instead of success", () => {
    expect(describeStatus(fixtureSnapshot("starting")).headline).toBe("Starting");
    expect(describeStatus(fixtureSnapshot("unconfirmed")).headline).toBe("Could not confirm this change");
    const pending = primaryAction(fixtureSnapshot("starting"));
    expect(pending.kind !== "none" && pending.enabled).toBe(false);
  });

  it("does not offer an ordinary Resume after a safety stop", () => {
    expect(primaryAction(fixtureSnapshot("failsafe")).kind).toBe("none");
    expect(primaryAction(fixtureSnapshot("paused")).kind).toBe("resume");
  });
});

describe("fixtures and commands", () => {
  it("labels every fixture as preview data with read-only settings", () => {
    for (const id of FIXTURE_IDS) {
      const s = fixtureSnapshot(id);
      expect(s.source).toBe("preview-fixture");
      expect(s.capabilities.settingsWrite.supported).toBe(false);
      expect(s.capabilities.setup.supported).toBe(false);
    }
  });

  it("never reports a command as applied", () => {
    for (const s of [unavailableSnapshot(), fixtureSnapshot("controlling")]) {
      const outcome = sendCommand(s, { kind: "pause" });
      expect(outcome.kind).toBe("not_sent");
      expect(outcome.message).toMatch(/unchanged/);
    }
  });
});
