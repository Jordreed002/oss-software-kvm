import { describe, expect, it } from "vitest";
import { parseAgentStatus, type AgentSnapshot, type FailureKind } from "./status";
import { idleStubPayload } from "./testSnapshots";
import { CHECKING_VIEW, projectAgent, projectFailure, projectSnapshot } from "./view";

function snapshot(patch: Partial<AgentSnapshot> = {}): AgentSnapshot {
  const r = parseAgentStatus(idleStubPayload());
  if (r.kind !== "connected") throw new Error("stub must parse");
  return { ...r.snapshot, ...patch };
}

const allText = (v: ReturnType<typeof projectSnapshot>) =>
  [v.headline, v.detail, v.remedy ?? "", ...(v.facts ?? []).map((f) => `${f.label} ${f.value}`)].join(" ");

describe("connected projection", () => {
  it("keeps the idle stub's unknown authority and readiness unknown", () => {
    const v = projectSnapshot(snapshot());
    expect(v.badge).toEqual({ label: "Agent connected", kind: "agent" });
    expect(v.headline).toBe("Input location not confirmed");
    expect(v.detail).toMatch(/pause is requested, but the agent hasn’t confirmed/i);
    expect(v.tone).toBe("neutral");
    expect(allText(v)).not.toMatch(/this computer|controlling|sharing is paused|ready to share/i);
    expect(v.facts?.find((f) => f.label === "Input")).toEqual({ label: "Input", value: "Not confirmed", unknown: true });
    expect(v.readiness?.every((r) => !r.confirmed)).toBe(true);
    expect(v.readiness).toHaveLength(6);
  });

  it("disables every mutation with the agent's own reason", () => {
    const v = projectSnapshot(snapshot());
    expect(v.primary).toEqual({ kind: "resume", label: "Resume sharing", reason: "The agent doesn’t offer Resume yet." });
    expect(v.quitReason).toMatch(/doesn’t offer quit/i);
  });

  it("still refuses a mutation the agent supports, because this build is read-only", () => {
    const s = snapshot({ userIntent: "sharing_requested", capabilities: { ...snapshot().capabilities, pause: "supported", quit: "supported" } });
    const v = projectSnapshot(s);
    expect(v.primary.kind).toBe("pause");
    if (v.primary.kind !== "none") expect(v.primary.reason).toMatch(/only reads status.*can’t send pause/i);
    expect(v.quitReason).toMatch(/only reads status/i);
  });

  it("only says Controlling for confirmed remote authority", () => {
    const remote = projectSnapshot(snapshot({ input: { destination: "remote", host: "Desk PC" }, lifecycle: "active", userIntent: "sharing_requested" }));
    expect(remote.headline).toBe("Controlling Desk PC");
    expect(remote.tone).toBe("active");
    for (const destination of ["local", "transitioning", "unknown"] as const) {
      const v = projectSnapshot(snapshot({ input: { destination }, lifecycle: "active", userIntent: "sharing_requested" }));
      expect(v.headline).not.toMatch(/controlling/i);
    }
  });

  it("says paused only with confirmed local input", () => {
    expect(projectSnapshot(snapshot({ input: { destination: "local" } })).headline).toBe("Sharing is paused");
    expect(projectSnapshot(snapshot({ input: { destination: "unknown" } })).headline).not.toMatch(/paused/i);
    expect(projectSnapshot(snapshot({ input: { destination: "transitioning" } })).headline).toBe("Input is moving");
  });

  it("puts a safety latch first and offers no ordinary Resume", () => {
    const v = projectSnapshot(
      snapshot({ safety: { state: "latched", cause: "peer_link_failure" }, input: { destination: "remote", host: "Desk PC" } }),
    );
    expect(v.headline).toBe("Sharing stopped for safety");
    expect(v.detail).toMatch(/link to the other computer failed/i);
    expect(v.primary.kind).toBe("none");
    expect(v.facts?.find((f) => f.label === "Safety")?.value).toBe("Stopped: Link failed");
  });

  it("surfaces unconfirmed cleanup and faults as attention", () => {
    const cleanup = projectSnapshot(snapshot({ cleanupUnconfirmed: true }));
    expect(cleanup.headline).toBe("Cleanup not confirmed");
    expect(cleanup.facts?.find((f) => f.label === "Cleanup")).toEqual({ label: "Cleanup", value: "Not confirmed", unknown: true });
    expect(projectSnapshot(snapshot({ lifecycle: "faulted" })).tone).toBe("attention");
  });

  it("counts only confirmed prerequisites", () => {
    const s = snapshot();
    const v = projectSnapshot({ ...s, readiness: { ...s.readiness, enrollment: "confirmed" } });
    expect(v.readiness?.filter((r) => r.confirmed).map((r) => r.label)).toEqual(["Computers paired"]);
  });

  it("puts the exact revision and instance only in technical details", () => {
    const v = projectSnapshot(snapshot({ revision: "18446744073709551615" }));
    expect(v.technical).toContain("revision: 18446744073709551615");
    expect(allText(v)).not.toMatch(/6f1c2f4e|revision/);
  });
});

describe("failure projection", () => {
  const kinds: FailureKind[] = ["not_found", "permission_denied", "timed_out", "incompatible", "invalid_reply", "transport", "bridge"];

  it("gives every failure its own headline and badge", () => {
    const views = kinds.map(projectFailure);
    expect(new Set(views.map((v) => v.headline)).size).toBe(kinds.length);
    expect(new Set(views.map((v) => v.badge.label)).size).toBe(kinds.length);
  });

  it("never claims connection, state or an enabled command", () => {
    for (const kind of kinds) {
      const v = projectAgent({ kind: "failed", error: kind });
      expect(v.badge.label).not.toMatch(/bconnected/i);
      expect(v.facts).toBeNull();
      expect(v.readiness).toBeNull();
      expect(v.remedy).toBeTruthy();
      expect(v.primary.kind).toBe("pause");
      expect(`${v.headline} ${v.detail}`).not.toMatch(/paused|sharing is|controlling/i);
    }
  });

  it("names the untrusted and unavailable cases specifically", () => {
    expect(projectFailure("not_found").headline).toBe("Agent not running");
    expect(projectFailure("permission_denied").headline).toBe("Agent couldn’t be verified");
    expect(projectFailure("timed_out").headline).toBe("Agent didn’t answer in time");
    expect(projectFailure("incompatible").headline).toBe("Agent version doesn’t match");
    expect(projectFailure("invalid_reply").headline).toBe("Agent reply was rejected");
    expect(projectFailure("transport").headline).toBe("Connection to the agent failed");
  });

  it("starts in a checking state that claims nothing", () => {
    expect(CHECKING_VIEW.facts).toBeNull();
    expect(CHECKING_VIEW.badge.label).toBe("Checking");
  });
});
