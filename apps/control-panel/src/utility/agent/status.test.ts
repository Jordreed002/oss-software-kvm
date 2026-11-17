import { describe, expect, it } from "vitest";
import { parseAgentStatus, queryAgentStatus } from "./status";
import { idleStubPayload, INSTANCE, unavailablePayload } from "./testSnapshots";

describe("parseAgentStatus", () => {
  it("accepts the idle stub snapshot unchanged", () => {
    const result = parseAgentStatus(idleStubPayload());
    expect(result).toEqual({ kind: "connected", snapshot: idleStubPayload().snapshot });
  });

  it("keeps a u64 revision exact as a string", () => {
    const p = idleStubPayload();
    p.snapshot.revision = "18446744073709551615";
    const result = parseAgentStatus(p);
    expect(result.kind === "connected" && result.snapshot.revision).toBe("18446744073709551615");
  });

  it("maps each native error category to a distinct failure", () => {
    for (const error of ["not_found", "permission_denied", "timed_out", "incompatible", "invalid_reply", "transport"]) {
      expect(parseAgentStatus(unavailablePayload(error))).toEqual({ kind: "failed", error });
    }
  });

  it("treats anything unrecognised as a bridge failure, never a default state", () => {
    const bad: unknown[] = [
      null,
      "connected",
      [],
      {},
      { kind: "connected" },
      unavailablePayload("bridge"), // only the page may produce this
      unavailablePayload("something_new"),
      { ...unavailablePayload("not_found"), detail: "C:\\pipe\\path" },
    ];
    const mutate: ((s: ReturnType<typeof idleStubPayload>["snapshot"] & Record<string, unknown>) => void)[] = [
      (s) => (s.lifecycle = "sharing"),
      (s) => (s.userIntent = "on"),
      (s) => (s.revision = "-1"),
      (s) => (s.revision = "01"),
      (s) => ((s as Record<string, unknown>).revision = 3),
      (s) => (s.instance = INSTANCE.toUpperCase()),
      (s) => ((s as Record<string, unknown>).cleanupUnconfirmed = "false"),
      (s) => ((s as Record<string, unknown>).input = { destination: "local", host: "x" }),
      (s) => ((s as Record<string, unknown>).input = { destination: "remote", host: "" }),
      (s) => ((s as Record<string, unknown>).input = { destination: "remote", host: "é".repeat(128) }),
      (s) => ((s as Record<string, unknown>).input = { destination: "remote" }),
      (s) => ((s as Record<string, unknown>).safety = { state: "latched" }),
      (s) => ((s as Record<string, unknown>).safety = { state: "clear", cause: "unspecified" }),
      (s) => ((s.readiness as Record<string, string>).permissions = "granted"),
      (s) => delete (s.readiness as Partial<Record<string, string>>).inventory,
      (s) => ((s.capabilities as Record<string, string>).pause = "yes"),
      (s) => ((s.capabilities as Record<string, string>).clipboard = "supported"),
      (s) => (s.extra = true),
    ];
    for (const m of mutate) {
      const p = idleStubPayload();
      m(p.snapshot as never);
      bad.push(p);
    }
    for (const raw of bad) expect(parseAgentStatus(raw)).toEqual({ kind: "failed", error: "bridge" });
  });

  it("accepts a valid remote host up to the byte bound", () => {
    const p = idleStubPayload();
    (p.snapshot as Record<string, unknown>).input = { destination: "remote", host: "a".repeat(255) };
    expect(parseAgentStatus(p).kind).toBe("connected");
  });
});

describe("queryAgentStatus", () => {
  it("calls only the read-only agent_status command", async () => {
    const calls: string[] = [];
    await queryAgentStatus(async (cmd) => {
      calls.push(cmd);
      return idleStubPayload();
    });
    expect(calls).toEqual(["agent_status"]);
  });

  it("turns a refused or missing command into a bridge failure", async () => {
    const result = await queryAgentStatus(async () => {
      throw new Error("command agent_status not found");
    });
    expect(result).toEqual({ kind: "failed", error: "bridge" });
  });
});
