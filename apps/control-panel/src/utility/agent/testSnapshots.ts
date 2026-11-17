/** Test-only payloads shaped like the native `agent_status` command output.
 *  Not imported by any runtime module. */

export const INSTANCE = "6f1c2f4e-8a1b-4c3d-9e5f-0a1b2c3d4e5f";

/** Exactly what the idle agent stub reports today (see agent.rs tests). */
export function idleStubPayload() {
  return {
    kind: "connected",
    snapshot: {
      instance: INSTANCE,
      revision: "0",
      lifecycle: "idle",
      userIntent: "paused",
      safety: { state: "clear" },
      cleanupUnconfirmed: false,
      input: { destination: "unknown" },
      readiness: {
        configuration: "unconfirmed",
        enrollment: "unconfirmed",
        permissions: "unconfirmed",
        inventory: "unconfirmed",
        peerAuthentication: "unconfirmed",
        inputAuthority: "unconfirmed",
      },
      capabilities: {
        pause: "unsupported",
        resume: "unsupported",
        failsafe: "unsupported",
        quit: "unsupported",
        snapshot: "supported",
      },
    },
  };
}

export function unavailablePayload(error: string) {
  return { kind: "unavailable", error };
}
