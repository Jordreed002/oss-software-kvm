import type { UtilitySnapshot } from "./model";

/** Command boundary for the utility UI.
 *
 *  The production agent API will report accepted / applied / rejected /
 *  unconfirmed outcomes with correlation IDs and revisions. None of that
 *  exists yet, so the only honest outcome here is `not_sent`: the UI must
 *  show it and leave state untouched. Do not add an optimistic path. */

export type UtilityCommand = { kind: "pause" } | { kind: "resume" };

export interface CommandOutcome {
  kind: "not_sent";
  message: string;
}

export function sendCommand(snapshot: UtilitySnapshot, command: UtilityCommand): CommandOutcome {
  const verb = command.kind === "pause" ? "Pause" : "Resume";
  return {
    kind: "not_sent",
    message:
      snapshot.source === "preview-fixture"
        ? `${verb} not sent. Preview fixtures have no agent, so sharing is unchanged.`
        : `${verb} not sent. No agent is connected, so sharing is unchanged.`,
  };
}
