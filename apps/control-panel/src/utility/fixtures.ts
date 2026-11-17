import { unsupported, type UtilitySnapshot } from "./model";

/** Development fixtures. These are illustrative states for designing the
 *  utility UI, never a claim about real computers. Every fixture carries
 *  `source: "preview-fixture"` and the UI badges it as a preview. */

const SETTINGS_REASON =
  "Changing settings needs the new agent’s confirmed settings transactions, which aren’t built yet.";
const SETUP_REASON = "Pairing and setup run through the new agent, which isn’t available in this preview.";
const QUIT_REASON = "Quit is provided by the native tray menu, which isn’t part of this preview.";
const EXPORT_REASON = "Support bundles come from the agent with a redaction preview; not available yet.";

function base(id: FixtureId, label: string): UtilitySnapshot {
  return {
    source: "preview-fixture",
    label,
    thisComputer: { name: "Studio Mac", platform: "macos" },
    peer: { name: "Desk PC", platform: "windows", link: "connected" },
    sharing: "paused",
    destination: "local",
    clipboard: "off",
    launchAtLogin: "off",
    blocker: null,
    technical: [`fixture: ${id}`, "commands: not sent (preview)"],
    capabilities: {
      // The preview shows the control a confirmed agent would offer; the
      // preview command port refuses to send it (see commands.ts).
      pauseResume: { supported: true },
      settingsWrite: unsupported(SETTINGS_REASON),
      setup: unsupported(SETUP_REASON),
      quit: unsupported(QUIT_REASON),
      diagnosticsExport: unsupported(EXPORT_REASON),
    },
  };
}

export const FIXTURE_IDS = [
  "paused",
  "ready",
  "controlling",
  "starting",
  "peer-offline",
  "unconfirmed",
  "failsafe",
] as const;

export type FixtureId = (typeof FIXTURE_IDS)[number];

export const FIXTURE_LABELS: Record<FixtureId, string> = {
  paused: "Paused",
  ready: "Sharing on, input here",
  controlling: "Controlling the other computer",
  starting: "Starting (pending)",
  "peer-offline": "Other computer offline",
  unconfirmed: "Change not confirmed",
  failsafe: "Safety stop",
};

export function fixtureSnapshot(id: FixtureId): UtilitySnapshot {
  const s = base(id, FIXTURE_LABELS[id]);
  switch (id) {
    case "paused":
      return s;
    case "ready":
      return { ...s, sharing: "sharing", destination: "local", clipboard: "on" };
    case "controlling":
      return { ...s, sharing: "sharing", destination: "peer", clipboard: "on" };
    case "starting":
      return { ...s, sharing: "starting", destination: "local" };
    case "peer-offline":
      return {
        ...s,
        sharing: "sharing",
        destination: "local",
        peer: { ...s.peer!, link: "offline" },
        blocker: {
          title: "Desk PC isn’t reachable",
          detail: "The two computers can’t see each other on this network.",
          remedy: "Make sure Desk PC is awake, on the same network, and that Software KVM is running there.",
        },
      };
    case "unconfirmed":
      return {
        ...s,
        sharing: "unconfirmed",
        destination: "unknown",
        blocker: {
          title: "A change wasn’t confirmed",
          detail: "Software KVM asked to change sharing but didn’t hear back in time.",
          remedy: "Check which computer your pointer is on. Pause, then resume once the status is clear.",
        },
      };
    case "failsafe":
      return {
        ...s,
        sharing: "failsafe",
        destination: "local",
        blocker: {
          title: "Sharing stopped for safety",
          detail: "A safety check stopped sharing and returned input to this computer.",
          remedy: "Release any held keys, then use the recovery step once the agent offers it.",
        },
        technical: [...s.technical, "failsafe latch: set (fixture)"],
      };
  }
}
