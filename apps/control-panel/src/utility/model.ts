/** Presentation model for the replacement utility UI.
 *
 *  The new Rust agent will own all confirmed state (ADR 0003). Until its
 *  versioned local API exists, the UI can only be fed by one of two explicit
 *  sources:
 *
 *  - `unavailable`: no agent. Every fact is unknown and every mutation is
 *    unsupported. This is the default.
 *  - `preview-fixture`: hand-written development data, always labelled as a
 *    preview. Fixtures may describe any state, but commands are never sent and
 *    never succeed.
 *
 *  Everything the UI says is derived here from the snapshot so the wording
 *  rules (e.g. "Connected" and "Controlling" are different facts) are
 *  testable without rendering. */

export type SnapshotSource = "unavailable" | "preview-fixture";

export type Platform = "windows" | "macos";

/** Agent-reported sharing lifecycle. `unknown` means no confirmed state. */
export type SharingState =
  | "unknown"
  | "paused"
  | "starting"
  | "sharing"
  | "pausing"
  | "unconfirmed"
  | "failsafe";

export type PeerLink = "unknown" | "connected" | "offline";

/** Where keyboard and pointer input is actually going right now. */
export type InputDestination = "unknown" | "local" | "peer";

export type Toggle = "unknown" | "on" | "off";

/** A capability is either supported by the source, or carries the reason it
 *  isn't, which the UI must show next to the control. */
export type Capability = { supported: true } | { supported: false; reason: string };

export interface Computer {
  name: string;
  platform: Platform;
}

export interface Blocker {
  title: string;
  /** User-facing explanation; no protocol terminology. */
  detail: string;
  /** What the person can do about it. */
  remedy: string;
}

export interface UtilitySnapshot {
  source: SnapshotSource;
  /** Human-readable label for the fixture; null for `unavailable`. */
  label: string | null;
  thisComputer: Computer | null;
  peer: (Computer & { link: PeerLink }) | null;
  sharing: SharingState;
  destination: InputDestination;
  clipboard: Toggle;
  launchAtLogin: Toggle;
  blocker: Blocker | null;
  /** Technical lines for troubleshooting only. Never shown in the widget. */
  technical: string[];
  capabilities: {
    pauseResume: Capability;
    settingsWrite: Capability;
    setup: Capability;
    quit: Capability;
    diagnosticsExport: Capability;
  };
}

export type Tone = "neutral" | "active" | "pending" | "attention";

/** Icon shape — states must differ by shape, not only by colour. */
export type GlyphShape = "absent" | "paused" | "pending" | "sharing" | "attention";

export interface StatusView {
  headline: string;
  detail: string;
  tone: Tone;
  glyph: GlyphShape;
}

export const NO_AGENT_REASON =
  "No Software KVM agent is connected to this preview, so this can’t be changed here.";

export function unsupported(reason: string): Capability {
  return { supported: false, reason };
}

export function unavailableSnapshot(): UtilitySnapshot {
  const none = unsupported(NO_AGENT_REASON);
  return {
    source: "unavailable",
    label: null,
    thisComputer: null,
    peer: null,
    sharing: "unknown",
    destination: "unknown",
    clipboard: "unknown",
    launchAtLogin: "unknown",
    blocker: {
      title: "Agent not connected",
      detail:
        "This development preview has no connection to the new Software KVM agent. Nothing here reflects your computers.",
      remedy:
        "Use the existing console for real sharing. This view will show confirmed state once the new agent reports it.",
    },
    technical: ["source: none (development preview)", "local control API: not implemented in this build"],
    capabilities: {
      pauseResume: none,
      settingsWrite: none,
      setup: none,
      quit: unsupported("Quit is provided by the native tray menu, which isn’t part of this preview."),
      diagnosticsExport: none,
    },
  };
}

const thisName = (s: UtilitySnapshot) => s.thisComputer?.name ?? "this computer";
const peerName = (s: UtilitySnapshot) => s.peer?.name ?? "the other computer";

export function describeStatus(s: UtilitySnapshot): StatusView {
  if (s.source === "unavailable") {
    return {
      headline: "Agent not connected",
      detail: "No status available. This preview can’t tell where input is going.",
      tone: "neutral",
      glyph: "absent",
    };
  }
  switch (s.sharing) {
    case "unknown":
      return {
        headline: "Status unknown",
        detail: "No confirmed state has been reported yet.",
        tone: "neutral",
        glyph: "absent",
      };
    case "failsafe":
      return {
        headline: "Sharing stopped for safety",
        detail: `Input is held on ${thisName(s)}. Recovery needs an explicit step in Troubleshoot.`,
        tone: "attention",
        glyph: "attention",
      };
    case "unconfirmed":
      return {
        headline: "Could not confirm this change",
        detail: "The last request wasn’t confirmed. Check where your pointer is before typing.",
        tone: "attention",
        glyph: "attention",
      };
    case "starting":
      return {
        headline: "Starting",
        detail: `Waiting for confirmation. Input stays on ${thisName(s)} until then.`,
        tone: "pending",
        glyph: "pending",
      };
    case "pausing":
      return {
        headline: "Pausing",
        detail: "Waiting for confirmation that input is back on this computer.",
        tone: "pending",
        glyph: "pending",
      };
    case "paused":
      return {
        headline: "Sharing is paused",
        detail: `Keyboard and pointer stay on ${thisName(s)}.`,
        tone: "neutral",
        glyph: "paused",
      };
    case "sharing":
      if (s.peer?.link !== "connected") {
        return {
          headline: `Waiting for ${peerName(s)}`,
          detail: `${peerName(s)} isn’t reachable. Input stays on ${thisName(s)}.`,
          tone: "pending",
          glyph: "pending",
        };
      }
      if (s.destination === "peer") {
        return {
          headline: `Controlling ${peerName(s)}`,
          detail: `Keyboard and pointer are going to ${peerName(s)}.`,
          tone: "active",
          glyph: "sharing",
        };
      }
      if (s.destination === "local") {
        return {
          headline: "Ready to share",
          detail: `Input is on ${thisName(s)}. Cross the shared screen edge to reach ${peerName(s)}.`,
          tone: "active",
          glyph: "sharing",
        };
      }
      return {
        headline: "Sharing on, destination unknown",
        detail: "Where input is going hasn’t been confirmed.",
        tone: "attention",
        glyph: "attention",
      };
  }
}

export type PrimaryAction =
  | { kind: "none"; guidance: string }
  | { kind: "pause" | "resume"; label: string; enabled: true }
  | { kind: "pause" | "resume"; label: string; enabled: false; reason: string };

/** The one primary widget action. Pause is offered whenever input could be
 *  shared, Resume only from a confirmed pause. A failsafe latch never offers
 *  an ordinary Resume. */
export function primaryAction(s: UtilitySnapshot): PrimaryAction {
  const cap = s.capabilities.pauseResume;
  let kind: "pause" | "resume";
  switch (s.sharing) {
    case "failsafe":
      return { kind: "none", guidance: "Resume isn’t available after a safety stop. Open Troubleshoot to recover." };
    case "paused":
      kind = "resume";
      break;
    case "unknown":
      // No confirmed state: offer the safe direction, which stays disabled
      // unless the source can actually carry the command.
      kind = "pause";
      break;
    default:
      kind = "pause";
  }
  const label = kind === "pause" ? "Pause sharing" : "Resume sharing";
  if (!cap.supported) return { kind, label, enabled: false, reason: cap.reason };
  if (s.sharing === "starting" || s.sharing === "pausing") {
    return { kind, label, enabled: false, reason: "Waiting for the current change to be confirmed." };
  }
  return { kind, label, enabled: true };
}

export function toggleLabel(t: Toggle): string {
  return t === "on" ? "On" : t === "off" ? "Off" : "Unknown";
}

export function platformLabel(p: Platform): string {
  return p === "macos" ? "macOS" : "Windows";
}
