/** Projection from an agent status result to what the read-only agent
 *  surface says. Pure, so every wording rule is testable without rendering.
 *
 *  Rules (ADR 0003 / agent API docs):
 *  - Unknown input destination is never shown as "on this computer", even
 *    while pause is requested. Intent is a request, not a fact.
 *  - Readiness `unconfirmed` is "Not confirmed", never "missing" or "failed".
 *  - Only `remote` authority may say "Controlling".
 *  - This build cannot send commands, so every mutation is disabled with a
 *    reason, whatever the agent advertises. No optimistic outcome exists. */

import type { GlyphShape, Tone } from "../model";
import type {
  AgentResult,
  AgentSnapshot,
  CapabilityKey,
  FailureKind,
  Lifecycle,
  ReadinessKey,
  SafetyCause,
} from "./status";
import { READINESS_KEYS } from "./status";

export type Badge = { label: string; kind: "agent" | "offline" | "attention" | "pending" };

export interface Fact {
  label: string;
  value: string;
  /** True when the value is an explicit unknown; styled as such. */
  unknown: boolean;
}

export interface ReadinessItem {
  key: ReadinessKey;
  label: string;
  confirmed: boolean;
}

export type Mutation =
  | { kind: "pause" | "resume"; label: string; reason: string }
  | { kind: "none"; guidance: string };

export interface AgentView {
  badge: Badge;
  headline: string;
  detail: string;
  tone: Tone;
  glyph: GlyphShape;
  /** What the person can do; null when nothing is needed. */
  remedy: string | null;
  /** Present only for a connected snapshot. */
  facts: Fact[] | null;
  readiness: ReadinessItem[] | null;
  /** Always disabled in this build. */
  primary: Mutation;
  quitReason: string;
  technical: string[];
}

const READ_ONLY = "This development build only reads status, so it can’t send";

const READINESS_LABELS: Record<ReadinessKey, string> = {
  configuration: "Settings saved",
  enrollment: "Computers paired",
  permissions: "Input permissions",
  inventory: "Displays and devices",
  peerAuthentication: "Other computer verified",
  inputAuthority: "Input control available",
};

const LIFECYCLE_LABELS: Record<Lifecycle, string> = {
  idle: "Idle",
  preparing: "Starting",
  active: "Active",
  draining: "Stopping",
  faulted: "Fault reported",
};

const CAUSE_TEXT: Record<SafetyCause, string> = {
  failsafe_command: "A safety stop was requested.",
  native_permission_loss: "The system withdrew input permissions.",
  peer_link_failure: "The link to the other computer failed.",
  unspecified: "The agent didn’t report a cause.",
};

const CAUSE_SHORT: Record<SafetyCause, string> = {
  failsafe_command: "Safety stop requested",
  native_permission_loss: "Permissions withdrawn",
  peer_link_failure: "Link failed",
  unspecified: "Cause not reported",
};

interface FailureCopy {
  badge: string;
  headline: string;
  detail: string;
  remedy: string;
}

export const FAILURE_COPY: Record<FailureKind, FailureCopy> = {
  not_found: {
    badge: "No agent",
    headline: "Agent not running",
    detail: "No Software KVM agent answered for your account on this computer.",
    remedy: "Start the agent, then select Refresh.",
  },
  permission_denied: {
    badge: "Not trusted",
    headline: "Agent couldn’t be verified",
    detail: "Something answered at the agent’s address, but it couldn’t be verified as running under your account, so no status was read.",
    remedy: "Quit any agent started by another account or with elevated rights, start it normally, then refresh.",
  },
  timed_out: {
    badge: "No reply",
    headline: "Agent didn’t answer in time",
    detail: "The status check stopped waiting after 2 seconds. Nothing was read.",
    remedy: "Refresh to try again. If it keeps happening, restart the agent.",
  },
  incompatible: {
    badge: "Incompatible",
    headline: "Agent version doesn’t match",
    detail: "The running agent speaks a different version of the status protocol than this control panel.",
    remedy: "Run the agent and the control panel from the same build.",
  },
  invalid_reply: {
    badge: "Bad reply",
    headline: "Agent reply was rejected",
    detail: "The agent answered, but the reply was malformed or didn’t match the request, so it was ignored.",
    remedy: "Refresh. If it repeats, restart the agent.",
  },
  transport: {
    badge: "Disconnected",
    headline: "Connection to the agent failed",
    detail: "The connection broke before any status was read.",
    remedy: "Refresh to try again.",
  },
  bridge: {
    badge: "App error",
    headline: "Status check couldn’t run",
    detail: "The control panel’s native side didn’t return a status this page can read.",
    remedy: "Restart the utility from a development build with --utility-agent.",
  },
};

const NO_AGENT_MUTATION = "No agent status was read, so nothing can be changed here.";

function mutationReason(verb: string, offer: "supported" | "unsupported"): string {
  return offer === "unsupported"
    ? `The agent doesn’t offer ${verb} yet.`
    : `${READ_ONLY} ${verb}.`;
}

function capabilityLine(key: CapabilityKey, offer: "supported" | "unsupported"): string {
  return `capability ${key}: ${offer}`;
}

/** Shown before the first result arrives. */
export const CHECKING_VIEW: AgentView = {
  badge: { label: "Checking", kind: "pending" },
  headline: "Checking the agent",
  detail: "Asking the local agent for its status.",
  tone: "pending",
  glyph: "pending",
  remedy: null,
  facts: null,
  readiness: null,
  primary: { kind: "pause", label: "Pause sharing", reason: "Waiting for the agent’s status." },
  quitReason: "Quit is in the tray menu. It closes this window only; the agent keeps running.",
  technical: ["source: native agent (read-only)", "status: not yet read"],
};

export function projectAgent(result: AgentResult): AgentView {
  return result.kind === "connected" ? projectSnapshot(result.snapshot) : projectFailure(result.error);
}

export function projectFailure(error: FailureKind): AgentView {
  const copy = FAILURE_COPY[error];
  return {
    badge: { label: copy.badge, kind: error === "not_found" ? "offline" : "attention" },
    headline: copy.headline,
    detail: copy.detail,
    tone: error === "not_found" ? "neutral" : "attention",
    glyph: error === "not_found" ? "absent" : "attention",
    remedy: copy.remedy,
    facts: null,
    readiness: null,
    primary: { kind: "pause", label: "Pause sharing", reason: NO_AGENT_MUTATION },
    quitReason: CHECKING_VIEW.quitReason,
    technical: ["source: native agent (read-only)", `status: unavailable (${error})`],
  };
}

function inputFact(s: AgentSnapshot): Fact {
  switch (s.input.destination) {
    case "local":
      return { label: "Input", value: "This computer", unknown: false };
    case "remote":
      return { label: "Input", value: s.input.host, unknown: false };
    case "transitioning":
      return { label: "Input", value: "Moving, not confirmed", unknown: true };
    case "unknown":
      return { label: "Input", value: "Not confirmed", unknown: true };
  }
}

interface Headline {
  headline: string;
  detail: string;
  tone: Tone;
  glyph: GlyphShape;
  remedy: string | null;
}

function inputSentence(s: AgentSnapshot): string {
  switch (s.input.destination) {
    case "local":
      return "Input is confirmed on this computer.";
    case "remote":
      return `Input is confirmed on ${s.input.host}.`;
    case "transitioning":
      return "Input is moving and isn’t confirmed on either computer.";
    case "unknown":
      return "Where keyboard and pointer are going isn’t confirmed.";
  }
}

function describe(s: AgentSnapshot): Headline {
  if (s.safety.state === "latched") {
    return {
      headline: "Sharing stopped for safety",
      detail: `${CAUSE_TEXT[s.safety.cause]} ${inputSentence(s)}`,
      tone: "attention",
      glyph: "attention",
      remedy: "Ordinary Resume can’t clear a safety stop. Release any held keys and check where your pointer is.",
    };
  }
  if (s.cleanupUnconfirmed) {
    return {
      headline: "Cleanup not confirmed",
      detail: `The agent couldn’t confirm that input was released. ${inputSentence(s)}`,
      tone: "attention",
      glyph: "attention",
      remedy: "Check which computer your pointer is on before typing.",
    };
  }
  if (s.lifecycle === "faulted") {
    return {
      headline: "Agent reported a fault",
      detail: `The sharing session failed. ${inputSentence(s)}`,
      tone: "attention",
      glyph: "attention",
      remedy: "Restart the agent. Check where your pointer is before typing.",
    };
  }
  const requested = s.userIntent === "paused" ? "Pause is requested" : "Sharing is requested";
  switch (s.input.destination) {
    case "remote":
      return {
        headline: `Controlling ${s.input.host}`,
        detail: `Keyboard and pointer are going to ${s.input.host}.`,
        tone: "active",
        glyph: "sharing",
        remedy: null,
      };
    case "transitioning":
      return {
        headline: "Input is moving",
        detail: "Waiting for the agent to confirm which computer has input.",
        tone: "pending",
        glyph: "pending",
        remedy: null,
      };
    case "unknown":
      return {
        headline: "Input location not confirmed",
        detail: `${requested}, but the agent hasn’t confirmed where keyboard and pointer are going.`,
        tone: "neutral",
        glyph: "absent",
        remedy: null,
      };
    case "local":
      if (s.userIntent === "paused") {
        return {
          headline: "Sharing is paused",
          detail: "Input is confirmed on this computer.",
          tone: "neutral",
          glyph: "paused",
          remedy: null,
        };
      }
      if (s.lifecycle === "active") {
        return {
          headline: "Input is on this computer",
          detail: "Sharing is active. Input stays here until the agent confirms a switch.",
          tone: "active",
          glyph: "sharing",
          remedy: null,
        };
      }
      return {
        headline: "Input is on this computer",
        detail:
          s.lifecycle === "preparing"
            ? "Sharing is starting. Waiting for the agent to confirm it’s ready."
            : "Sharing is requested but hasn’t started.",
        tone: "pending",
        glyph: "pending",
        remedy: null,
      };
  }
}

export function projectSnapshot(s: AgentSnapshot): AgentView {
  const head = describe(s);
  const facts: Fact[] = [
    inputFact(s),
    {
      label: "Sharing request",
      value: s.userIntent === "paused" ? "Pause requested" : "Sharing requested",
      unknown: false,
    },
    { label: "Session", value: LIFECYCLE_LABELS[s.lifecycle], unknown: false },
    {
      label: "Safety",
      value: s.safety.state === "clear" ? "Clear" : `Stopped: ${CAUSE_SHORT[s.safety.cause]}`,
      unknown: false,
    },
  ];
  if (s.cleanupUnconfirmed) facts.push({ label: "Cleanup", value: "Not confirmed", unknown: true });

  const readiness = READINESS_KEYS.map((key) => ({
    key,
    label: READINESS_LABELS[key],
    confirmed: s.readiness[key] === "confirmed",
  }));

  let primary: Mutation;
  if (s.safety.state === "latched") {
    primary = { kind: "none", guidance: "Resume isn’t available after a safety stop." };
  } else if (s.userIntent === "paused") {
    primary = { kind: "resume", label: "Resume sharing", reason: mutationReason("Resume", s.capabilities.resume) };
  } else {
    primary = { kind: "pause", label: "Pause sharing", reason: mutationReason("Pause", s.capabilities.pause) };
  }

  return {
    badge: { label: "Agent connected", kind: "agent" },
    ...head,
    facts,
    readiness,
    primary,
    quitReason:
      s.capabilities.quit === "supported"
        ? `${READ_ONLY} Quit to the agent. The tray menu closes this window only.`
        : "The agent doesn’t offer Quit yet. The tray menu closes this window only.",
    technical: [
      "source: native agent (read-only)",
      `instance: ${s.instance}`,
      `revision: ${s.revision}`,
      ...(Object.keys(s.capabilities) as CapabilityKey[]).map((k) => capabilityLine(k, s.capabilities[k])),
    ],
  };
}
