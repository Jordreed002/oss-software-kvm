/** Agent status contract between the native `agent_status` command and the
 *  `--utility-agent` page.
 *
 *  The Rust side projects the agent API snapshot into this shape
 *  (`src-tauri/src/utility_preview/agent.rs`). The page still validates every
 *  field: anything it does not recognise becomes a `bridge` failure, never a
 *  guessed or defaulted state. */

export type Lifecycle = "idle" | "preparing" | "active" | "draining" | "faulted";
export type Intent = "paused" | "sharing_requested";
export type SafetyCause = "failsafe_command" | "native_permission_loss" | "peer_link_failure" | "unspecified";
export type Safety = { state: "clear" } | { state: "latched"; cause: SafetyCause };
export type Input =
  | { destination: "local" }
  | { destination: "remote"; host: string }
  | { destination: "transitioning" }
  | { destination: "unknown" };
export type Check = "confirmed" | "unconfirmed";
export type Offer = "supported" | "unsupported";

export const READINESS_KEYS = [
  "configuration",
  "enrollment",
  "permissions",
  "inventory",
  "peerAuthentication",
  "inputAuthority",
] as const;
export type ReadinessKey = (typeof READINESS_KEYS)[number];

export const CAPABILITY_KEYS = ["pause", "resume", "failsafe", "quit", "snapshot"] as const;
export type CapabilityKey = (typeof CAPABILITY_KEYS)[number];

export interface AgentSnapshot {
  instance: string;
  /** Decimal string; u64 does not fit a JS number exactly. */
  revision: string;
  lifecycle: Lifecycle;
  userIntent: Intent;
  safety: Safety;
  cleanupUnconfirmed: boolean;
  input: Input;
  readiness: Record<ReadinessKey, Check>;
  capabilities: Record<CapabilityKey, Offer>;
}

/** Failure categories reported by the native client. */
export type AgentErrorKind =
  | "not_found"
  | "permission_denied"
  | "timed_out"
  | "incompatible"
  | "invalid_reply"
  | "transport";

/** Local failure: the page could not get or read an answer from its own
 *  native side (command missing/refused, or an unrecognised payload). */
export type FailureKind = AgentErrorKind | "bridge";

export type AgentResult = { kind: "connected"; snapshot: AgentSnapshot } | { kind: "failed"; error: FailureKind };

const AGENT_ERRORS: ReadonlySet<string> = new Set<AgentErrorKind>([
  "not_found",
  "permission_denied",
  "timed_out",
  "incompatible",
  "invalid_reply",
  "transport",
]);
const LIFECYCLES: ReadonlySet<string> = new Set<Lifecycle>(["idle", "preparing", "active", "draining", "faulted"]);
const INTENTS: ReadonlySet<string> = new Set<Intent>(["paused", "sharing_requested"]);
const CAUSES: ReadonlySet<string> = new Set<SafetyCause>([
  "failsafe_command",
  "native_permission_loss",
  "peer_link_failure",
  "unspecified",
]);
const CHECKS: ReadonlySet<string> = new Set<Check>(["confirmed", "unconfirmed"]);
const OFFERS: ReadonlySet<string> = new Set<Offer>(["supported", "unsupported"]);
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Matches the agent API's host label bound. */
const MAX_HOST_BYTES = 255;

export const BRIDGE_FAILURE: AgentResult = { kind: "failed", error: "bridge" };

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isIn = (set: ReadonlySet<string>, v: unknown): v is string => typeof v === "string" && set.has(v);
const keysExactly = (o: Obj, keys: readonly string[]) =>
  Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

function parseSafety(v: unknown): Safety | null {
  if (!isObj(v)) return null;
  if (v.state === "clear" && keysExactly(v, ["state"])) return { state: "clear" };
  if (v.state === "latched" && keysExactly(v, ["state", "cause"]) && isIn(CAUSES, v.cause)) {
    return { state: "latched", cause: v.cause as SafetyCause };
  }
  return null;
}

function parseInput(v: unknown): Input | null {
  if (!isObj(v)) return null;
  switch (v.destination) {
    case "local":
    case "transitioning":
    case "unknown":
      return keysExactly(v, ["destination"]) ? { destination: v.destination } : null;
    case "remote": {
      const host = v.host;
      if (!keysExactly(v, ["destination", "host"]) || typeof host !== "string") return null;
      if (host.trim() === "" || new TextEncoder().encode(host).length > MAX_HOST_BYTES) return null;
      return { destination: "remote", host };
    }
    default:
      return null;
  }
}

function parseRecord<K extends string, V extends string>(v: unknown, keys: readonly K[], values: ReadonlySet<string>) {
  if (!isObj(v) || !keysExactly(v, keys)) return null;
  const out = {} as Record<K, V>;
  for (const k of keys) {
    if (!isIn(values, v[k])) return null;
    out[k] = v[k] as V;
  }
  return out;
}

function parseSnapshot(v: unknown): AgentSnapshot | null {
  if (!isObj(v)) return null;
  const keys = [
    "instance",
    "revision",
    "lifecycle",
    "userIntent",
    "safety",
    "cleanupUnconfirmed",
    "input",
    "readiness",
    "capabilities",
  ];
  if (!keysExactly(v, keys)) return null;
  const { instance, revision, lifecycle, userIntent, cleanupUnconfirmed } = v;
  if (typeof instance !== "string" || !UUID.test(instance)) return null;
  if (typeof revision !== "string" || !DECIMAL.test(revision)) return null;
  if (!isIn(LIFECYCLES, lifecycle) || !isIn(INTENTS, userIntent)) return null;
  if (typeof cleanupUnconfirmed !== "boolean") return null;
  const safety = parseSafety(v.safety);
  const input = parseInput(v.input);
  const readiness = parseRecord<ReadinessKey, Check>(v.readiness, READINESS_KEYS, CHECKS);
  const capabilities = parseRecord<CapabilityKey, Offer>(v.capabilities, CAPABILITY_KEYS, OFFERS);
  if (!safety || !input || !readiness || !capabilities) return null;
  return {
    instance,
    revision,
    lifecycle: lifecycle as Lifecycle,
    userIntent: userIntent as Intent,
    safety,
    cleanupUnconfirmed,
    input,
    readiness,
    capabilities,
  };
}

/** Validates the raw command payload. Never throws. */
export function parseAgentStatus(raw: unknown): AgentResult {
  if (!isObj(raw)) return BRIDGE_FAILURE;
  if (raw.kind === "unavailable" && keysExactly(raw, ["kind", "error"]) && isIn(AGENT_ERRORS, raw.error)) {
    return { kind: "failed", error: raw.error as AgentErrorKind };
  }
  if (raw.kind === "connected" && keysExactly(raw, ["kind", "snapshot"])) {
    const snapshot = parseSnapshot(raw.snapshot);
    if (snapshot) return { kind: "connected", snapshot };
  }
  return BRIDGE_FAILURE;
}

/** Minimal invoke signature so tests never need a Tauri runtime. */
export type InvokeStatus = (command: "agent_status") => Promise<unknown>;

/** One read-only status query. Resolves to a result in every case. */
export async function queryAgentStatus(invoke: InvokeStatus): Promise<AgentResult> {
  let raw: unknown;
  try {
    raw = await invoke("agent_status");
  } catch {
    return BRIDGE_FAILURE;
  }
  return parseAgentStatus(raw);
}
