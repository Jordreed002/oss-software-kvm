import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Check, ChevronRight, Eye, Pause, Play, Power, RefreshCw } from "lucide-react";
import { StatusGlyph, Unavailable } from "../parts";
import { queryAgentStatus, type AgentResult, type InvokeStatus } from "./status";
import { useAgentStatus } from "./useAgentStatus";
import { CHECKING_VIEW, projectAgent, type AgentView, type ReadinessItem } from "./view";
import "../utility.css";
import "./agent.css";

/** Native event the tray emits each time it opens this window. */
export const OPENED_EVENT = "utility-agent:opened";

export type SubscribeOpened = (onOpened: () => void) => () => void;

const tauriInvoke: InvokeStatus = (command) => invoke(command);

/** Listens for the tray's open event. Handles unsubscribing before the async
 *  registration resolves (StrictMode, fast unmount). */
const subscribeTauriOpened: SubscribeOpened = (onOpened) => {
  let disposed = false;
  let unlisten: (() => void) | null = null;
  listen(OPENED_EVENT, () => onOpened()).then(
    (fn) => {
      if (disposed) fn();
      else unlisten = fn;
    },
    () => {
      // Without the event the page still fetches on mount and on Refresh.
    },
  );
  return () => {
    disposed = true;
    unlisten?.();
  };
};

const TIME = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export interface AgentUtilityProps {
  invoke?: InvokeStatus;
  subscribeOpened?: SubscribeOpened;
  now?: () => number;
}

/** Read-only agent status for the `--utility-agent` development shell.
 *  Real snapshots or a named failure; no fixtures, no commands. */
export default function AgentUtility({
  invoke: invokeStatus = tauriInvoke,
  subscribeOpened = subscribeTauriOpened,
  now,
}: AgentUtilityProps) {
  // Created once so the hook's mount query and refreshes share one function.
  const [query] = useState(() => (): Promise<AgentResult> => queryAgentStatus(invokeStatus));
  const { result, checkedAt, checking, refresh } = useAgentStatus(query, now);

  useEffect(() => subscribeOpened(refresh), [subscribeOpened, refresh]);

  // Re-project only when a new result settles, not on every checking toggle.
  const view = useMemo(() => (result ? projectAgent(result) : CHECKING_VIEW), [result]);

  return (
    <div className="kvmu u-agent">
      <main className="u-agent-panel" aria-busy={checking}>
        <AgentHeader view={view} />
        <div className="u-agent-content">
          <AgentStatus view={view} />
          <AgentAction view={view} />
          {view.readiness ? <Readiness items={view.readiness} /> : null}
          {view.facts ? (
            <dl className="u-agent-facts" aria-label="Agent status">
              {view.facts.map((f) => (
                <div key={f.label}>
                  <dt>{f.label}</dt>
                  <dd data-unknown={f.unknown || undefined}>{f.value}</dd>
                </div>
              ))}
            </dl>
          ) : null}
          <details className="u-agent-details">
            <summary>
              <ChevronRight size={14} aria-hidden="true" className="u-agent-chevron" />
              Technical details
            </summary>
            <ul>
              {view.technical.map((line) => (
                <li key={line}>
                  <code>{line}</code>
                </li>
              ))}
            </ul>
          </details>
        </div>
        <footer className="u-agent-foot">
          <p className="u-agent-checked" role="status">
            {checking
              ? "Checking agent status…"
              : checkedAt !== null
                ? `Checked at ${TIME.format(checkedAt)}`
                : ""}
          </p>
          <button
            type="button"
            className="u-agent-btn u-agent-quiet"
            disabled
            title={view.quitReason}
            aria-describedby="u-agent-quit-reason"
          >
            <Power size={13} aria-hidden="true" />
            Quit agent
          </button>
          <span className="u-visually-hidden" id="u-agent-quit-reason">
            {view.quitReason}
          </span>
          <button type="button" className="u-agent-btn u-agent-ghost" onClick={refresh}>
            <RefreshCw size={13} aria-hidden="true" className="u-agent-refresh-icon" data-spinning={checking || undefined} />
            Refresh
          </button>
        </footer>
      </main>
    </div>
  );
}

function AgentHeader({ view }: { view: AgentView }) {
  return (
    <header className="u-agent-head">
      <span className="u-agent-brand">
        <span className="u-agent-wordmark">Software KVM</span>
        <span className="u-agent-mode">
          <Eye size={12} aria-hidden="true" />
          Dev build, read-only
        </span>
      </span>
      <span className="u-agent-conn" data-kind={view.badge.kind}>
        <span className="u-agent-dot" aria-hidden="true" />
        {view.badge.label}
      </span>
    </header>
  );
}

function AgentStatus({ view }: { view: AgentView }) {
  return (
    <section className="u-agent-status" data-tone={view.tone} aria-labelledby="u-agent-headline">
      <span className="u-agent-glyph">
        <StatusGlyph shape={view.glyph} size={18} />
      </span>
      <div className="u-agent-status-text">
        <h1 className="u-agent-headline" id="u-agent-headline">
          {view.headline}
        </h1>
        <p className="u-agent-detail">{view.detail}</p>
        {view.remedy ? <p className="u-agent-remedy">{view.remedy}</p> : null}
      </div>
    </section>
  );
}

function AgentAction({ view }: { view: AgentView }) {
  const primary = view.primary;
  if (primary.kind === "none") {
    return (
      <div className="u-agent-action">
        <Unavailable id="u-agent-primary-reason">{primary.guidance}</Unavailable>
      </div>
    );
  }
  return (
    <div className="u-agent-action">
      <button type="button" className="u-agent-btn u-agent-primary" disabled aria-describedby="u-agent-primary-reason">
        {primary.kind === "pause" ? <Pause size={14} aria-hidden="true" /> : <Play size={14} aria-hidden="true" />}
        {primary.label}
      </button>
      <Unavailable id="u-agent-primary-reason">{primary.reason}</Unavailable>
    </div>
  );
}

function Readiness({ items }: { items: ReadinessItem[] }) {
  const confirmed = items.filter((r) => r.confirmed).length;
  return (
    <section className="u-agent-ready" aria-labelledby="u-agent-ready-title">
      <div className="u-agent-ready-head">
        <h2 id="u-agent-ready-title">Ready to share</h2>
        <span className="u-agent-ready-count">
          {confirmed} of {items.length} confirmed
        </span>
      </div>
      <span className="u-agent-meter" aria-hidden="true">
        {items.map((r) => (
          <span key={r.key} data-confirmed={r.confirmed || undefined} />
        ))}
      </span>
      <ul>
        {items.map((r) => (
          <li key={r.key} data-confirmed={r.confirmed || undefined}>
            <span className="u-agent-mark" aria-hidden="true">
              {r.confirmed ? <Check size={10} strokeWidth={3} /> : null}
            </span>
            <span className="u-agent-ready-label">{r.label}</span>
            <span className="u-visually-hidden">{r.confirmed ? ": confirmed" : ": not confirmed"}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
