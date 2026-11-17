import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Check, Pause, Play, Power, RefreshCw } from "lucide-react";
import { StatusGlyph, Unavailable } from "../parts";
import { queryAgentStatus, type AgentResult, type InvokeStatus } from "./status";
import { useAgentStatus } from "./useAgentStatus";
import { CHECKING_VIEW, projectAgent, type AgentView } from "./view";
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

  const view = result ? projectAgent(result) : CHECKING_VIEW;

  return (
    <div className="kvmu u-agent">
      <main className="u-agent-panel" aria-busy={checking}>
        <AgentHeader view={view} />
        <AgentBody view={view} />
        <footer className="u-agent-foot">
          <p className="u-agent-checked" role="status">
            {checking
              ? "Checking agent status…"
              : checkedAt !== null
                ? `Checked at ${TIME.format(checkedAt)}`
                : ""}
          </p>
          <button type="button" className="u-btn u-btn-secondary" onClick={refresh}>
            <RefreshCw size={14} aria-hidden="true" className="u-agent-refresh-icon" data-spinning={checking || undefined} />
            Refresh
          </button>
        </footer>
      </main>
    </div>
  );
}

function AgentHeader({ view }: { view: AgentView }) {
  return (
    <header className="u-widget-head">
      <span className="u-wordmark">Software KVM</span>
      <span className="u-agent-badges">
        <span className="u-badge" data-kind="preview">Dev, read-only</span>
        <span className="u-badge" data-kind={view.badge.kind}>
          {view.badge.label}
        </span>
      </span>
    </header>
  );
}

function AgentBody({ view }: { view: AgentView }) {
  const confirmed = view.readiness ? view.readiness.filter((r) => r.confirmed).length : 0;
  return (
    <>
      <section className="u-status" data-tone={view.tone} aria-labelledby="u-agent-headline">
        <span className="u-status-glyph">
          <StatusGlyph shape={view.glyph} size={20} />
        </span>
        <div>
          <h1 className="u-status-headline" id="u-agent-headline">
            {view.headline}
          </h1>
          <p className="u-status-detail">{view.detail}</p>
        </div>
      </section>

      {view.remedy ? <p className="u-agent-remedy">{view.remedy}</p> : null}

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

      {view.readiness ? (
        <section className="u-agent-ready" aria-labelledby="u-agent-ready-title">
          <div className="u-agent-ready-head">
            <h2 id="u-agent-ready-title">Ready to share</h2>
            <span>
              {confirmed} of {view.readiness.length} confirmed
            </span>
          </div>
          <ul>
            {view.readiness.map((r) => (
              <li key={r.key} data-confirmed={r.confirmed || undefined}>
                <span className="u-agent-mark" aria-hidden="true">
                  {r.confirmed ? <Check size={11} strokeWidth={3} /> : null}
                </span>
                <span className="u-agent-ready-label">{r.label}</span>
                <span className="u-agent-ready-value">{r.confirmed ? "Confirmed" : "Not confirmed"}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <div className="u-primary">
        {view.primary.kind === "none" ? (
          <Unavailable id="u-agent-primary-reason">{view.primary.guidance}</Unavailable>
        ) : (
          <>
            <button type="button" className="u-btn u-btn-primary" disabled aria-describedby="u-agent-primary-reason">
              {view.primary.kind === "pause" ? <Pause size={15} aria-hidden="true" /> : <Play size={15} aria-hidden="true" />}
              {view.primary.label}
            </button>
            <Unavailable id="u-agent-primary-reason">{view.primary.reason}</Unavailable>
          </>
        )}
      </div>

      <div className="u-agent-quit">
        <button type="button" className="u-btn u-btn-quiet" disabled aria-describedby="u-agent-quit-reason">
          <Power size={14} aria-hidden="true" />
          Quit agent
        </button>
        <span className="u-visually-hidden" id="u-agent-quit-reason">
          {view.quitReason}
        </span>
      </div>

      <details className="u-details u-agent-details">
        <summary>Technical details</summary>
        <ul>
          {view.technical.map((line) => (
            <li key={line}>
              <code>{line}</code>
            </li>
          ))}
        </ul>
      </details>
    </>
  );
}
