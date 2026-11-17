import { useState } from "react";
import { LifeBuoy, Pause, Play, Power, Settings } from "lucide-react";
import { sendCommand, type CommandOutcome } from "./commands";
import { describeStatus, primaryAction, toggleLabel, type UtilitySnapshot } from "./model";
import { StatusGlyph, Unavailable, WorkspaceSketch } from "./parts";

export interface WidgetProps {
  snapshot: UtilitySnapshot;
  onOpenSettings: () => void;
  onOpenTroubleshoot: () => void;
}

/** Compact anchored widget (~360 logical px). Answers: where is input going,
 *  is sharing ready, how do I pause safely. No charts, no protocol words. */
export function Widget({ snapshot, onOpenSettings, onOpenTroubleshoot }: WidgetProps) {
  const status = describeStatus(snapshot);
  const action = primaryAction(snapshot);
  const [outcome, setOutcome] = useState<CommandOutcome | null>(null);
  const { thisComputer, peer } = snapshot;
  const quitReason = snapshot.capabilities.quit.supported ? null : snapshot.capabilities.quit.reason;

  return (
    <div className="u-widget-body">
      <header className="u-widget-head">
        <span className="u-wordmark">Software KVM</span>
        {snapshot.source === "preview-fixture" ? (
          <span className="u-badge" data-kind="preview">Preview fixture</span>
        ) : (
          <span className="u-badge" data-kind="offline">No agent</span>
        )}
      </header>

      <section className="u-status" data-tone={status.tone} aria-labelledby="u-status-headline">
        <span className="u-status-glyph">
          <StatusGlyph shape={status.glyph} size={20} />
        </span>
        <div>
          <h1 className="u-status-headline" id="u-status-headline">
            {status.headline}
          </h1>
          <p className="u-status-detail">{status.detail}</p>
        </div>
      </section>

      {thisComputer && peer && snapshot.destination !== "unknown" ? (
        <WorkspaceSketch local={thisComputer} peer={peer} link={peer.link} destination={snapshot.destination} />
      ) : null}

      {peer ? (
        <dl className="u-facts">
          <div>
            <dt>Other computer</dt>
            <dd>
              {peer.name} · {peer.link === "connected" ? "Connected" : peer.link === "offline" ? "Offline" : "Unknown"}
            </dd>
          </div>
          <div>
            <dt>Clipboard</dt>
            <dd>{toggleLabel(snapshot.clipboard)}</dd>
          </div>
        </dl>
      ) : null}

      <div className="u-primary">
        {action.kind === "none" ? (
          <Unavailable id="u-primary-reason">{action.guidance}</Unavailable>
        ) : (
          <>
            <button
              type="button"
              className="u-btn u-btn-primary"
              disabled={!action.enabled}
              aria-describedby={!action.enabled ? "u-primary-reason" : outcome ? "u-outcome" : undefined}
              onClick={() => setOutcome(sendCommand(snapshot, { kind: action.kind }))}
            >
              {action.kind === "pause" ? <Pause size={15} aria-hidden="true" /> : <Play size={15} aria-hidden="true" />}
              {action.label}
            </button>
            {!action.enabled ? <Unavailable id="u-primary-reason">{action.reason}</Unavailable> : null}
          </>
        )}
        <p className="u-outcome" id="u-outcome" role="status">
          {outcome ? outcome.message : ""}
        </p>
      </div>

      <nav className="u-widget-foot" aria-label="Utility">
        <button type="button" className="u-btn u-btn-quiet" onClick={onOpenSettings}>
          <Settings size={14} aria-hidden="true" />
          Settings
        </button>
        <button type="button" className="u-btn u-btn-quiet" data-attention={snapshot.blocker ? true : undefined} onClick={onOpenTroubleshoot}>
          <LifeBuoy size={14} aria-hidden="true" />
          Troubleshoot
        </button>
        <button
          type="button"
          className="u-btn u-btn-quiet"
          disabled={quitReason !== null}
          aria-describedby={quitReason ? "u-quit-reason" : undefined}
          title={quitReason ?? undefined}
        >
          <Power size={14} aria-hidden="true" />
          Quit
        </button>
        {quitReason ? (
          <span className="u-visually-hidden" id="u-quit-reason">
            {quitReason}
          </span>
        ) : null}
      </nav>
    </div>
  );
}
