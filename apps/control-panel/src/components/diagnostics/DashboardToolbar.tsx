import { Download, Pause, Play, RefreshCw } from "lucide-react";

interface DashboardToolbarProps {
  paused: boolean;
  updatedAt: number | null;
  canRefresh: boolean;
  canExport: boolean;
  onRefresh: () => void;
  onTogglePause: () => void;
  onExport: () => void;
}

/** Dashboard header: copy block, refresh/pause/export controls, and the live
 *  pulse readout. Extracted from DiagnosticsDashboard.tsx verbatim — the poll /
 *  pause / export handlers are passed in as props. */
export function DashboardToolbar({ paused, updatedAt, canRefresh, canExport, onRefresh, onTogglePause, onExport }: DashboardToolbarProps) {
  return (
    <header className="dashboard-head">
      <div>
        <div className="eyebrow">DIAGNOSTICS · SEPARATE CHANNEL · 24801</div>
        <h2>Live session monitor</h2>
        <p>
          Aggregate counters and redacted distributions pulled over a dedicated read-only connection — distinct from the
          active KVM switch on 24800. No input payloads, credentials, or peer addresses leave either host.
        </p>
      </div>
      <div className="dashboard-controls">
        <button
          type="button"
          className="dash-btn"
          onClick={onRefresh}
          disabled={!canRefresh}
          title="Poll both hosts once now"
        >
          <RefreshCw size={13} /> Refresh
        </button>
        <button
          type="button"
          className={`dash-btn${paused ? " active" : ""}`}
          onClick={onTogglePause}
          aria-pressed={paused}
          title={paused ? "Resume periodic polling" : "Pause periodic polling"}
        >
          {paused ? (<><Play size={13} /> Resume</>) : (<><Pause size={13} /> Pause</>)}
        </button>
        <button
          type="button"
          className="dash-btn"
          onClick={onExport}
          disabled={!canExport}
          title="Download the current diagnostics pair as JSON"
        >
          <Download size={13} /> Export
        </button>
        <div className={`dashboard-pulse${paused ? " paused" : ""}`} aria-live="polite">
          <i />
          {paused ? "Paused" : updatedAt ? `Updated ${new Date(updatedAt).toLocaleTimeString()}` : "Connecting…"}
        </div>
      </div>
    </header>
  );
}
