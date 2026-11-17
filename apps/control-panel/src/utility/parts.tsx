import { Info } from "lucide-react";
import type { Capability, Computer, GlyphShape, InputDestination, PeerLink } from "./model";

/** Status glyph. Each state has a distinct silhouette so it reads without
 *  colour (tray icons are often monochrome). Decorative: callers supply text. */
export function StatusGlyph({ shape, size = 16 }: { shape: GlyphShape; size?: number }) {
  return (
    <svg className="u-glyph" data-shape={shape} width={size} height={size} viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      {shape === "absent" ? (
        <circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="2.4 2.2" />
      ) : shape === "paused" ? (
        <>
          <rect x="4" y="3.5" width="2.6" height="9" rx="0.8" fill="currentColor" />
          <rect x="9.4" y="3.5" width="2.6" height="9" rx="0.8" fill="currentColor" />
        </>
      ) : shape === "pending" ? (
        <>
          <circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.35" />
          <path d="M8 2.5a5.5 5.5 0 0 1 5.5 5.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </>
      ) : shape === "sharing" ? (
        <>
          <rect x="1.5" y="1.5" width="13" height="13" rx="3.5" fill="currentColor" />
          <path d="M6.5 5l3 3-3 3" fill="none" stroke="var(--u-on-accent)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        </>
      ) : (
        <>
          <path d="M8 1.8l6.6 11.6H1.4z" fill="currentColor" strokeLinejoin="round" />
          <rect x="7.2" y="5.6" width="1.6" height="4.2" rx="0.6" fill="var(--u-on-accent)" />
          <rect x="7.2" y="10.8" width="1.6" height="1.6" rx="0.6" fill="var(--u-on-accent)" />
        </>
      )}
    </svg>
  );
}

/** Explains why a control is unavailable. Render next to the control and
 *  reference it with aria-describedby. */
export function Unavailable({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <p className="u-unavailable" id={id}>
      <Info size={13} aria-hidden="true" />
      <span>{children}</span>
    </p>
  );
}

export function capabilityReason(cap: Capability): string | null {
  return cap.supported ? null : cap.reason;
}

/** A read-only switch. Without a confirmed settings transaction it is always
 *  disabled; it shows the last known value (or Unknown) and the reason. */
export function LockedSwitch({
  id,
  label,
  value,
  reason,
}: {
  id: string;
  label: string;
  value: "on" | "off" | "unknown";
  reason: string;
}) {
  return (
    <div className="u-setting">
      <div className="u-setting-row">
        <span className="u-setting-label" id={`${id}-label`}>
          {label}
        </span>
        <button
          type="button"
          role="switch"
          className="u-switch"
          data-value={value}
          aria-checked={value === "on" ? true : value === "off" ? false : "mixed"}
          aria-labelledby={`${id}-label`}
          aria-describedby={`${id}-reason`}
          disabled
        >
          <span className="u-switch-thumb" />
          <span className="u-switch-text">{value === "on" ? "On" : value === "off" ? "Off" : "Unknown"}</span>
        </button>
      </div>
      <Unavailable id={`${id}-reason`}>{reason}</Unavailable>
    </div>
  );
}

/** Small two-screen sketch of where input is. Decorative: the status
 *  sentence carries the same fact for assistive technology. */
export function WorkspaceSketch({
  local,
  peer,
  link,
  destination,
}: {
  local: Computer;
  peer: Computer;
  link: PeerLink;
  destination: InputDestination;
}) {
  return (
    <div className="u-sketch" aria-hidden="true" data-link={link}>
      <Screen name={local.name} tag="This computer" active={destination === "local"} />
      <span className="u-sketch-link" />
      <Screen name={peer.name} tag={link === "connected" ? "Connected" : link === "offline" ? "Offline" : "Unknown"} active={destination === "peer"} />
    </div>
  );
}

function Screen({ name, tag, active }: { name: string; tag: string; active: boolean }) {
  return (
    <div className="u-screen" data-active={active || undefined}>
      <div className="u-screen-face">
        {active ? (
          <svg className="u-cursor" width="12" height="14" viewBox="0 0 12 14">
            <path d="M1 1l9.5 7.2-4.3.5L8.5 13 6.6 13.6 4.4 9.4 1 12z" fill="currentColor" stroke="var(--u-surface)" strokeWidth="1" strokeLinejoin="round" />
          </svg>
        ) : null}
      </div>
      <span className="u-screen-name">{name}</span>
      <span className="u-screen-tag">{tag}</span>
    </div>
  );
}
