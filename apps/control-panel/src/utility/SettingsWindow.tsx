import { Info, KeyRound, Keyboard, LifeBuoy, MonitorSmartphone, Power } from "lucide-react";
import { SectionNav, type NavItem } from "./SectionNav";
import { platformLabel, type UtilitySnapshot } from "./model";
import { LockedSwitch, Unavailable, capabilityReason } from "./parts";

export type SettingsSection = "computers" | "input" | "permissions" | "startup" | "troubleshoot" | "about";

const ICON = { size: 15, "aria-hidden": true } as const;

const SECTIONS: readonly NavItem<SettingsSection>[] = [
  { id: "computers", label: "Computers & displays", icon: <MonitorSmartphone {...ICON} /> },
  { id: "input", label: "Keyboard & clipboard", icon: <Keyboard {...ICON} /> },
  { id: "permissions", label: "Permissions", icon: <KeyRound {...ICON} /> },
  { id: "startup", label: "Startup", icon: <Power {...ICON} /> },
  { id: "troubleshoot", label: "Troubleshoot", icon: <LifeBuoy {...ICON} /> },
  { id: "about", label: "About", icon: <Info {...ICON} /> },
];

export function SettingsWindow({
  snapshot,
  section,
  onSection,
}: {
  snapshot: UtilitySnapshot;
  section: SettingsSection;
  onSection: (section: SettingsSection) => void;
}) {
  const current = SECTIONS.find((s) => s.id === section)!;
  return (
    <div className="u-window-body u-split">
      <SectionNav label="Settings sections" items={SECTIONS} selected={section} onSelect={onSection} idPrefix="u-settings" />
      <section
        className="u-pane"
        role="tabpanel"
        id="u-settings-panel"
        aria-labelledby={`u-settings-tab-${section}`}
        tabIndex={0}
      >
        <h2 className="u-pane-title">{current.label}</h2>
        <SectionBody snapshot={snapshot} section={section} />
      </section>
    </div>
  );
}

function SectionBody({ snapshot, section }: { snapshot: UtilitySnapshot; section: SettingsSection }) {
  const writeReason = capabilityReason(snapshot.capabilities.settingsWrite);
  const locked = writeReason ?? "";
  switch (section) {
    case "computers":
      return (
        <>
          <dl className="u-rows">
            <Row term="This computer" value={snapshot.thisComputer ? `${snapshot.thisComputer.name} · ${platformLabel(snapshot.thisComputer.platform)}` : "Unknown"} />
            <Row term="Other computer" value={snapshot.peer ? `${snapshot.peer.name} · ${platformLabel(snapshot.peer.platform)}` : "Not known"} />
          </dl>
          <ActionRow id="u-arrange" label="Arrange displays…" reason={writeReason} />
          <ActionRow id="u-forget" label="Forget this computer…" reason={writeReason} tone="danger" />
        </>
      );
    case "input":
      return (
        <>
          <LockedSwitch id="u-clipboard" label="Share plain-text clipboard" value={snapshot.clipboard} reason={locked} />
          <p className="u-copy">
            Keyboard layout follows each computer’s own settings. Per-key remapping isn’t offered in this release.
          </p>
        </>
      );
    case "permissions":
      return (
        <>
          <p className="u-copy">
            Software KVM needs to read and send keyboard and pointer input. Only the installed app can check this, so the status
            below stays unknown in a preview.
          </p>
          <dl className="u-rows">
            <Row term="macOS · Accessibility" value="Unknown" />
            <Row term="macOS · Input Monitoring" value="Unknown" />
            <Row term="Windows · Firewall rule" value="Unknown" />
          </dl>
          <p className="u-copy u-copy-muted">
            On Windows, input can’t reach apps running as administrator or the sign-in screen.
          </p>
        </>
      );
    case "startup":
      return <LockedSwitch id="u-login" label="Open at login" value={snapshot.launchAtLogin} reason={locked || "Startup registration belongs to the native shell, which isn’t connected."} />;
    case "troubleshoot":
      return <Troubleshoot snapshot={snapshot} />;
    case "about":
      return (
        <dl className="u-rows">
          <Row term="Build" value="Development preview" />
          <Row term="Data source" value={snapshot.source === "preview-fixture" ? `Preview fixture: ${snapshot.label}` : "None — agent not connected"} />
          <Row term="Daily console" value="The existing console remains the default app." />
        </dl>
      );
  }
}

function Troubleshoot({ snapshot }: { snapshot: UtilitySnapshot }) {
  const exportReason = capabilityReason(snapshot.capabilities.diagnosticsExport);
  return (
    <>
      {snapshot.blocker ? (
        <div className="u-blocker" role="group" aria-labelledby="u-blocker-title">
          <h3 id="u-blocker-title">{snapshot.blocker.title}</h3>
          <p>{snapshot.blocker.detail}</p>
          <p className="u-blocker-remedy">
            <strong>What to do: </strong>
            {snapshot.blocker.remedy}
          </p>
        </div>
      ) : (
        <p className="u-copy">No problems are reported{snapshot.source === "preview-fixture" ? " in this fixture" : ""}.</p>
      )}
      <ActionRow id="u-export" label="Export support bundle…" reason={exportReason} />
      <details className="u-details">
        <summary>Technical detail</summary>
        <ul>
          {snapshot.technical.map((line) => (
            <li key={line}>
              <code>{line}</code>
            </li>
          ))}
        </ul>
      </details>
    </>
  );
}

function Row({ term, value }: { term: string; value: string }) {
  return (
    <div className="u-row">
      <dt>{term}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function ActionRow({ id, label, reason, tone }: { id: string; label: string; reason: string | null; tone?: "danger" }) {
  return (
    <div className="u-action-row">
      <button type="button" className="u-btn u-btn-secondary" data-tone={tone} disabled={reason !== null} aria-describedby={reason ? `${id}-reason` : undefined}>
        {label}
      </button>
      {reason ? <Unavailable id={`${id}-reason`}>{reason}</Unavailable> : null}
    </div>
  );
}
