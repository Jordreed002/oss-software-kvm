import { useEffect, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from "react";
import { X } from "lucide-react";
import { FIXTURE_IDS, FIXTURE_LABELS, fixtureSnapshot, type FixtureId } from "./fixtures";
import { isNativePreviewHost } from "./entry";
import { describeStatus, unavailableSnapshot } from "./model";
import { StatusGlyph } from "./parts";
import { SettingsWindow, type SettingsSection } from "./SettingsWindow";
import { SetupWindow, type SetupStep } from "./SetupWindow";
import { Widget } from "./Widget";
import "./utility.css";

type Source = "none" | FixtureId;
type Theme = "system" | "light" | "dark";
type View = "widget" | "setup" | "settings";

const VIEWS: readonly { id: View; label: string }[] = [
  { id: "widget", label: "Widget" },
  { id: "setup", label: "Setup" },
  { id: "settings", label: "Settings" },
];

/** Development host for the replacement utility surfaces. It stands in for
 *  the native tray icon and windows, which the Tauri shell will own later. */
export default function UtilityPreview() {
  const [source, setSource] = useState<Source>("none");
  const [theme, setTheme] = useState<Theme>("system");
  const [view, setView] = useState<View>("widget");
  const [widgetOpen, setWidgetOpen] = useState(true);
  const [section, setSection] = useState<SettingsSection>("computers");
  const [step, setStep] = useState<SetupStep>("identify");
  const [nativeHost] = useState(() => isNativePreviewHost(window));

  const snapshot = source === "none" ? unavailableSnapshot() : fixtureSnapshot(source);
  const status = describeStatus(snapshot);

  const trayRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const focusAfterRender = useRef<"panel" | "tray" | null>(null);

  useEffect(() => {
    const target = focusAfterRender.current;
    if (!target) return;
    focusAfterRender.current = null;
    (target === "panel" ? panelRef.current : trayRef.current)?.focus();
  }, [widgetOpen, view]);

  const dismissWidget = (restoreFocus: boolean) => {
    if (restoreFocus) focusAfterRender.current = "tray";
    setWidgetOpen(false);
  };

  const openWindow = (next: Exclude<View, "widget">, nextSection?: SettingsSection) => {
    if (nextSection) setSection(nextSection);
    setView(next);
  };

  const closeWindow = () => {
    focusAfterRender.current = "tray";
    setWidgetOpen(false);
    setView("widget");
  };

  const onDeskPointerDown = (event: PointerEvent<HTMLElement>) => {
    if (!widgetOpen || view !== "widget") return;
    const target = event.target as Node;
    if (panelRef.current?.contains(target) || trayRef.current?.contains(target)) return;
    dismissWidget(false);
  };

  const onPanelKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      dismissWidget(true);
    }
  };

  return (
    <div className="kvmu" data-theme={theme === "system" ? undefined : theme}>
      <div className="u-previewbar" role="region" aria-label="Development preview controls">
        <p className="u-previewbar-title">
          <span className="u-badge" data-kind="preview">Dev preview</span>
          {nativeHost
            ? "Native tray preview — no agent connected, owns no input"
            : "Utility UI — not connected to a native tray or agent"}
        </p>
        <label className="u-field">
          <span>Preview scenario</span>
          <select className="u-select" value={source} onChange={(e) => setSource(e.target.value as Source)}>
            <option value="none">No agent (default, real state)</option>
            {FIXTURE_IDS.map((id) => (
              <option key={id} value={id}>
                Preview fixture: {FIXTURE_LABELS[id]}
              </option>
            ))}
          </select>
        </label>
        <label className="u-field">
          <span>Theme</span>
          <select className="u-select" value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
            <option value="system">System</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </label>
        <div className="u-segmented" role="group" aria-label="Surface">
          {VIEWS.map((v) => (
            <button
              key={v.id}
              type="button"
              className="u-segment"
              aria-pressed={view === v.id}
              onClick={() => {
                setView(v.id);
                if (v.id === "widget") setWidgetOpen(true);
              }}
            >
              {v.label}
            </button>
          ))}
        </div>
      </div>

      <main className="u-desk" onPointerDown={onDeskPointerDown}>
        {view === "widget" ? (
          <div className="u-tray-zone">
            <div className="u-menubar" aria-label="Mock notification area">
              <button
                ref={trayRef}
                type="button"
                className="u-tray-button"
                data-tone={status.tone}
                aria-label={`Software KVM: ${status.headline}`}
                aria-expanded={widgetOpen}
                aria-controls="u-widget"
                onClick={() => {
                  if (widgetOpen) {
                    dismissWidget(false);
                  } else {
                    focusAfterRender.current = "panel";
                    setWidgetOpen(true);
                  }
                }}
              >
                <StatusGlyph shape={status.glyph} />
              </button>
            </div>
            {widgetOpen ? (
              <div
                ref={panelRef}
                id="u-widget"
                className="u-widget"
                role="dialog"
                aria-label="Software KVM"
                tabIndex={-1}
                onKeyDown={onPanelKeyDown}
              >
                <Widget
                  key={source}
                  snapshot={snapshot}
                  onOpenSettings={() => openWindow("settings", "computers")}
                  onOpenTroubleshoot={() => openWindow("settings", "troubleshoot")}
                />
              </div>
            ) : (
              <p className="u-desk-hint">Widget dismissed. Activate the tray icon to open it again.</p>
            )}
          </div>
        ) : view === "settings" ? (
          <MockWindow title="Software KVM Settings" source={snapshot.source} onClose={closeWindow}>
            <SettingsWindow key={source} snapshot={snapshot} section={section} onSection={setSection} />
          </MockWindow>
        ) : (
          <MockWindow title="Set up Software KVM" source={snapshot.source} onClose={closeWindow}>
            <SetupWindow snapshot={snapshot} step={step} onStep={setStep} />
          </MockWindow>
        )}
      </main>
    </div>
  );
}

function MockWindow({
  title,
  source,
  onClose,
  children,
}: {
  title: string;
  source: "unavailable" | "preview-fixture";
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <section className="u-window" aria-labelledby="u-window-title">
      <header className="u-window-titlebar">
        <h1 id="u-window-title">{title}</h1>
        <span className="u-badge" data-kind={source === "preview-fixture" ? "preview" : "offline"}>
          {source === "preview-fixture" ? "Preview fixture" : "No agent"}
        </span>
        <button type="button" className="u-icon-btn" aria-label={`Close ${title}`} onClick={onClose}>
          <X size={15} aria-hidden="true" />
        </button>
      </header>
      {children}
    </section>
  );
}
