import { useEffect, useMemo, useState } from "react";
import {
    ArrowLeftRight, Check, ChevronRight, CircleAlert, Copy, KeyRound,
  Handshake, Laptop, Link2, LoaderCircle, Monitor, MousePointer2, Move, Play, Radio, RotateCcw, ShieldCheck, Square, Unplug, X,
} from "lucide-react";
import { api } from "./bridge";
import type { DisplayInfo, DisplayPlacement, Placement, SetupSnapshot } from "./types";

const steps = ["This computer", "Pair", "Arrange", "Ready"] as const;

function hostFromSocketAddress(value?: string) {
  if (!value) return "";
  if (value.startsWith("[")) return value.slice(1, value.indexOf("]"));
  return value.slice(0, value.lastIndexOf(":"));
}

function App() {
  const [snapshot, setSnapshot] = useState<SetupSnapshot | null>(null);
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [bundle, setBundle] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.status().then((state) => {
      setSnapshot(state);
      setName(state.local?.displayName ?? state.suggestedName);
      setAddress(hostFromSocketAddress(state.local?.address) || state.addressOptions[0] || "");
      if (state.configured) setStep(3);
      else if (state.peer) setStep(2);
      else if (state.local) setStep(1);
    }).catch(() => setError("The native setup service did not respond."));
  }, []);

  useEffect(() => {
    if (step !== 1 && step !== 2 && step !== 3) return;
    const timer = window.setInterval(() => {
      if (!busy) api.status().then(setSnapshot).catch(() => undefined);
    }, snapshot?.runtime === "running" ? 400 : 1200);
    return () => window.clearInterval(timer);
  }, [step, busy, snapshot?.runtime]);

  useEffect(() => {
    if (step === 1 && snapshot?.peer) setStep(2);
  }, [snapshot?.peer, step]);

  useEffect(() => {
    if (step === 2 && snapshot?.configured && snapshot.workspaceRole === "follower") setStep(3);
  }, [snapshot?.configured, snapshot?.workspaceRole, step]);

  const perform = async (label: string, operation: () => Promise<SetupSnapshot>, next?: number) => {
    setBusy(label); setError(null);
    try {
      const state = await operation();
      setSnapshot(state);
      if (next !== undefined) setStep(next);
    } catch (operationError) {
      const detail = typeof operationError === "string"
        ? operationError
        : operationError instanceof Error
          ? operationError.message
          : "That step could not be completed safely. Nothing was changed.";
      setError(detail);
    } finally { setBusy(null); }
  };

  const readiness = useMemo(() => {
    if (!snapshot?.local) return "Identity needed";
    if (!snapshot.peer) return "Waiting for peer";
    if (!snapshot.validated) return "Needs validation";
    if (snapshot.runtime === "running") {
      if (snapshot.inputAuthority.owner === "peer") return `Input · ${snapshot.peer?.displayName ?? "Peer"}`;
      if (snapshot.inputAuthority.owner === "local") return `Input · ${snapshot.local?.displayName ?? "This computer"}`;
      return "Synchronizing input";
    }
    if (snapshot.runtime === "faulted") return "Needs attention";
    return "Ready to start";
  }, [snapshot]);

  if (!snapshot) return <Loading error={error} />;

  return (
    <main className="app-shell">
      <div className="ambient ambient-one" /><div className="ambient ambient-two" />
      <header className="topbar">
        <div className="brand"><span className="brand-mark"><ArrowLeftRight size={18} /></span><span>Software KVM</span><small>Link Console</small></div>
        <div className={`runtime-pill ${snapshot.runtime}`}><i />{readiness}</div>
      </header>

      <section className="workspace">
        <aside className="rail">
          <div className="eyebrow">SETUP / 01</div>
          <h1>Make two computers feel like one desk.</h1>
          <p>The console handles identity, trusted pairing, display placement, and the native runtime without exposing private keys.</p>
          <nav aria-label="Setup progress">
            {steps.map((label, index) => (
              <button key={label} className={index === step ? "active" : index < step ? "done" : ""} onClick={() => {
                if (index > step) return;
                if (index === 2 && snapshot.runtime === "running") {
                  void perform("stop-for-arrange", api.stop, 2);
                } else {
                  setStep(index);
                }
              }} disabled={index > step || busy === "stop-for-arrange"}>
                <span>{index < step ? <Check size={15} /> : String(index + 1).padStart(2, "0")}</span>{label}
              </button>
            ))}
          </nav>
          <div className="safety-note"><ShieldCheck size={18} /><div><strong>Fail-open by design</strong><span>If routing is uncertain, input stays on this computer.</span></div></div>
        </aside>

        <section className="panel">
          {error && <div className="error-banner"><CircleAlert size={18} />{error}</div>}
          {step === 0 && <LocalStep snapshot={snapshot} name={name} setName={setName} address={address} setAddress={setAddress} busy={busy} onContinue={() => perform("identity", () => api.createIdentity(name, address), 1)} />}
          {step === 1 && <PairStep snapshot={snapshot} bundle={bundle} setBundle={setBundle} copied={copied} onCopy={async () => { await navigator.clipboard.writeText(snapshot.local?.publicBundle ?? ""); setCopied(true); window.setTimeout(() => setCopied(false), 1800); }} busy={busy} onImport={() => perform("pair", () => api.importPeer(bundle), 2)} onRequest={(peerId) => perform("pair-request", () => api.requestNearbyPairing(peerId))} onAccept={(requestId) => perform("pair-accept", () => api.acceptNearbyPairing(requestId))} onConfirm={(requestId) => perform("pair-confirm", () => api.confirmNearbyPairing(requestId), 2)} onDecline={(requestId) => perform("pair-decline", () => api.declineNearbyPairing(requestId))} onForget={() => perform("forget-pair", api.forgetPairedComputer)} />}
          {step === 2 && <ArrangeStep snapshot={snapshot} busy={busy} onContinue={(nextPlacement, layout) => perform("arrange", async () => {
            if (snapshot.runtime === "running") await api.stop();
            return api.finalize(nextPlacement, layout);
          }, 3)} />}
          {step === 3 && <ReadyStep snapshot={snapshot} busy={busy} onValidate={() => perform("validate", api.validate)} onStart={() => perform("start", api.start)} onStop={() => perform("stop", api.stop)} onReplace={() => perform("forget-pair", async () => { if (snapshot.runtime === "running") await api.stop(); return api.forgetPairedComputer(); }, 1)} onRepair={() => perform("repair-lan", async () => { const restart = snapshot.runtime === "running"; if (restart) await api.stop(); const repaired = await api.repairLanBinding(); return restart ? api.start() : repaired; })} />}
        </section>
      </section>
      <footer><span>ALPHA · TWO HOSTS · LOCAL NETWORK ONLY</span><span className="escape"><KeyRound size={13} /> Emergency: Ctrl + Alt + Shift + Backspace</span></footer>
    </main>
  );
}

function SectionHeading({ number, kicker, title, copy }: { number: string; kicker: string; title: string; copy: string }) {
  return <div className="section-heading"><span className="section-number">{number}</span><div><div className="eyebrow">{kicker}</div><h2>{title}</h2><p>{copy}</p></div></div>;
}

function LocalStep({ snapshot, name, setName, address, setAddress, busy, onContinue }: { snapshot: SetupSnapshot; name: string; setName: (v: string) => void; address: string; setAddress: (v: string) => void; busy: string | null; onContinue: () => void }) {
  return <div className="step-content enter">
    <SectionHeading number="01" kicker="IDENTIFY" title="Start with this computer." copy="We’ll create a private identity and discover displays. The private key never leaves this machine." />
    <div className="machine-card local-card">
      <div className="machine-icon"><Laptop /></div><div><span className="card-label">Detected platform</span><strong>{snapshot.platform === "macos" ? "macOS" : "Windows 11"}</strong><small>{snapshot.displays.length} display{snapshot.displays.length === 1 ? "" : "s"} found</small></div><span className="signal"><Radio size={14} /> Native</span>
    </div>
    <div className="form-grid">
      <label><span>Computer name</span><input value={name} maxLength={64} onChange={(e) => setName(e.target.value)} placeholder="Office Mac" /></label>
      <label><span>Wi-Fi address</span><select value={address} onChange={(e) => setAddress(e.target.value)}>{snapshot.addressOptions.map((ip) => <option key={ip}>{ip}</option>)}</select></label>
    </div>
    <p className="field-note">Use a DHCP reservation so this address stays stable.</p>
    <PrimaryButton busy={busy === "identity"} disabled={!name.trim() || !address} onClick={onContinue}>Create private identity</PrimaryButton>
  </div>;
}

function PairStep({ snapshot, bundle, setBundle, copied, onCopy, busy, onImport, onRequest, onAccept, onConfirm, onDecline, onForget }: { snapshot: SetupSnapshot; bundle: string; setBundle: (v: string) => void; copied: boolean; onCopy: () => void; busy: string | null; onImport: () => void; onRequest: (peerId: string) => void; onAccept: (requestId: string) => void; onConfirm: (requestId: string) => void; onDecline: (requestId: string) => void; onForget: () => void }) {
  const [confirmForget, setConfirmForget] = useState(false);
  const replacing = !!snapshot.peer;
  return <div className="step-content enter">
    <SectionHeading number="02" kicker="MUTUAL TRUST" title={replacing ? "A computer is already trusted." : "Pair with one request."} copy={replacing ? "Remove the old peer trust before starting a new mutual pairing. This computer’s private identity will stay intact." : "Choose the nearby computer. The other person must accept, then both screens show the same verification code before trust is saved."} />
    {snapshot.peer && <section className="existing-pair">
      <span className="existing-pair-icon"><ShieldCheck size={19}/></span>
      <div><small>CURRENTLY PAIRED</small><strong>{snapshot.peer.displayName}</strong><span>{snapshot.peer.platform === "macos" ? "macOS" : "Windows"} · certificate pinned</span></div>
      {!confirmForget ? <button onClick={() => setConfirmForget(true)}><Unplug size={14}/>Replace pairing</button> : <div className="replace-confirm"><span>This stops routing and forgets only the old peer.</span><button className="cancel-replace" onClick={() => setConfirmForget(false)}>Keep it</button><button className="confirm-replace" disabled={!!busy} onClick={onForget}>{busy === "forget-pair" ? <LoaderCircle className="spin" size={14}/> : <Unplug size={14}/>}Forget peer</button></div>}
    </section>}
    <NearbyPanel snapshot={snapshot} busy={busy} onRequest={replacing ? undefined : onRequest} onAccept={replacing ? undefined : onAccept} onConfirm={replacing ? undefined : onConfirm} onDecline={replacing ? undefined : onDecline}/>
    {!replacing && <details className="manual-pairing">
      <summary>Can’t see the other computer? Use a public link card</summary>
      <div className="bundle-card">
        <div><span className="card-label">This computer’s public card</span><strong>{snapshot.local?.displayName}</strong><small>Certificate + address + display inventory</small></div>
        <button className="copy-button" onClick={onCopy}>{copied ? <Check size={17} /> : <Copy size={17} />}{copied ? "Copied" : "Copy card"}</button>
      </div>
      <div className="link-divider"><span /><Link2 size={18}/><span /></div>
      <label className="bundle-input"><span>Other computer’s public card</span><textarea value={bundle} onChange={(e) => setBundle(e.target.value)} placeholder="Paste the pairing card from the other machine…" /></label>
      <PrimaryButton busy={busy === "pair"} disabled={bundle.trim().length < 16} onClick={onImport}>Verify and pair</PrimaryButton>
    </details>}
  </div>;
}

type DisplayOwner = "local" | "peer";
type MappedDisplay = DisplayInfo & { owner: DisplayOwner; hostName: string; number: number };

const MAP_PADDING = 28;

function mappedDisplays(snapshot: SetupSnapshot): MappedDisplay[] {
  const localName = snapshot.local?.displayName ?? "This computer";
  const peerName = snapshot.peer?.displayName ?? "Paired computer";
  return [
    ...snapshot.displays.map((display, index) => ({ ...display, owner: "local" as const, hostName: localName, number: index + 1 })),
    ...(snapshot.peer?.displays ?? []).map((display, index) => ({ ...display, owner: "peer" as const, hostName: peerName, number: snapshot.displays.length + index + 1 })),
  ];
}

function defaultDisplayLayout(snapshot: SetupSnapshot, displays: MappedDisplay[]): DisplayPlacement[] {
  const ids = new Set(displays.map((display) => display.id));
  if (snapshot.displayLayout.length === displays.length && snapshot.displayLayout.every((item) => ids.has(item.displayId))) {
    const minimumX = Math.min(...snapshot.displayLayout.map((item) => item.x));
    const minimumY = Math.min(...snapshot.displayLayout.map((item) => item.y));
    return snapshot.displayLayout.map((item) => ({ ...item, x: item.x - minimumX, y: item.y - minimumY }));
  }
  const ordered = (owner: DisplayOwner) => displays
    .filter((display) => display.owner === owner)
    .sort((left, right) => (left.nativeBounds?.x ?? Number(!left.primary)) - (right.nativeBounds?.x ?? Number(!right.primary)) || (left.nativeBounds?.y ?? 0) - (right.nativeBounds?.y ?? 0));
  const groups = snapshot.placement === "local_left" ? [ordered("local"), ordered("peer")] : [ordered("peer"), ordered("local")];
  const layout: DisplayPlacement[] = [];
  let x = 0;
  for (const group of groups) {
    for (const display of group) {
      layout.push({ displayId: display.id, x, y: 0 });
      x += display.width;
    }
  }
  return layout;
}

function displayTouch(
  first: DisplayPlacement,
  firstDisplay: MappedDisplay,
  second: DisplayPlacement,
  secondDisplay: MappedDisplay,
) {
  const epsilon = .01;
  const verticalOverlap = Math.min(first.y + firstDisplay.height, second.y + secondDisplay.height) - Math.max(first.y, second.y);
  const horizontalOverlap = Math.min(first.x + firstDisplay.width, second.x + secondDisplay.width) - Math.max(first.x, second.x);
  return (verticalOverlap > 1 && (Math.abs(first.x + firstDisplay.width - second.x) < epsilon || Math.abs(second.x + secondDisplay.width - first.x) < epsilon))
    || (horizontalOverlap > 1 && (Math.abs(first.y + firstDisplay.height - second.y) < epsilon || Math.abs(second.y + secondDisplay.height - first.y) < epsilon));
}

function hasCrossHostEdge(layout: DisplayPlacement[], displays: MappedDisplay[]) {
  const byId = new Map(displays.map((display) => [display.id, display]));
  return layout.some((first, index) => layout.slice(index + 1).some((second) => {
    const firstDisplay = byId.get(first.displayId);
    const secondDisplay = byId.get(second.displayId);
    return !!firstDisplay && !!secondDisplay && firstDisplay.owner !== secondDisplay.owner
      && displayTouch(first, firstDisplay, second, secondDisplay);
  }));
}

function hasDisplayOverlap(layout: DisplayPlacement[], displays: MappedDisplay[]) {
  const byId = new Map(displays.map((display) => [display.id, display]));
  return layout.some((first, index) => layout.slice(index + 1).some((second) => {
    const firstDisplay = byId.get(first.displayId);
    const secondDisplay = byId.get(second.displayId);
    if (!firstDisplay || !secondDisplay) return false;
    const horizontalOverlap = Math.min(first.x + firstDisplay.width, second.x + secondDisplay.width) - Math.max(first.x, second.x);
    const verticalOverlap = Math.min(first.y + firstDisplay.height, second.y + secondDisplay.height) - Math.max(first.y, second.y);
    return horizontalOverlap > .01 && verticalOverlap > .01;
  }));
}

function snapDisplay(layout: DisplayPlacement[], movingId: string, displays: MappedDisplay[], scale: number) {
  const byId = new Map(displays.map((display) => [display.id, display]));
  const moving = layout.find((item) => item.displayId === movingId);
  const movingDisplay = byId.get(movingId);
  if (!moving || !movingDisplay) return layout;
  const threshold = 22 / scale;
  let best = { distance: threshold, x: moving.x, y: moving.y };
  for (const other of layout) {
    if (other.displayId === movingId) continue;
    const otherDisplay = byId.get(other.displayId);
    if (!otherDisplay) continue;
    const horizontal = [
      { x: other.x + otherDisplay.width, distance: Math.abs(moving.x - (other.x + otherDisplay.width)) },
      { x: other.x - movingDisplay.width, distance: Math.abs(moving.x + movingDisplay.width - other.x) },
    ];
    for (const candidate of horizontal) {
      const overlap = Math.min(moving.y + movingDisplay.height, other.y + otherDisplay.height) - Math.max(moving.y, other.y);
      if (overlap > 1 && candidate.distance < best.distance) best = { ...best, x: candidate.x, distance: candidate.distance };
    }
    const vertical = [
      { y: other.y + otherDisplay.height, distance: Math.abs(moving.y - (other.y + otherDisplay.height)) },
      { y: other.y - movingDisplay.height, distance: Math.abs(moving.y + movingDisplay.height - other.y) },
    ];
    for (const candidate of vertical) {
      const overlap = Math.min(moving.x + movingDisplay.width, other.x + otherDisplay.width) - Math.max(moving.x, other.x);
      if (overlap > 1 && candidate.distance < best.distance) best = { ...best, y: candidate.y, distance: candidate.distance };
    }
  }
  const next = layout.map((item) => item.displayId === movingId
    ? { ...item, x: Math.max(0, Math.round(best.x * 1000) / 1000), y: Math.max(0, Math.round(best.y * 1000) / 1000) }
    : item);
  const minimumX = Math.min(...next.map((item) => item.x));
  const minimumY = Math.min(...next.map((item) => item.y));
  return next.map((item) => ({ ...item, x: item.x - minimumX, y: item.y - minimumY }));
}

function ArrangeStep({ snapshot, busy, onContinue }: { snapshot: SetupSnapshot; busy: string | null; onContinue: (placement: Placement, layout: DisplayPlacement[]) => void }) {
  const displays = useMemo(() => mappedDisplays(snapshot), [snapshot]);
  const [layout, setLayout] = useState(() => defaultDisplayLayout(snapshot, displays));
  const followsPeer = snapshot.workspaceRole === "follower";
  const leadsPeer = snapshot.workspaceRole === "leader";
  const [drag, setDrag] = useState<{ displayId: string; pointerId: number; clientX: number; clientY: number; x: number; y: number } | null>(null);
  useEffect(() => {
    if (followsPeer) setLayout(defaultDisplayLayout(snapshot, displays));
  }, [displays, followsPeer, snapshot]);
  const scale = useMemo(() => {
    const totalWidth = displays.reduce((sum, display) => sum + display.width, 0);
    const tallest = Math.max(...displays.map((display) => display.height), 1);
    return Math.min(.16, 690 / Math.max(totalWidth, 1), 285 / tallest);
  }, [displays]);
  const byId = useMemo(() => new Map(displays.map((display) => [display.id, display])), [displays]);
  const maxRight = Math.max(...layout.map((item) => item.x + (byId.get(item.displayId)?.width ?? 0)), 1);
  const maxBottom = Math.max(...layout.map((item) => item.y + (byId.get(item.displayId)?.height ?? 0)), 1);
  const canvasWidth = Math.max(720, maxRight * scale + MAP_PADDING * 2);
  const canvasHeight = Math.max(330, maxBottom * scale + MAP_PADDING * 2);
  const linked = hasCrossHostEdge(layout, displays);
  const overlapping = hasDisplayOverlap(layout, displays);
  const valid = linked && !overlapping;
  const localCenter = layout.filter((item) => byId.get(item.displayId)?.owner === "local").reduce((sum, item) => sum + item.x + (byId.get(item.displayId)?.width ?? 0) / 2, 0) / Math.max(snapshot.displays.length, 1);
  const peerCenter = layout.filter((item) => byId.get(item.displayId)?.owner === "peer").reduce((sum, item) => sum + item.x + (byId.get(item.displayId)?.width ?? 0) / 2, 0) / Math.max(snapshot.peer?.displays.length ?? 0, 1);
  const placement: Placement = localCenter <= peerCenter ? "local_left" : "local_right";

  return <div className="step-content enter arrange-content">
    <SectionHeading number="03" kicker="WORKSPACE MAP" title="Build the desk you actually have." copy="Drag every screen into its physical position. Touch one Mac edge to one Windows edge to choose where the pointer crosses." />
    <div className="display-map-toolbar">
      <div className="map-legend"><span className="local"><i/>This computer</span><span className="peer"><i/>Paired computer</span><em className={`map-role ${snapshot.workspaceRole}`}>{followsPeer ? `${snapshot.peer?.displayName ?? "Peer"} leads` : snapshot.workspaceRole === "leader" ? "This computer leads" : "Local map"}</em></div>
      <button disabled={followsPeer} onClick={() => setLayout(defaultDisplayLayout(snapshot, displays))}><RotateCcw size={13}/>Reset arrangement</button>
    </div>
    <div className="display-map-viewport">
      <div className="display-map-grid" style={{ width: canvasWidth, height: canvasHeight }}>
        <div className="map-instruction"><Move size={13}/>DRAG TO POSITION · EDGES SNAP TOGETHER</div>
        {layout.map((position) => {
          const display = byId.get(position.displayId);
          if (!display) return null;
          return <button
            key={display.id}
            className={`mapped-display ${display.owner} ${display.primary ? "primary" : ""} ${drag?.displayId === display.id ? "dragging" : ""}`}
            style={{ left: MAP_PADDING + position.x * scale, top: MAP_PADDING + position.y * scale, width: display.width * scale, height: display.height * scale }}
            onPointerDown={(event) => {
              if (followsPeer) return;
              event.currentTarget.setPointerCapture(event.pointerId);
              setDrag({ displayId: display.id, pointerId: event.pointerId, clientX: event.clientX, clientY: event.clientY, x: position.x, y: position.y });
            }}
            onPointerMove={(event) => {
              if (!drag || drag.displayId !== display.id || drag.pointerId !== event.pointerId) return;
              setLayout((current) => current.map((item) => item.displayId === display.id ? {
                ...item,
                x: Math.max(0, drag.x + (event.clientX - drag.clientX) / scale),
                y: Math.max(0, drag.y + (event.clientY - drag.clientY) / scale),
              } : item));
            }}
            onPointerUp={(event) => {
              if (!drag || drag.pointerId !== event.pointerId) return;
              setLayout((current) => snapDisplay(current, display.id, displays, scale));
              setDrag(null);
            }}
          >
            <span className="display-number">{display.number}</span>
            <span className="display-identity"><small>{display.owner === "local" ? "THIS COMPUTER" : "PAIRED COMPUTER"}</small><strong>{display.hostName}</strong></span>
            <span className="display-spec">{Math.round(display.width)} × {Math.round(display.height)}{display.primary ? " · MAIN" : ""}</span>
          </button>;
        })}
      </div>
    </div>
    <div className={`map-validation ${valid && !followsPeer ? "ready" : "needs-edge"}`}>
      <span><i/>{followsPeer ? "FOLLOWING THE PAIRING LEADER" : overlapping ? "SCREENS CANNOT OVERLAP" : linked ? "HANDOFF EDGE READY" : "CONNECT THE TWO COMPUTERS"}</span>
      <p>{followsPeer ? `Save the arrangement on ${snapshot.peer?.displayName ?? "the paired computer"}. Its signed map will appear here automatically.` : overlapping ? "Separate the overlapping screens, then join one Mac edge to one Windows edge." : linked && leadsPeer ? "The signed map will be synchronized to the paired computer." : linked ? "This older or manual pairing cannot sync maps; save the same arrangement on both computers." : "Drag a screen from each computer together until their edges snap."}</p>
    </div>
    <PrimaryButton busy={busy === "arrange"} disabled={!valid || followsPeer} onClick={() => onContinue(placement, layout)}>{followsPeer ? "Waiting for leader map" : leadsPeer ? "Save and sync display map" : "Save display map"}</PrimaryButton>
  </div>;
}

function ReadyStep({ snapshot, busy, onValidate, onStart, onStop, onReplace, onRepair }: { snapshot: SetupSnapshot; busy: string | null; onValidate: () => void; onStart: () => void; onStop: () => void; onReplace: () => void; onRepair: () => void }) {
  const running = snapshot.runtime === "running";
  const workspaceSynchronized = snapshot.workspaceSync === "confirmed" || snapshot.workspaceSync === "manual";
  const runtimeFault = snapshot.runtime === "faulted" ? runtimeFaultMessage(snapshot.runtimeFault) : null;
  const [confirmReplace, setConfirmReplace] = useState(false);
  return <div className="step-content enter">
    <SectionHeading number="04" kicker="ACTIVATE" title={running ? "Your desk is linked." : "One last safety check."} copy={running ? "Pointer and keyboard routing are active. Closing this console does not terminate the runtime." : "Validate identities, certificates, network addresses, topology, and file protections before capture can start."} />
    {running && <InputAuthorityPanel snapshot={snapshot}/>}
    <NearbyPanel snapshot={snapshot}/>
    <div className="checklist">
      <CheckRow label="Local identity" detail="Private credential is protected" good={!!snapshot.local}/>
      <CheckRow label="Selected peer" detail="Public certificate is pinned" good={!!snapshot.peer}/>
      <CheckRow label="Display topology" detail="Bidirectional edge link configured" good={snapshot.configured}/>
      <CheckRow
        label="Display map sync"
        detail={snapshot.workspaceSync === "confirmed" ? "Both computers confirmed the same map" : snapshot.workspaceSync === "manual" ? "Manual pairing uses this computer's map" : "Waiting for the paired computer to confirm this revision"}
        good={workspaceSynchronized}
      />
      <CheckRow label="Runtime validation" detail={snapshot.validated ? "All safety checks passed" : "Not checked yet"} good={snapshot.validated}/>
      {snapshot.developerDiagnostics && (
        <CheckRow
          label="LAN binding"
          detail={snapshot.developerDiagnostics.lanBinding === "healthy" ? "Listener and observed peer use the active LAN" : "Configured addresses do not match the active LAN"}
          good={snapshot.developerDiagnostics.lanBinding === "healthy"}
        />
      )}
    </div>
    {import.meta.env.DEV && snapshot.developerDiagnostics && (
      <DeveloperDiagnosticsPanel diagnostics={snapshot.developerDiagnostics} busy={busy} onRepair={onRepair}/>
    )}
    {snapshot.peer && <section className="ready-pair-management">
      <div><span>Paired with</span><strong>{snapshot.peer.displayName}</strong><small>Replace this peer if the other computer does not show the same pairing.</small></div>
      {!confirmReplace ? <button onClick={() => setConfirmReplace(true)}><Unplug size={14}/>Replace paired computer</button> : <div className="ready-replace-confirm"><span>{running ? "Routing will stop first. " : ""}The local private identity will be preserved.</span><button onClick={() => setConfirmReplace(false)}>Keep pairing</button><button className="danger" disabled={!!busy} onClick={onReplace}>{busy === "forget-pair" ? <LoaderCircle className="spin" size={14}/> : <Unplug size={14}/>}Replace now</button></div>}
    </section>}
    {runtimeFault && <div className="error-banner"><CircleAlert size={18}/><div><strong>{runtimeFault.title}</strong><br/><span>{runtimeFault.detail}</span></div></div>}
    {snapshot.setupDirectory && <div className="path-note"><span>Setup stored securely</span><code>{snapshot.setupDirectory}</code></div>}
    {runtimeFault && snapshot.runtimeLogPath && <div className="path-note"><span>Private diagnostic log</span><code>{snapshot.runtimeLogPath}</code></div>}
    {running ? <button className="stop-button" disabled={!!busy} onClick={onStop}><Square size={16} fill="currentColor"/> Stop routing safely</button> : !snapshot.validated ? <PrimaryButton busy={busy === "validate"} onClick={onValidate}>Validate this setup</PrimaryButton> : <PrimaryButton busy={busy === "start"} disabled={!workspaceSynchronized} onClick={onStart}><Play size={17} fill="currentColor"/> {workspaceSynchronized ? "Start Software KVM" : "Waiting for display-map sync"}</PrimaryButton>}
  </div>;
}

function InputAuthorityPanel({ snapshot }: { snapshot: SetupSnapshot }) {
  const { owner, linkReady, sessionActive } = snapshot.inputAuthority;
  const localName = snapshot.local?.displayName ?? "This computer";
  const peerName = snapshot.peer?.displayName ?? "Paired computer";
  const activeName = owner === "peer" ? peerName : owner === "local" ? localName : null;
  const headline = activeName ? `${activeName} is receiving input` : owner === "transitioning" ? "Switching input destination…" : "Confirming input destination…";
  const detail = owner === "peer"
    ? `Keyboard, trackpad, and mouse input from either computer is locked to ${peerName}. The cursor on ${localName} is parked and hidden.`
    : owner === "local"
      ? linkReady
        ? `Keyboard, trackpad, and mouse input from either computer is locked to ${localName}. The cursor on ${peerName} is parked and hidden.`
        : `Input remains safely on ${localName} until the authenticated workspace is ready.`
      : owner === "transitioning"
        ? "New input is briefly held while both computers commit the same destination."
        : "The runtime has not published a trusted input destination yet. Input is not routed remotely.";
  const connection = linkReady ? "LINKED" : sessionActive ? "PREPARING" : "LOCAL SAFE";
  const localFirst = snapshot.placement === "local_left";
  const machines = [
    { key: "local", name: localName, platform: snapshot.platform, active: owner === "local" },
    { key: "peer", name: peerName, platform: snapshot.peer?.platform ?? "windows", active: owner === "peer" },
  ];
  if (!localFirst) machines.reverse();

  return <section className={`input-authority ${owner}`} aria-live="polite" aria-label="Current input destination">
    <div className="input-authority-heading">
      <span><MousePointer2 size={14}/>Active input destination</span>
      <em><i/>{connection}</em>
    </div>
    <div className="input-authority-summary">
      <div className="authority-pulse"><MousePointer2 size={20}/></div>
      <div><small>{activeName ? "INPUT IS ON" : "AUTHORITY STATUS"}</small><strong>{headline}</strong><p>{detail}</p></div>
    </div>
    <div className="authority-machines">
      {machines.map((machine, index) => <div className="authority-machine-slot" key={machine.key}>
        <div className={`authority-machine ${machine.active ? "active" : "parked"}`}>
          {machine.platform === "macos" ? <Laptop size={18}/> : <Monitor size={18}/>}
          <span><small>{machine.key === "local" ? "THIS COMPUTER" : "PAIRED COMPUTER"}</small><strong>{machine.name}</strong></span>
          <em>{machine.active ? "RECEIVING" : owner === "transitioning" || owner === "unavailable" ? "WAITING" : "CURSOR PARKED"}</em>
        </div>
        {index === 0 && <div className={`authority-bridge ${owner === "transitioning" ? "switching" : ""}`}><span/><ArrowLeftRight size={15}/><span/></div>}
      </div>)}
    </div>
    <div className="authority-foot"><ShieldCheck size={13}/>Exactly one destination can receive routed input at a time. Move through the configured screen edge to switch.</div>
  </section>;
}

function DeveloperDiagnosticsPanel({ diagnostics, busy, onRepair }: { diagnostics: NonNullable<SetupSnapshot["developerDiagnostics"]>; busy: string | null; onRepair: () => void }) {
  const mismatch = diagnostics.lanBinding === "mismatch";
  return <details className={`developer-diagnostics ${mismatch ? "has-mismatch" : ""}`} open={mismatch}>
    <summary><span><i/>Developer diagnostics</span><em>{mismatch ? "LAN MISMATCH" : diagnostics.lanBinding.replaceAll("_", " ")}</em></summary>
    <div className="diagnostic-grid">
      <DiagnosticValue label="Configured listener" value={diagnostics.configuredListener}/>
      <DiagnosticValue label="Routed listener" value={diagnostics.routedListener}/>
      <DiagnosticValue label="Configured peer" value={diagnostics.configuredPeer}/>
      <DiagnosticValue label="Observed peer" value={diagnostics.observedPeer}/>
    </div>
    {mismatch && <div className="diagnostic-repair"><div><strong>The runtime is bound to the wrong network interface.</strong><span>Repair rewrites the listener and peer addresses using the active LAN route, revalidates, and restarts if necessary.</span></div><button disabled={!!busy} onClick={onRepair}>{busy === "repair-lan" ? <LoaderCircle className="spin" size={14}/> : <Radio size={14}/>}Repair LAN binding</button></div>}
    <div className="event-console" aria-label="Recent redacted runtime events">
      <div><span>Recent runtime events</span><em>REDACTED · LIVE</em></div>
      {diagnostics.recentEvents.length === 0 ? <p>No detailed events yet. Restart the runtime from this development build.</p> : <ol>{diagnostics.recentEvents.map((event, index) => <li key={`${index}-${event}`}>{event}</li>)}</ol>}
    </div>
  </details>;
}

function DiagnosticValue({ label, value }: { label: string; value: string | null }) {
  return <div><span>{label}</span><code>{value ?? "Waiting…"}</code></div>;
}

function NearbyPanel({ snapshot, busy = null, onRequest, onAccept, onConfirm, onDecline }: { snapshot: SetupSnapshot; busy?: string | null; onRequest?: (peerId: string) => void; onAccept?: (requestId: string) => void; onConfirm?: (requestId: string) => void; onDecline?: (requestId: string) => void }) {
  const pairing = snapshot.nearbyPairing;
  return <section className="nearby-panel" aria-label="Nearby Software KVM computers">
    <div className="nearby-heading">
      <div><span className="radar-mark"><Radio size={15}/></span><div><strong>LAN radar</strong><small>Discovery is untrusted · both computers must approve</small></div></div>
      <span className={snapshot.discoveryAvailable ? "scanning" : "unavailable"}>{snapshot.discoveryAvailable ? "SCANNING" : "UNAVAILABLE"}</span>
    </div>
    {pairing && <div className={`pairing-request ${pairing.status}`}>
      <span className="pairing-glyph"><Handshake size={20}/></span>
      <div className="pairing-copy">
        <small>{pairing.status === "incoming_request" ? "PAIR REQUEST RECEIVED" : pairing.status === "verify_code" ? "VERIFY BOTH SCREENS" : "PAIRING IN PROGRESS"}</small>
        <strong>{pairing.name}</strong>
        <span>{pairing.status === "incoming_request" && "This computer has not trusted the request yet."}{pairing.status === "waiting_for_acceptance" && "Waiting for the other computer to accept."}{pairing.status === "verify_code" && "Make sure this code matches the other screen, then confirm."}{pairing.status === "waiting_for_confirmation" && "Keep this window open while the other computer confirms."}</span>
      </div>
      {pairing.verificationCode && <code className="verification-code">{pairing.verificationCode}</code>}
      <div className="pairing-actions">
        {pairing.status === "incoming_request" && onAccept && <button className="accept-pair" disabled={!!busy} onClick={() => onAccept(pairing.requestId)}>{busy === "pair-accept" ? <LoaderCircle className="spin" size={14}/> : <Check size={14}/>}Accept</button>}
        {pairing.status === "verify_code" && onConfirm && <button className="accept-pair" disabled={!!busy} onClick={() => onConfirm(pairing.requestId)}>{busy === "pair-confirm" ? <LoaderCircle className="spin" size={14}/> : <ShieldCheck size={14}/>}Codes match</button>}
        {onDecline && <button className="decline-pair" disabled={!!busy} aria-label="Cancel pairing" onClick={() => onDecline(pairing.requestId)}><X size={14}/></button>}
      </div>
    </div>}
    {snapshot.nearbyMachines.length === 0 ? <div className="nearby-empty"><i/><span>No other Software KVM consoles detected yet.</span></div> : <div className="nearby-list">
      {snapshot.nearbyMachines.map((machine) => <div className="nearby-machine" key={`${machine.address}-${machine.name}`}>
        <span className={`presence-orbit ${machine.presence}`}><i/></span>
        <div><strong>{machine.name}</strong><small>{machine.platform === "macos" ? "macOS" : "Windows"} · {machine.address}</small></div>
        <div className="nearby-badges">{machine.paired && <span>PAIRED</span>}<em>{machine.presence === "runtime_active" ? "RUNTIME ACTIVE" : "SETTING UP"}</em>{onRequest && !machine.paired && !pairing && <button className="request-pair" disabled={!!busy} onClick={() => onRequest(machine.peerId)}><Handshake size={13}/>Pair</button>}</div>
      </div>)}
    </div>}
  </section>;
}

function runtimeFaultMessage(fault: SetupSnapshot["runtimeFault"]) {
  switch (fault) {
    case "native_capture": return { title: "Native input capture stopped.", detail: "Check Accessibility and Input Monitoring permissions, then try again." };
    case "authenticated_transport": return { title: "The authenticated peer link stopped.", detail: "Keep both computers on the same Wi-Fi and start Software KVM on both." };
    case "runtime_task": return { title: "A runtime service stopped unexpectedly.", detail: "The diagnostic log contains the coarse failure category." };
    default: return { title: "Software KVM stopped unexpectedly.", detail: "Open the private diagnostic log shown below for the failure category." };
  }
}

function CheckRow({ label, detail, good }: { label: string; detail: string; good: boolean }) { return <div className="check-row"><span className={good ? "good" : "pending"}>{good ? <Check size={16}/> : "·"}</span><div><strong>{label}</strong><small>{detail}</small></div><em>{good ? "READY" : "PENDING"}</em></div>; }
function PrimaryButton({ children, busy, disabled = false, onClick }: { children: React.ReactNode; busy: boolean; disabled?: boolean; onClick: () => void }) { return <button className="primary-button" disabled={disabled || busy} onClick={onClick}>{busy ? <LoaderCircle className="spin" size={18}/> : children}<ChevronRight size={18}/></button>; }
function Loading({ error }: { error: string | null }) { return <main className="loading"><div className="brand-mark"><ArrowLeftRight /></div><h1>Link Console</h1>{error ? <p>{error}</p> : <LoaderCircle className="spin" />}</main>; }

export default App;
