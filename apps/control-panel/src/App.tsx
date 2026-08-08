import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeftRight, Check, ChevronRight, CircleAlert, Copy, KeyRound,
  Laptop, Link2, LoaderCircle, Monitor, Play, Radio, ShieldCheck, Square,
} from "lucide-react";
import { api } from "./bridge";
import type { Placement, SetupSnapshot } from "./types";

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
  const [placement, setPlacement] = useState<Placement>("local_left");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.status().then((state) => {
      setSnapshot(state);
      setName(state.local?.displayName ?? state.suggestedName);
      setAddress(hostFromSocketAddress(state.local?.address) || state.addressOptions[0] || "");
      setPlacement(state.placement);
      if (state.configured) setStep(3);
      else if (state.peer) setStep(2);
      else if (state.local) setStep(1);
    }).catch(() => setError("The native setup service did not respond."));
  }, []);

  useEffect(() => {
    if (step !== 3) return;
    const timer = window.setInterval(() => {
      if (!busy) api.status().then(setSnapshot).catch(() => undefined);
    }, 1200);
    return () => window.clearInterval(timer);
  }, [step, busy]);

  const perform = async (label: string, operation: () => Promise<SetupSnapshot>, next?: number) => {
    setBusy(label); setError(null);
    try {
      const state = await operation();
      setSnapshot(state);
      if (next !== undefined) setStep(next);
    } catch {
      setError("That step could not be completed safely. Nothing was changed.");
    } finally { setBusy(null); }
  };

  const readiness = useMemo(() => {
    if (!snapshot?.local) return "Identity needed";
    if (!snapshot.peer) return "Waiting for peer";
    if (!snapshot.validated) return "Needs validation";
    if (snapshot.runtime === "running") return "Connected mode";
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
              <button key={label} className={index === step ? "active" : index < step ? "done" : ""} onClick={() => index <= step && setStep(index)} disabled={index > step}>
                <span>{index < step ? <Check size={15} /> : String(index + 1).padStart(2, "0")}</span>{label}
              </button>
            ))}
          </nav>
          <div className="safety-note"><ShieldCheck size={18} /><div><strong>Fail-open by design</strong><span>If routing is uncertain, input stays on this computer.</span></div></div>
        </aside>

        <section className="panel">
          {error && <div className="error-banner"><CircleAlert size={18} />{error}</div>}
          {step === 0 && <LocalStep snapshot={snapshot} name={name} setName={setName} address={address} setAddress={setAddress} busy={busy} onContinue={() => perform("identity", () => api.createIdentity(name, address), 1)} />}
          {step === 1 && <PairStep snapshot={snapshot} bundle={bundle} setBundle={setBundle} copied={copied} onCopy={async () => { await navigator.clipboard.writeText(snapshot.local?.publicBundle ?? ""); setCopied(true); window.setTimeout(() => setCopied(false), 1800); }} busy={busy} onImport={() => perform("pair", () => api.importPeer(bundle), 2)} />}
          {step === 2 && <ArrangeStep snapshot={snapshot} placement={placement} setPlacement={setPlacement} busy={busy} onContinue={() => perform("arrange", () => api.finalize(placement), 3)} />}
          {step === 3 && <ReadyStep snapshot={snapshot} busy={busy} onValidate={() => perform("validate", api.validate)} onStart={() => perform("start", api.start)} onStop={() => perform("stop", api.stop)} />}
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

function PairStep({ snapshot, bundle, setBundle, copied, onCopy, busy, onImport }: { snapshot: SetupSnapshot; bundle: string; setBundle: (v: string) => void; copied: boolean; onCopy: () => void; busy: string | null; onImport: () => void }) {
  return <div className="step-content enter">
    <SectionHeading number="02" kicker="TRUST" title="Exchange public link cards." copy="Copy this computer’s card to the other machine, then paste the other machine’s card below. It contains no private key." />
    <div className="bundle-card">
      <div><span className="card-label">This computer’s public card</span><strong>{snapshot.local?.displayName}</strong><small>Certificate + address + display inventory</small></div>
      <button className="copy-button" onClick={onCopy}>{copied ? <Check size={17} /> : <Copy size={17} />}{copied ? "Copied" : "Copy card"}</button>
    </div>
    <div className="link-divider"><span /><Link2 size={18}/><span /></div>
    <label className="bundle-input"><span>Other computer’s public card</span><textarea value={bundle} onChange={(e) => setBundle(e.target.value)} placeholder="Paste the pairing card from the other machine…" /></label>
    <PrimaryButton busy={busy === "pair"} disabled={bundle.trim().length < 16} onClick={onImport}>Verify and pair</PrimaryButton>
  </div>;
}

function ArrangeStep({ snapshot, placement, setPlacement, busy, onContinue }: { snapshot: SetupSnapshot; placement: Placement; setPlacement: (v: Placement) => void; busy: string | null; onContinue: () => void }) {
  const localFirst = placement === "local_left";
  return <div className="step-content enter">
    <SectionHeading number="03" kicker="WORKSPACE" title="Arrange the desk you actually have." copy="Choose which side this computer occupies. Moving through the touching edge hands off pointer and keyboard together." />
    <div className="desk-stage">
      <div className="desk-grid" />
      <div className={`display-row ${localFirst ? "" : "reverse"}`}>
        <DisplayTile label="THIS COMPUTER" name={snapshot.local?.displayName ?? "Local"} display={snapshot.displays[0]} local />
        <div className="handoff"><ChevronRight /></div>
        <DisplayTile label="PAIRED COMPUTER" name={snapshot.peer?.displayName ?? "Peer"} display={snapshot.peer?.displays[0]} />
      </div>
    </div>
    <div className="segmented" role="group" aria-label="Computer position">
      <button className={placement === "local_left" ? "selected" : ""} onClick={() => setPlacement("local_left")}>This computer on left</button>
      <button className={placement === "local_right" ? "selected" : ""} onClick={() => setPlacement("local_right")}>This computer on right</button>
    </div>
    <PrimaryButton busy={busy === "arrange"} onClick={onContinue}>Write secure configuration</PrimaryButton>
  </div>;
}

function DisplayTile({ label, name, display, local = false }: { label: string; name: string; display?: { name: string; width: number; height: number }; local?: boolean }) {
  return <div className={`display-tile ${local ? "is-local" : ""}`}><div className="screen"><div className="screen-glow"/><Monitor size={24}/><span>{display?.width ?? "—"} × {display?.height ?? "—"}</span></div><div className="stand"/><small>{label}</small><strong>{name}</strong><span>{display?.name ?? "Display"}</span></div>;
}

function ReadyStep({ snapshot, busy, onValidate, onStart, onStop }: { snapshot: SetupSnapshot; busy: string | null; onValidate: () => void; onStart: () => void; onStop: () => void }) {
  const running = snapshot.runtime === "running";
  const runtimeFault = snapshot.runtime === "faulted" ? runtimeFaultMessage(snapshot.runtimeFault) : null;
  return <div className="step-content enter">
    <SectionHeading number="04" kicker="ACTIVATE" title={running ? "Your desk is linked." : "One last safety check."} copy={running ? "Pointer and keyboard routing are active. Closing this console does not terminate the runtime." : "Validate identities, certificates, network addresses, topology, and file protections before capture can start."} />
    <div className="checklist">
      <CheckRow label="Local identity" detail="Private credential is protected" good={!!snapshot.local}/>
      <CheckRow label="Selected peer" detail="Public certificate is pinned" good={!!snapshot.peer}/>
      <CheckRow label="Display topology" detail="Bidirectional edge link configured" good={snapshot.configured}/>
      <CheckRow label="Runtime validation" detail={snapshot.validated ? "All safety checks passed" : "Not checked yet"} good={snapshot.validated}/>
    </div>
    {runtimeFault && <div className="error-banner"><CircleAlert size={18}/><div><strong>{runtimeFault.title}</strong><br/><span>{runtimeFault.detail}</span></div></div>}
    {snapshot.setupDirectory && <div className="path-note"><span>Setup stored securely</span><code>{snapshot.setupDirectory}</code></div>}
    {runtimeFault && snapshot.runtimeLogPath && <div className="path-note"><span>Private diagnostic log</span><code>{snapshot.runtimeLogPath}</code></div>}
    {!snapshot.validated ? <PrimaryButton busy={busy === "validate"} onClick={onValidate}>Validate this setup</PrimaryButton> : running ? <button className="stop-button" disabled={!!busy} onClick={onStop}><Square size={16} fill="currentColor"/> Stop routing safely</button> : <PrimaryButton busy={busy === "start"} onClick={onStart}><Play size={17} fill="currentColor"/> Start Software KVM</PrimaryButton>}
  </div>;
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
