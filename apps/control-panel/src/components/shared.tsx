import { Check, ChevronRight, LoaderCircle } from "lucide-react";

/** Small presentation primitives shared by the setup wizard steps and the
 *  display-layout editor. Extracted from App.tsx verbatim — no behavior
 *  changes. */

export function SectionHeading({ number, kicker, title, copy }: { number: string; kicker: string; title: string; copy: string }) {
  return <div className="section-heading"><span className="section-number">{number}</span><div><div className="eyebrow">{kicker}</div><h2>{title}</h2><p>{copy}</p></div></div>;
}

export function PrimaryButton({ children, busy, disabled = false, onClick }: { children: React.ReactNode; busy: boolean; disabled?: boolean; onClick: () => void }) { return <button className="primary-button" disabled={disabled || busy} onClick={onClick}>{busy ? <LoaderCircle className="spin" size={18}/> : children}<ChevronRight size={18}/></button>; }

/** One readiness row of the setup checklist. Shared by the Ready step and the
 *  live §31 daemon status card. Extracted from App.tsx verbatim. */
export function CheckRow({ label, detail, good }: { label: string; detail: string; good: boolean }) { return <div className="check-row"><span className={good ? "good" : "pending"}>{good ? <Check size={16}/> : "·"}</span><div><strong>{label}</strong><small>{detail}</small></div><em>{good ? "READY" : "PENDING"}</em></div>; }
