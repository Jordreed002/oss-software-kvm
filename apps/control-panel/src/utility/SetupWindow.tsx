import { ArrowLeft, ArrowRight } from "lucide-react";
import { SectionNav, type NavItem } from "./SectionNav";
import type { UtilitySnapshot } from "./model";
import { Unavailable, capabilityReason } from "./parts";

export type SetupStep = "identify" | "permissions" | "pair" | "arrange" | "test";

const STEPS: readonly (NavItem<SetupStep> & { title: string; body: string; action: string })[] = [
  {
    id: "identify",
    label: "This computer",
    hint: "1",
    title: "Name this computer",
    body: "Pick a name the other computer will show, so you can tell them apart at a glance.",
    action: "Save name",
  },
  {
    id: "permissions",
    label: "Permissions",
    hint: "2",
    title: "Allow keyboard and pointer access",
    body: "macOS asks for Accessibility and Input Monitoring. Windows may ask to allow Software KVM through the firewall on private networks.",
    action: "Check permissions",
  },
  {
    id: "pair",
    label: "Find the other computer",
    hint: "3",
    title: "Find and verify the other computer",
    body: "Nearby computers are only candidates. Both people confirm the same short code before the computers trust each other.",
    action: "Look for computers",
  },
  {
    id: "arrange",
    label: "Arrange displays",
    hint: "4",
    title: "Arrange displays",
    body: "Place the other computer’s screens beside yours. The pointer crosses where the screens touch.",
    action: "Apply arrangement",
  },
  {
    id: "test",
    label: "Test and enable",
    hint: "5",
    title: "Test, then turn sharing on",
    body: "Move the pointer across and type a few keys. Sharing starts only after both computers confirm.",
    action: "Start test",
  },
];

/** Focused onboarding window. Progress is owned by the agent, so steps can be
 *  browsed for review but no step can be completed from the preview. */
export function SetupWindow({
  snapshot,
  step,
  onStep,
}: {
  snapshot: UtilitySnapshot;
  step: SetupStep;
  onStep: (step: SetupStep) => void;
}) {
  const index = STEPS.findIndex((s) => s.id === step);
  const current = STEPS[index];
  const reason = capabilityReason(snapshot.capabilities.setup);
  return (
    <div className="u-window-body u-split">
      <SectionNav label="Setup steps" items={STEPS} selected={step} onSelect={onStep} idPrefix="u-setup" />
      <section className="u-pane" role="tabpanel" id="u-setup-panel" aria-labelledby={`u-setup-tab-${step}`} tabIndex={0}>
        <p className="u-step-count">
          Step {index + 1} of {STEPS.length}
        </p>
        <h2 className="u-pane-title">{current.title}</h2>
        <p className="u-copy">{current.body}</p>
        <div className="u-action-row">
          <button type="button" className="u-btn u-btn-primary" disabled={reason !== null} aria-describedby={reason ? "u-setup-reason" : undefined}>
            {current.action}
          </button>
          {reason ? <Unavailable id="u-setup-reason">{reason}</Unavailable> : null}
        </div>
        <div className="u-stepper">
          <button type="button" className="u-btn u-btn-quiet" disabled={index === 0} onClick={() => onStep(STEPS[index - 1].id)}>
            <ArrowLeft size={14} aria-hidden="true" />
            Previous step
          </button>
          <button type="button" className="u-btn u-btn-quiet" disabled={index === STEPS.length - 1} onClick={() => onStep(STEPS[index + 1].id)}>
            Next step
            <ArrowRight size={14} aria-hidden="true" />
          </button>
        </div>
        <p className="u-copy u-copy-muted">Browsing steps doesn’t complete them. Setup progress will come from the agent.</p>
      </section>
    </div>
  );
}
