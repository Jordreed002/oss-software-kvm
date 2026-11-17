import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import UtilityPreview from "./UtilityPreview";

function chooseScenario(label: RegExp | string) {
  const select = screen.getByLabelText("Preview scenario") as HTMLSelectElement;
  const option = within(select).getByRole("option", { name: label }) as HTMLOptionElement;
  fireEvent.change(select, { target: { value: option.value } });
}

const widget = () => screen.getByRole("dialog", { name: "Software KVM" });

describe("UtilityPreview — truthfulness", () => {
  it("defaults to the no-agent state with every mutation disabled", () => {
    render(<UtilityPreview />);
    const w = widget();
    expect(within(w).getByRole("heading", { name: "Agent not connected" })).toBeInTheDocument();
    expect(within(w).getByText("No agent")).toBeInTheDocument();
    expect(within(w).queryByText(/preview fixture/i)).toBeNull();
    expect(w.textContent).not.toMatch(/controlling|ready to share/i);

    const pause = within(w).getByRole("button", { name: /pause sharing/i });
    expect(pause).toBeDisabled();
    expect(pause).toHaveAccessibleDescription(/no software kvm agent is connected/i);
    expect(within(w).getByRole("button", { name: "Quit" })).toBeDisabled();
  });

  it("badges fixtures as preview and does not change state when a command is attempted", () => {
    render(<UtilityPreview />);
    chooseScenario(/Controlling the other computer/);
    const w = widget();
    expect(within(w).getByText("Preview fixture")).toBeInTheDocument();
    expect(within(w).getByRole("heading", { name: "Controlling Desk PC" })).toBeInTheDocument();

    fireEvent.click(within(w).getByRole("button", { name: /pause sharing/i }));

    expect(within(w).getByRole("status")).toHaveTextContent(/not sent.*unchanged/i);
    expect(within(w).getByRole("heading", { name: "Controlling Desk PC" })).toBeInTheDocument();
    expect(within(w).queryByRole("button", { name: /resume sharing/i })).toBeNull();
  });

  it("clears a previous command outcome when the scenario changes", () => {
    render(<UtilityPreview />);
    chooseScenario(/Controlling the other computer/);
    fireEvent.click(within(widget()).getByRole("button", { name: /pause sharing/i }));
    chooseScenario(/^Preview fixture: Paused$/);
    expect(within(widget()).getByRole("status")).toBeEmptyDOMElement();
  });

  it("replaces Resume with recovery guidance after a safety stop", () => {
    render(<UtilityPreview />);
    chooseScenario(/Safety stop/);
    const w = widget();
    expect(within(w).queryByRole("button", { name: /resume|pause/i })).toBeNull();
    expect(within(w).getByText(/resume isn’t available after a safety stop/i)).toBeInTheDocument();

    fireEvent.click(within(w).getByRole("button", { name: "Troubleshoot" }));
    const panel = screen.getByRole("tabpanel");
    expect(screen.getByRole("tab", { name: "Troubleshoot" })).toHaveAttribute("aria-selected", "true");
    expect(within(panel).getByRole("heading", { name: "Sharing stopped for safety" })).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: /export support bundle/i })).toBeDisabled();
  });
});

describe("UtilityPreview — widget keyboard and dismissal", () => {
  it("Escape dismisses without changing state and returns focus to the tray icon", () => {
    render(<UtilityPreview />);
    fireEvent.keyDown(within(widget()).getByRole("button", { name: "Settings" }), { key: "Escape" });

    expect(screen.queryByRole("dialog")).toBeNull();
    const tray = screen.getByRole("button", { name: "Software KVM: Agent not connected" });
    expect(tray).toHaveFocus();
    expect(tray).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(tray);
    expect(widget()).toHaveFocus();
  });

  it("dismisses on outside activation but not on activation inside the widget", () => {
    render(<UtilityPreview />);
    fireEvent.pointerDown(widget());
    expect(screen.queryByRole("dialog")).not.toBeNull();
    fireEvent.pointerDown(screen.getByRole("main"));
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("UtilityPreview — settings and setup navigation", () => {
  it("moves between settings sections with arrow, Home and End keys", () => {
    render(<UtilityPreview />);
    fireEvent.click(within(widget()).getByRole("button", { name: "Settings" }));

    const first = screen.getByRole("tab", { name: "Computers & displays" });
    expect(first).toHaveAttribute("aria-selected", "true");
    expect(first).toHaveAttribute("tabindex", "0");

    fireEvent.keyDown(first, { key: "ArrowDown" });
    const input = screen.getByRole("tab", { name: "Keyboard & clipboard" });
    expect(input).toHaveAttribute("aria-selected", "true");
    expect(input).toHaveFocus();
    expect(first).toHaveAttribute("tabindex", "-1");
    expect(screen.getByRole("tabpanel", { name: "Keyboard & clipboard" })).toBeInTheDocument();

    fireEvent.keyDown(input, { key: "End" });
    expect(screen.getByRole("tab", { name: "About" })).toHaveFocus();
    fireEvent.keyDown(screen.getByRole("tab", { name: "About" }), { key: "ArrowDown" });
    expect(first).toHaveFocus();
  });

  it("keeps settings read-only, showing unknown values and the reason", () => {
    render(<UtilityPreview />);
    fireEvent.click(within(widget()).getByRole("button", { name: "Settings" }));
    fireEvent.click(screen.getByRole("tab", { name: "Keyboard & clipboard" }));

    const clipboard = screen.getByRole("switch", { name: "Share plain-text clipboard" });
    expect(clipboard).toBeDisabled();
    expect(clipboard).toHaveAttribute("aria-checked", "mixed");
    expect(clipboard).toHaveAccessibleDescription(/no software kvm agent/i);

    fireEvent.click(screen.getByRole("tab", { name: "Computers & displays" }));
    expect(screen.getByRole("button", { name: /forget this computer/i })).toBeDisabled();
  });

  it("closing a window returns to the dismissed widget with focus on the tray icon", () => {
    render(<UtilityPreview />);
    fireEvent.click(within(widget()).getByRole("button", { name: "Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Close Software KVM Settings" }));
    expect(screen.getByRole("button", { name: /^Software KVM:/ })).toHaveFocus();
  });

  it("lets setup steps be browsed but never completed", () => {
    render(<UtilityPreview />);
    chooseScenario(/^Preview fixture: Paused$/);
    fireEvent.click(screen.getByRole("button", { name: "Setup" }));

    expect(screen.getByText("Step 1 of 5")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous step" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /next step/i }));
    expect(screen.getByText("Step 2 of 5")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /permissions/i })).toHaveAttribute("aria-selected", "true");

    const act = screen.getByRole("button", { name: "Check permissions" });
    expect(act).toBeDisabled();
    expect(act).toHaveAccessibleDescription(/isn’t available in this preview/i);
  });
});
