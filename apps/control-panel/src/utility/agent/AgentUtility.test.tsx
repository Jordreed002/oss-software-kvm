import { StrictMode } from "react";
import { act, fireEvent, render, renderHook, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import AgentUtility, { type SubscribeOpened } from "./AgentUtility";
import type { AgentResult, AgentSnapshot } from "./status";
import { idleStubPayload, unavailablePayload } from "./testSnapshots";
import { useAgentStatus } from "./useAgentStatus";

/** A controllable query: each call returns a promise the test settles. */
function deferredQueue<T>() {
  const pending: { resolve: (v: T) => void; reject: (e: unknown) => void }[] = [];
  const fn = vi.fn(
    () =>
      new Promise<T>((resolve, reject) => {
        pending.push({ resolve, reject });
      }),
  );
  return { fn, pending };
}

const connected = (revision: string): AgentResult => {
  const p = idleStubPayload();
  return { kind: "connected", snapshot: { ...(p.snapshot as unknown as AgentSnapshot), revision } };
};
const failed = (error: "not_found" | "timed_out"): AgentResult => ({ kind: "failed", error });

const noSubscribe: SubscribeOpened = () => () => {};

afterEach(() => {
  vi.useRealTimers();
});

describe("useAgentStatus", () => {
  it("queries exactly once on mount, even under StrictMode", async () => {
    const q = deferredQueue<AgentResult>();
    renderHook(() => useAgentStatus(q.fn), { wrapper: StrictMode });
    expect(q.fn).toHaveBeenCalledTimes(1);
    await act(async () => q.pending[0].resolve(connected("1")));
    expect(q.fn).toHaveBeenCalledTimes(1);
  });

  it("never polls", async () => {
    vi.useFakeTimers();
    const q = deferredQueue<AgentResult>();
    renderHook(() => useAgentStatus(q.fn));
    await act(async () => q.pending[0].resolve(connected("1")));
    await act(async () => {
      vi.advanceTimersByTime(10 * 60 * 1000);
    });
    expect(q.fn).toHaveBeenCalledTimes(1);
  });

  it("drops a stale completion that settles after a newer one", async () => {
    const q = deferredQueue<AgentResult>();
    let t = 100;
    const { result } = renderHook(() => useAgentStatus(q.fn, () => t++));
    act(() => result.current.refresh());
    expect(q.fn).toHaveBeenCalledTimes(2);

    await act(async () => q.pending[1].resolve(connected("2")));
    expect(result.current.result).toEqual(connected("2"));
    expect(result.current.checking).toBe(false);
    const checkedAt = result.current.checkedAt;

    // The first (older) query answers late with a different state.
    await act(async () => q.pending[0].resolve(failed("timed_out")));
    expect(result.current.result).toEqual(connected("2"));
    expect(result.current.checkedAt).toBe(checkedAt);
  });

  it("keeps the previous result visible while a refresh is in flight, then replaces it", async () => {
    const q = deferredQueue<AgentResult>();
    const { result } = renderHook(() => useAgentStatus(q.fn));
    expect(result.current).toMatchObject({ result: null, checking: true });
    await act(async () => q.pending[0].resolve(connected("1")));
    act(() => result.current.refresh());
    expect(result.current).toMatchObject({ result: connected("1"), checking: true });
    await act(async () => q.pending[1].resolve(failed("not_found")));
    expect(result.current).toMatchObject({ result: failed("not_found"), checking: false });
  });

  it("ignores completions after unmount and maps rejections to a bridge failure", async () => {
    const q = deferredQueue<AgentResult>();
    const first = renderHook(() => useAgentStatus(q.fn));
    first.unmount();
    await act(async () => q.pending[0].resolve(connected("1")));
    expect(first.result.current.result).toBeNull();

    const second = renderHook(() => useAgentStatus(q.fn));
    await act(async () => q.pending[1].reject(new Error("boom")));
    expect(second.result.current.result).toEqual({ kind: "failed", error: "bridge" });
  });
});

describe("AgentUtility", () => {
  it("renders the real idle snapshot with unknowns and every mutation disabled", async () => {
    const invoke = vi.fn(async () => idleStubPayload());
    render(<AgentUtility invoke={invoke} subscribeOpened={noSubscribe} />);
    expect(screen.getByRole("heading", { name: "Checking the agent" })).toBeInTheDocument();
    await screen.findByRole("heading", { name: "Input location not confirmed" });

    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("agent_status");
    expect(screen.getByText("Agent connected")).toBeInTheDocument();
    expect(screen.getByText("Dev, read-only")).toBeInTheDocument();
    expect(screen.getByText("0 of 6 confirmed")).toBeInTheDocument();
    const input = within(screen.getByLabelText("Agent status")).getByText("Not confirmed");
    expect(input).toHaveAttribute("data-unknown");

    const resume = screen.getByRole("button", { name: /resume sharing/i });
    expect(resume).toBeDisabled();
    expect(resume).toHaveAccessibleDescription("The agent doesn’t offer Resume yet.");
    expect(screen.getByRole("button", { name: /quit agent/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled();

    // No fixture vocabulary or controls leak into the agent surface.
    expect(document.body.textContent).not.toMatch(/fixture|Desk PC|Studio Mac|scenario/i);
    expect(screen.queryByRole("combobox")).toBeNull();
    for (const button of screen.getAllByRole("button")) {
      if (button.textContent !== "Refresh") expect(button).toBeDisabled();
    }
  });

  it.each([
    ["not_found", "Agent not running", "No agent"],
    ["permission_denied", "Agent couldn’t be verified", "Not trusted"],
    ["timed_out", "Agent didn’t answer in time", "No reply"],
    ["incompatible", "Agent version doesn’t match", "Incompatible"],
    ["invalid_reply", "Agent reply was rejected", "Bad reply"],
    ["transport", "Connection to the agent failed", "Disconnected"],
  ])("shows %s as its own state with mutations disabled", async (error, headline, badge) => {
    render(<AgentUtility invoke={async () => unavailablePayload(error)} subscribeOpened={noSubscribe} />);
    await screen.findByRole("heading", { name: headline });
    expect(screen.getByText(badge)).toBeInTheDocument();
    expect(screen.queryByText("Agent connected")).toBeNull();
    expect(screen.queryByText(/of 6 confirmed/)).toBeNull();
    expect(screen.getByRole("button", { name: /pause sharing/i })).toBeDisabled();
  });

  it("shows a bridge failure when the native command is unavailable (plain browser)", async () => {
    render(
      <AgentUtility
        invoke={async () => {
          throw new Error("no Tauri");
        }}
        subscribeOpened={noSubscribe}
      />,
    );
    await screen.findByRole("heading", { name: "Status check couldn’t run" });
    expect(screen.getByText("App error")).toBeInTheDocument();
  });

  it("refetches once per Refresh and once per tray open, and shows the newest answer", async () => {
    const answers = [idleStubPayload(), unavailablePayload("not_found"), idleStubPayload()];
    const invoke = vi.fn(async () => answers.shift());
    let opened: (() => void) | null = null;
    const unsubscribe = vi.fn();
    const subscribe: SubscribeOpened = (cb) => {
      opened = cb;
      return unsubscribe;
    };
    const { unmount } = render(<AgentUtility invoke={invoke} subscribeOpened={subscribe} />);
    await screen.findByRole("heading", { name: "Input location not confirmed" });

    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("heading", { name: "Agent not running" });
    expect(invoke).toHaveBeenCalledTimes(2);

    await act(async () => opened?.());
    await screen.findByRole("heading", { name: "Input location not confirmed" });
    expect(invoke).toHaveBeenCalledTimes(3);

    unmount();
    expect(unsubscribe).toHaveBeenCalled();
  });

  it("does not let a slow earlier reply overwrite a newer refresh", async () => {
    const q = deferredQueue<unknown>();
    render(<AgentUtility invoke={q.fn} subscribeOpened={noSubscribe} />);
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(q.fn).toHaveBeenCalledTimes(2);

    await act(async () => q.pending[1].resolve(unavailablePayload("timed_out")));
    await screen.findByRole("heading", { name: "Agent didn’t answer in time" });
    await act(async () => q.pending[0].resolve(idleStubPayload()));
    expect(screen.getByRole("heading", { name: "Agent didn’t answer in time" })).toBeInTheDocument();
    expect(screen.queryByText("Agent connected")).toBeNull();
  });

  it("announces checking and the time of the last answer", async () => {
    const q = deferredQueue<unknown>();
    render(<AgentUtility invoke={q.fn} subscribeOpened={noSubscribe} now={() => Date.UTC(2026, 10, 17, 9, 30, 5)} />);
    expect(screen.getByRole("status")).toHaveTextContent("Checking agent status…");
    await act(async () => q.pending[0].resolve(idleStubPayload()));
    expect(screen.getByRole("status")).toHaveTextContent(/^Checked at /);
  });
});
