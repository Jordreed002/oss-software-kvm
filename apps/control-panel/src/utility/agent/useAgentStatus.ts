import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { BRIDGE_FAILURE, type AgentResult } from "./status";

export interface AgentStatusState {
  /** Newest settled result; null until the first query settles. */
  result: AgentResult | null;
  /** When `result` settled (ms since epoch); null with it. */
  checkedAt: number | null;
  /** A query is in flight. The previous result stays visible meanwhile. */
  checking: boolean;
}

export interface AgentStatusController extends AgentStatusState {
  refresh: () => void;
}

/** Fetches agent status once on mount and once per `refresh()`. No polling.
 *
 *  Each query gets a sequence number; a completion is applied only if it
 *  belongs to the newest query, so a slow early reply can never overwrite a
 *  newer one. Completions after unmount are dropped.
 *
 *  `query` must be stable (module-level or created once) and should resolve
 *  rather than reject; a rejection is treated as a bridge failure. */
export function useAgentStatus(query: () => Promise<AgentResult>, now: () => number = Date.now): AgentStatusController {
  const [state, setState] = useState<AgentStatusState>({ result: null, checkedAt: null, checking: true });
  const latest = useRef(0);
  const mounted = useRef(false);
  const started = useRef(false);
  // Latest inputs, read only inside callbacks (never during render).
  const deps = useRef({ query, now });
  useLayoutEffect(() => {
    deps.current = { query, now };
  });

  const refresh = useCallback(() => {
    const id = ++latest.current;
    setState((s) => (s.checking ? s : { ...s, checking: true }));
    const settle = (result: AgentResult) => {
      if (!mounted.current || id !== latest.current) return;
      setState({ result, checkedAt: deps.current.now(), checking: false });
    };
    let pending: Promise<AgentResult>;
    try {
      pending = deps.current.query();
    } catch {
      pending = Promise.resolve(BRIDGE_FAILURE);
    }
    pending.then(settle, () => settle(BRIDGE_FAILURE));
  }, []);

  useEffect(() => {
    mounted.current = true;
    // StrictMode re-runs this effect on the same instance; refs persist, so
    // the mount query is still sent exactly once.
    if (!started.current) {
      started.current = true;
      refresh();
    }
    return () => {
      mounted.current = false;
    };
  }, [refresh]);

  return { ...state, refresh };
}
