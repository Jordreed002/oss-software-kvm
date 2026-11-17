import "@fontsource-variable/manrope";
import "@fontsource-variable/newsreader";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";
import { selectUtilitySurface } from "./utility/entry";

const root = ReactDOM.createRoot(document.getElementById("root")!);

// Development-only replacement utility UIs, opt-in via ?surface=utility
// (fixtures, no IPC) or ?surface=utility-agent (read-only agent status). The
// DEV check comes first so production builds drop both lazy chunks entirely.
const surface = import.meta.env.DEV ? selectUtilitySurface(import.meta.env.DEV, window.location.search) : null;

if (import.meta.env.DEV && surface !== null) {
  const Surface =
    surface === "utility-agent"
      ? React.lazy(() => import("./utility/agent/AgentUtility"))
      : React.lazy(() => import("./utility/UtilityPreview"));
  root.render(
    <React.StrictMode>
      <React.Suspense fallback={null}>
        <Surface />
      </React.Suspense>
    </React.StrictMode>,
  );
} else {
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}
