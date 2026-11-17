import "@fontsource-variable/manrope";
import "@fontsource-variable/newsreader";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";
import { shouldRenderUtilitySurface } from "./utility/entry";

const root = ReactDOM.createRoot(document.getElementById("root")!);

// Development-only replacement utility UI, opt-in via ?surface=utility. The
// DEV check comes first so production builds drop the lazy chunk entirely.
if (import.meta.env.DEV && shouldRenderUtilitySurface(import.meta.env.DEV, window.location.search)) {
  const UtilityPreview = React.lazy(() => import("./utility/UtilityPreview"));
  root.render(
    <React.StrictMode>
      <React.Suspense fallback={null}>
        <UtilityPreview />
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
