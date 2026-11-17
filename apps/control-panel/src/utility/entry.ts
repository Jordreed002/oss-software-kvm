/** Development-only entry gate for the replacement utility UI.
 *
 *  The legacy console stays the default surface. A utility surface renders
 *  only when BOTH conditions hold: the bundle is a Vite development build and
 *  the URL explicitly asks for it. `main.tsx` evaluates
 *  `import.meta.env.DEV` first, so production builds drop the lazy imports of
 *  both utility chunks entirely.
 *
 *  - `?surface=utility`: fixture/no-agent preview. Never calls IPC.
 *  - `?surface=utility-agent`: read-only native agent status. Only works in
 *    the `--utility-agent` native shell, which is the only host that
 *    registers the `agent_status` command. */
export type UtilitySurface = "utility" | "utility-agent";

export function selectUtilitySurface(isDev: boolean, search: string): UtilitySurface | null {
  if (!isDev) return null;
  const surface = new URLSearchParams(search).get("surface");
  return surface === "utility" || surface === "utility-agent" ? surface : null;
}

/** Fixture preview gate (kept for existing callers and tests). */
export function shouldRenderUtilitySurface(isDev: boolean, search: string): boolean {
  return selectUtilitySurface(isDev, search) === "utility";
}

/** Whether the page is hosted by a native development tray shell rather than
 *  a plain browser tab. Tauri injects `__TAURI_INTERNALS__` into every webview
 *  it creates. This only selects honest labelling; it does not imply an
 *  agent, capture or any IPC access. */
export function isNativePreviewHost(win: object): boolean {
  return "__TAURI_INTERNALS__" in win;
}
