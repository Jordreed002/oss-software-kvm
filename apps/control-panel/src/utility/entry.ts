/** Development-only entry gate for the replacement utility UI.
 *
 *  The legacy console stays the default surface. The utility preview renders
 *  only when BOTH conditions hold: the bundle is a Vite development build and
 *  the URL explicitly asks for `?surface=utility`. `main.tsx` evaluates
 *  `import.meta.env.DEV` first, so production builds drop the lazy import of
 *  the utility chunk entirely. */
export function shouldRenderUtilitySurface(isDev: boolean, search: string): boolean {
  if (!isDev) return false;
  return new URLSearchParams(search).get("surface") === "utility";
}

/** Whether the page is hosted by the native development tray shell
 *  (`--utility-preview`) rather than a plain browser tab. Tauri injects
 *  `__TAURI_INTERNALS__` into every webview it creates. This only selects
 *  honest labelling; it does not imply an agent, capture or any IPC access. */
export function isNativePreviewHost(win: object): boolean {
  return "__TAURI_INTERNALS__" in win;
}
