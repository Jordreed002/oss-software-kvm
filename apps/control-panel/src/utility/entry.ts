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
