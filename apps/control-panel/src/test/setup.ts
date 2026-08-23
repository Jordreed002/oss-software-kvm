import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest globals are off, so @testing-library/react cannot self-register its
// afterEach cleanup — do it explicitly so the DOM resets between tests.
afterEach(cleanup);

// jsdom does not implement ResizeObserver, which TimeSeriesChart attaches in
// its useLayoutEffect to track the plot width. The stub never fires, so the
// chart keeps its initial 640px width — enough for rendering assertions.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
