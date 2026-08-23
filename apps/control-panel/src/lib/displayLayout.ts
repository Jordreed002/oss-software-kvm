import type { DisplayInfo, DisplayPlacement, SetupSnapshot } from "../types";

/** Pure display-layout geometry and placement logic for the workspace-map
 *  editor. Extracted from App.tsx verbatim — no behavior changes — so the
 *  drag/snap/edge rules can be unit-tested without a DOM. */

export type DisplayOwner = "local" | "peer";
export type MappedDisplay = DisplayInfo & { owner: DisplayOwner; hostName: string; number: number };

export const MAP_PADDING = 28;

export function mappedDisplays(snapshot: SetupSnapshot): MappedDisplay[] {
  const localName = snapshot.local?.displayName ?? "This computer";
  const peerName = snapshot.peer?.displayName ?? "Paired computer";
  return [
    ...snapshot.displays.map((display, index) => ({ ...display, owner: "local" as const, hostName: localName, number: index + 1 })),
    ...(snapshot.peer?.displays ?? []).map((display, index) => ({ ...display, owner: "peer" as const, hostName: peerName, number: snapshot.displays.length + index + 1 })),
  ];
}

export function defaultDisplayLayout(snapshot: SetupSnapshot, displays: MappedDisplay[]): DisplayPlacement[] {
  const ids = new Set(displays.map((display) => display.id));
  if (snapshot.displayLayout.length === displays.length && snapshot.displayLayout.every((item) => ids.has(item.displayId))) {
    const minimumX = Math.min(...snapshot.displayLayout.map((item) => item.x));
    const minimumY = Math.min(...snapshot.displayLayout.map((item) => item.y));
    return snapshot.displayLayout.map((item) => ({ ...item, x: item.x - minimumX, y: item.y - minimumY }));
  }
  const ordered = (owner: DisplayOwner) => displays
    .filter((display) => display.owner === owner)
    .sort((left, right) => (left.nativeBounds?.x ?? Number(!left.primary)) - (right.nativeBounds?.x ?? Number(!right.primary)) || (left.nativeBounds?.y ?? 0) - (right.nativeBounds?.y ?? 0));
  const groups = snapshot.placement === "local_left" ? [ordered("local"), ordered("peer")] : [ordered("peer"), ordered("local")];
  const layout: DisplayPlacement[] = [];
  let x = 0;
  for (const group of groups) {
    for (const display of group) {
      layout.push({ displayId: display.id, x, y: 0 });
      x += display.width;
    }
  }
  return layout;
}

export function displayTouch(
  first: DisplayPlacement,
  firstDisplay: MappedDisplay,
  second: DisplayPlacement,
  secondDisplay: MappedDisplay,
) {
  const epsilon = .01;
  const verticalOverlap = Math.min(first.y + firstDisplay.height, second.y + secondDisplay.height) - Math.max(first.y, second.y);
  const horizontalOverlap = Math.min(first.x + firstDisplay.width, second.x + secondDisplay.width) - Math.max(first.x, second.x);
  return (verticalOverlap > 1 && (Math.abs(first.x + firstDisplay.width - second.x) < epsilon || Math.abs(second.x + secondDisplay.width - first.x) < epsilon))
    || (horizontalOverlap > 1 && (Math.abs(first.y + firstDisplay.height - second.y) < epsilon || Math.abs(second.y + secondDisplay.height - first.y) < epsilon));
}

export function hasCrossHostEdge(layout: DisplayPlacement[], displays: MappedDisplay[]) {
  const byId = new Map(displays.map((display) => [display.id, display]));
  return layout.some((first, index) => layout.slice(index + 1).some((second) => {
    const firstDisplay = byId.get(first.displayId);
    const secondDisplay = byId.get(second.displayId);
    return !!firstDisplay && !!secondDisplay && firstDisplay.owner !== secondDisplay.owner
      && displayTouch(first, firstDisplay, second, secondDisplay);
  }));
}

export function hasDisplayOverlap(layout: DisplayPlacement[], displays: MappedDisplay[]) {
  const byId = new Map(displays.map((display) => [display.id, display]));
  return layout.some((first, index) => layout.slice(index + 1).some((second) => {
    const firstDisplay = byId.get(first.displayId);
    const secondDisplay = byId.get(second.displayId);
    if (!firstDisplay || !secondDisplay) return false;
    const horizontalOverlap = Math.min(first.x + firstDisplay.width, second.x + secondDisplay.width) - Math.max(first.x, second.x);
    const verticalOverlap = Math.min(first.y + firstDisplay.height, second.y + secondDisplay.height) - Math.max(first.y, second.y);
    return horizontalOverlap > .01 && verticalOverlap > .01;
  }));
}

export function snapDisplay(layout: DisplayPlacement[], movingId: string, displays: MappedDisplay[], scale: number) {
  const byId = new Map(displays.map((display) => [display.id, display]));
  const moving = layout.find((item) => item.displayId === movingId);
  const movingDisplay = byId.get(movingId);
  if (!moving || !movingDisplay) return layout;
  const threshold = 22 / scale;
  let best = { distance: threshold, x: moving.x, y: moving.y };
  for (const other of layout) {
    if (other.displayId === movingId) continue;
    const otherDisplay = byId.get(other.displayId);
    if (!otherDisplay) continue;
    const horizontal = [
      { x: other.x + otherDisplay.width, distance: Math.abs(moving.x - (other.x + otherDisplay.width)) },
      { x: other.x - movingDisplay.width, distance: Math.abs(moving.x + movingDisplay.width - other.x) },
    ];
    for (const candidate of horizontal) {
      const overlap = Math.min(moving.y + movingDisplay.height, other.y + otherDisplay.height) - Math.max(moving.y, other.y);
      if (overlap > 1 && candidate.distance < best.distance) best = { ...best, x: candidate.x, distance: candidate.distance };
    }
    const vertical = [
      { y: other.y + otherDisplay.height, distance: Math.abs(moving.y - (other.y + otherDisplay.height)) },
      { y: other.y - movingDisplay.height, distance: Math.abs(moving.y + movingDisplay.height - other.y) },
    ];
    for (const candidate of vertical) {
      const overlap = Math.min(moving.x + movingDisplay.width, other.x + otherDisplay.width) - Math.max(moving.x, other.x);
      if (overlap > 1 && candidate.distance < best.distance) best = { ...best, y: candidate.y, distance: candidate.distance };
    }
  }
  const next = layout.map((item) => item.displayId === movingId
    ? { ...item, x: Math.max(0, Math.round(best.x * 1000) / 1000), y: Math.max(0, Math.round(best.y * 1000) / 1000) }
    : item);
  const minimumX = Math.min(...next.map((item) => item.x));
  const minimumY = Math.min(...next.map((item) => item.y));
  return next.map((item) => ({ ...item, x: item.x - minimumX, y: item.y - minimumY }));
}
