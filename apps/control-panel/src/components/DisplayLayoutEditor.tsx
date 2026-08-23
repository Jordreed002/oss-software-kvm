import { useEffect, useMemo, useState } from "react";
import { Move, RotateCcw } from "lucide-react";
import {
  MAP_PADDING, type MappedDisplay, defaultDisplayLayout, hasCrossHostEdge,
  hasDisplayOverlap, mappedDisplays, snapDisplay,
} from "../lib/displayLayout";
import type { DisplayPlacement, Placement, SetupSnapshot } from "../types";
import { PrimaryButton, SectionHeading } from "./shared";

/** Step 03 of the setup wizard: the draggable workspace display map. The pure
 *  placement/geometry rules live in src/lib/displayLayout.ts; this component
 *  owns the pointer-drag interaction and validation copy. Extracted from
 *  App.tsx verbatim — no behavior changes. */
export function ArrangeStep({ snapshot, busy, onContinue }: { snapshot: SetupSnapshot; busy: string | null; onContinue: (placement: Placement, layout: DisplayPlacement[]) => void }) {
  const displays = useMemo(() => mappedDisplays(snapshot), [snapshot]);
  const [layout, setLayout] = useState(() => defaultDisplayLayout(snapshot, displays));
  const followsPeer = snapshot.workspaceRole === "follower";
  const leadsPeer = snapshot.workspaceRole === "leader";
  const [drag, setDrag] = useState<{ displayId: string; pointerId: number; clientX: number; clientY: number; x: number; y: number } | null>(null);
  useEffect(() => {
    if (followsPeer) setLayout(defaultDisplayLayout(snapshot, displays));
  }, [displays, followsPeer, snapshot]);
  const scale = useMemo(() => {
    const totalWidth = displays.reduce((sum, display) => sum + display.width, 0);
    const tallest = Math.max(...displays.map((display) => display.height), 1);
    return Math.min(.16, 690 / Math.max(totalWidth, 1), 285 / tallest);
  }, [displays]);
  const byId = useMemo(() => new Map(displays.map((display) => [display.id, display])), [displays]);
  const maxRight = Math.max(...layout.map((item) => item.x + (byId.get(item.displayId)?.width ?? 0)), 1);
  const maxBottom = Math.max(...layout.map((item) => item.y + (byId.get(item.displayId)?.height ?? 0)), 1);
  const canvasWidth = Math.max(720, maxRight * scale + MAP_PADDING * 2);
  const canvasHeight = Math.max(330, maxBottom * scale + MAP_PADDING * 2);
  const linked = hasCrossHostEdge(layout, displays);
  const overlapping = hasDisplayOverlap(layout, displays);
  const valid = linked && !overlapping;
  const localCenter = layout.filter((item) => byId.get(item.displayId)?.owner === "local").reduce((sum, item) => sum + item.x + (byId.get(item.displayId)?.width ?? 0) / 2, 0) / Math.max(snapshot.displays.length, 1);
  const peerCenter = layout.filter((item) => byId.get(item.displayId)?.owner === "peer").reduce((sum, item) => sum + item.x + (byId.get(item.displayId)?.width ?? 0) / 2, 0) / Math.max(snapshot.peer?.displays.length ?? 0, 1);
  const placement: Placement = localCenter <= peerCenter ? "local_left" : "local_right";

  return <div className="step-content enter arrange-content">
    <SectionHeading number="03" kicker="WORKSPACE MAP" title="Build the desk you actually have." copy="Drag every screen into its physical position. Touch one Mac edge to one Windows edge to choose where the pointer crosses." />
    <div className="display-map-toolbar">
      <div className="map-legend"><span className="local"><i/>This computer</span><span className="peer"><i/>Paired computer</span><em className={`map-role ${snapshot.workspaceRole}`}>{followsPeer ? `${snapshot.peer?.displayName ?? "Peer"} leads` : snapshot.workspaceRole === "leader" ? "This computer leads" : "Local map"}</em></div>
      <button disabled={followsPeer} onClick={() => setLayout(defaultDisplayLayout(snapshot, displays))}><RotateCcw size={13}/>Reset arrangement</button>
    </div>
    <div className="display-map-viewport">
      <div className="display-map-grid" style={{ width: canvasWidth, height: canvasHeight }}>
        <div className="map-instruction"><Move size={13}/>DRAG TO POSITION · EDGES SNAP TOGETHER</div>
        {layout.map((position) => {
          const display: MappedDisplay | undefined = byId.get(position.displayId);
          if (!display) return null;
          return <button
            key={display.id}
            className={`mapped-display ${display.owner} ${display.primary ? "primary" : ""} ${drag?.displayId === display.id ? "dragging" : ""}`}
            style={{ left: MAP_PADDING + position.x * scale, top: MAP_PADDING + position.y * scale, width: display.width * scale, height: display.height * scale }}
            onPointerDown={(event) => {
              if (followsPeer) return;
              event.currentTarget.setPointerCapture(event.pointerId);
              setDrag({ displayId: display.id, pointerId: event.pointerId, clientX: event.clientX, clientY: event.clientY, x: position.x, y: position.y });
            }}
            onPointerMove={(event) => {
              if (!drag || drag.displayId !== display.id || drag.pointerId !== event.pointerId) return;
              setLayout((current) => current.map((item) => item.displayId === display.id ? {
                ...item,
                x: Math.max(0, drag.x + (event.clientX - drag.clientX) / scale),
                y: Math.max(0, drag.y + (event.clientY - drag.clientY) / scale),
              } : item));
            }}
            onPointerUp={(event) => {
              if (!drag || drag.pointerId !== event.pointerId) return;
              setLayout((current) => snapDisplay(current, display.id, displays, scale));
              setDrag(null);
            }}
          >
            <span className="display-number">{display.number}</span>
            <span className="display-identity"><small>{display.owner === "local" ? "THIS COMPUTER" : "PAIRED COMPUTER"}</small><strong>{display.hostName}</strong></span>
            <span className="display-spec">{Math.round(display.width)} × {Math.round(display.height)}{display.primary ? " · MAIN" : ""}</span>
          </button>;
        })}
      </div>
    </div>
    <div className={`map-validation ${valid && !followsPeer ? "ready" : "needs-edge"}`}>
      <span><i/>{followsPeer ? "FOLLOWING THE PAIRING LEADER" : overlapping ? "SCREENS CANNOT OVERLAP" : linked ? "HANDOFF EDGE READY" : "CONNECT THE TWO COMPUTERS"}</span>
      <p>{followsPeer ? `Save the arrangement on ${snapshot.peer?.displayName ?? "the paired computer"}. Its signed map will appear here automatically.` : overlapping ? "Separate the overlapping screens, then join one Mac edge to one Windows edge." : linked && leadsPeer ? "The signed map will be synchronized to the paired computer." : linked ? "This older or manual pairing cannot sync maps; save the same arrangement on both computers." : "Drag a screen from each computer together until their edges snap."}</p>
    </div>
    <PrimaryButton busy={busy === "arrange"} disabled={!valid || followsPeer} onClick={() => onContinue(placement, layout)}>{followsPeer ? "Waiting for leader map" : leadsPeer ? "Save and sync display map" : "Save display map"}</PrimaryButton>
  </div>;
}
