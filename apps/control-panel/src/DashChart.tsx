import { useCallback, useLayoutEffect, useRef, useState } from "react";

/** One drawable series in a {@link TimeSeriesChart}. Points share a common time
 *  grid across series (they are sampled together), which lets the hover
 *  crosshair index into every series at the same moment. */
export interface ChartSeries {
  id: string;
  label: string;
  color: string;
  points: Array<{ t: number; y: number | null }>;
}

interface TimeSeriesChartProps {
  title: string;
  badge?: string;
  /** Span of time (ms) mapped across the x axis. */
  windowMs: number;
  series: ChartSeries[];
  yFormat: (value: number) => string;
  /** Fixed pixel height of the plot canvas. */
  height?: number;
}

const PAD = { left: 46, right: 14, top: 16, bottom: 24 };
const GRID_LINES = 4;
const HOVER_HIT_RADIUS_PX = 30;

/** Dependency-free responsive SVG line/area chart with a hover crosshair and
 *  tooltip. Deliberately hand-rolled so the control panel stays free of a
 *  heavyweight charting dependency and the visual language matches the rest of
 *  the bespoke console. */
export function TimeSeriesChart({ title, badge = "LIVE", windowMs, series, yFormat, height = 180 }: TimeSeriesChartProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  useLayoutEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const measure = () => setWidth(Math.max(280, el.clientWidth));
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const plotW = Math.max(10, width - PAD.left - PAD.right);
  const plotH = height - PAD.top - PAD.bottom;
  const times = series[0]?.points.map((point) => point.t) ?? [];
  const now = times.length > 0 ? times[times.length - 1] : 0;

  const visiblePoints = series.flatMap((seriesEntry) => seriesEntry.points.filter((point) => point.y != null));
  const rawMax = visiblePoints.reduce((max, point) => Math.max(max, point.y as number), Number.NEGATIVE_INFINITY);
  const yMax = Number.isFinite(rawMax) ? rawMax * 1.15 : 1;
  const yMin = 0;
  const ySpan = Math.max(yMax - yMin, 1);

  const xOf = (t: number) => {
    const ratio = (t - (now - windowMs)) / windowMs;
    return PAD.left + Math.max(0, Math.min(1, ratio)) * plotW;
  };
  const yOf = (v: number) => PAD.top + (1 - (v - yMin) / ySpan) * plotH;

  const buildPath = (points: ChartSeries["points"]) => {
    let path = "";
    let penDown = false;
    for (const point of points) {
      if (point.y == null) {
        penDown = false;
        continue;
      }
      const command = penDown ? "L" : "M";
      path += `${command}${xOf(point.t).toFixed(2)} ${yOf(point.y).toFixed(2)}`;
      penDown = true;
    }
    return path;
  };

  const buildArea = (points: ChartSeries["points"]) => {
    const segments: string[] = [];
    let start: number | null = null;
    let segment: string[] = [];
    for (const point of points) {
      if (point.y == null) {
        if (segment.length > 0 && start != null) {
          const lastX = segmentX(segment[segment.length - 1]);
          segments.push(`M${xOf(start).toFixed(2)} ${yOf(yMin).toFixed(2)} ${segment.join(" ")} L${lastX.toFixed(2)} ${yOf(yMin).toFixed(2)} Z`);
        }
        segment = [];
        start = null;
        continue;
      }
      if (start == null) start = point.t;
      segment.push(`L${xOf(point.t).toFixed(2)} ${yOf(point.y).toFixed(2)}`);
    }
    if (segment.length > 0 && start != null) {
      const lastX = segmentX(segment[segment.length - 1]);
      segments.push(`M${xOf(start).toFixed(2)} ${yOf(yMin).toFixed(2)} ${segment.join(" ")} L${lastX.toFixed(2)} ${yOf(yMin).toFixed(2)} Z`);
    }
    return segments.join(" ");
  };

  const gridValues = Array.from({ length: GRID_LINES + 1 }, (_, index) => (ySpan / GRID_LINES) * index);

  const onMove = (event: React.MouseEvent<HTMLDivElement>) => {
    if (times.length === 0) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const px = event.clientX - rect.left;
    let best = -1;
    let bestDistance = Number.POSITIVE_INFINITY;
    for (let index = 0; index < times.length; index += 1) {
      const distance = Math.abs(xOf(times[index]) - px);
      if (distance < bestDistance) {
        bestDistance = distance;
        best = index;
      }
    }
    setHoverIdx(bestDistance <= HOVER_HIT_RADIUS_PX + plotW ? best : null);
  };

  const active = hoverIdx != null && hoverIdx >= 0 && hoverIdx < times.length ? hoverIdx : null;
  const crosshairX = active != null ? xOf(times[active]) : null;
  const ageSeconds = active != null ? Math.max(0, Math.round((now - times[active]) / 1000)) : null;

  return (
    <div className="dash-chart-card">
      <div className="dash-chart-head">
        <span>{title}</span>
        <em>{badge}</em>
      </div>
      <div
        className="dash-chart-canvas"
        ref={containerRef}
        onMouseMove={onMove}
        onMouseLeave={() => setHoverIdx(null)}
      >
        {times.length === 0 ? (
          <div className="dash-chart-empty">Collecting telemetry…</div>
        ) : (
          <svg width={width} height={height} className="dash-svg" role="img" aria-label={`${title} time series`}>
            {gridValues.map((value, index) => {
              const y = yOf(value);
              return (
                <g key={`grid-${index}`}>
                  <line x1={PAD.left} y1={y} x2={PAD.left + plotW} y2={y} stroke="rgba(235,233,223,.06)" strokeWidth={1} />
                  <text x={PAD.left - 8} y={y + 3} textAnchor="end" className="dash-axis-text">{yFormat(value)}</text>
                </g>
              );
            })}
            {[0.25, 0.5, 0.75, 1].map((fraction) => {
              const labelSeconds = Math.round((windowMs / 1000) * (1 - fraction));
              return (
                <text key={`xtick-${fraction}`} x={PAD.left + plotW * fraction} y={height - 6} textAnchor="middle" className="dash-axis-text">
                  {labelSeconds === 0 ? "now" : `-${labelSeconds}s`}
                </text>
              );
            })}
            {series.map((seriesEntry) => (
              <path key={`area-${seriesEntry.id}`} d={buildArea(seriesEntry.points)} fill={seriesEntry.color} fillOpacity={0.1} stroke="none" />
            ))}
            {series.map((seriesEntry) => (
              <path key={`line-${seriesEntry.id}`} d={buildPath(seriesEntry.points)} fill="none" stroke={seriesEntry.color} strokeWidth={1.75} strokeLinejoin="round" strokeLinecap="round" />
            ))}
            {active != null && crosshairX != null && (
              <g>
                <line x1={crosshairX} y1={PAD.top} x2={crosshairX} y2={PAD.top + plotH} stroke="rgba(235,233,223,.22)" strokeWidth={1} strokeDasharray="3 3" />
                {series.map((seriesEntry) => {
                  const point = seriesEntry.points[active];
                  if (point?.y == null) return null;
                  return <circle key={`dot-${seriesEntry.id}`} cx={xOf(point.t)} cy={yOf(point.y)} r={3} fill={seriesEntry.color} stroke="#0b100e" strokeWidth={1.5} />;
                })}
              </g>
            )}
          </svg>
        )}
        {active != null && crosshairX != null && (
          <div className="dash-tooltip" style={{ left: Math.min(Math.max(crosshairX, 8), width - 150) }}>
            <strong>{ageSeconds === 0 ? "now" : `${ageSeconds}s ago`}</strong>
            {series.map((seriesEntry) => {
              const point = seriesEntry.points[active];
              return (
                <span key={`tip-${seriesEntry.id}`}>
                  <i style={{ background: seriesEntry.color }} />
                  {seriesEntry.label}
                  <em>{point?.y != null ? yFormat(point.y) : "—"}</em>
                </span>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

/** Extracts the x coordinate from an `L<x> <y>` segment string for area closing. */
function segmentX(segmentCommand: string): number {
  const match = segmentCommand.match(/L([-\d.]+)/);
  return match ? Number.parseFloat(match[1]) : 0;
}

/** Convenience hook: keeps a rolling buffer of the last `max` samples and
 *  appends a new one (dropping the oldest). The append function is stable
 *  across renders (it only touches state through the setter), so it is safe to
 *  use as an effect dependency without restarting the effect each render. */
export function useHistory<T>(max: number): [T[], (sample: T) => void] {
  const [history, setHistory] = useState<T[]>([]);
  const append = useCallback((sample: T) => {
    setHistory((current) => {
      const next = current.length >= max ? current.slice(current.length - max + 1) : current.slice();
      next.push(sample);
      return next;
    });
  }, [max]);
  return [history, append];
}

/** One colored slice of a stacked composition bar. Color is carried per segment
 *  so the same category renders identically across hosts. */
export interface CompositionSegment {
  label: string;
  value: number;
  color: string;
}

interface CompositionBarProps {
  title: string;
  badge?: string;
  /** One stacked bar per host, on a shared scale so magnitudes compare. */
  hosts: Array<{ name: string; segments: CompositionSegment[] }>;
  valueFormat: (value: number) => string;
}

/** A point-in-time stacked-bar comparison — a distinct display type from the
 *  time-series chart above. Each host is one full-width bar split into colored
 *  segments; bars share a common scale (the largest host total) so relative
 *  magnitudes are legible at a glance. Empty totals render a placeholder. */
export function CompositionBar({ title, badge = "SPLIT", hosts, valueFormat }: CompositionBarProps) {
  const totals = hosts.map((host) => host.segments.reduce((sum, seg) => sum + Math.max(0, seg.value), 0));
  const scaleMax = Math.max(1, ...totals);
  // Legend categories are identical across hosts; derive from the first host.
  const legend = hosts[0]?.segments ?? [];

  return (
    <div className="dash-chart-card">
      <div className="dash-chart-head">
        <span>{title}</span>
        <em>{badge}</em>
      </div>
      <div className="dash-comp">
        {hosts.length === 0 && <div className="dash-chart-empty">No capture data yet.</div>}
        {hosts.map((host, index) => {
          const total = totals[index];
          return (
            <div className="dash-comp-row" key={host.name}>
              <div className="dash-comp-label" title={host.name}>{host.name}</div>
              <div className="dash-comp-bar">
                {total === 0 ? (
                  <div className="dash-comp-empty">Waiting for capture…</div>
                ) : (
                  host.segments.map((seg) => {
                    const value = Math.max(0, seg.value);
                    if (value === 0) return null;
                    const pct = (value / scaleMax) * 100;
                    return (
                      <div
                        key={seg.label}
                        className="dash-comp-seg"
                        style={{ width: `${pct}%`, background: seg.color }}
                        title={`${seg.label}: ${valueFormat(value)}`}
                      >
                        {pct > 14 && <span>{valueFormat(value)}</span>}
                      </div>
                    );
                  })
                )}
              </div>
              <div className="dash-comp-total">{valueFormat(total)}</div>
            </div>
          );
        })}
        {legend.length > 0 && (
          <div className="dash-comp-legend">
            {legend.map((seg) => (
              <span key={seg.label}>
                <i style={{ background: seg.color }} />
                {seg.label}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

type Severity = "healthy" | "watch" | "degraded" | "critical";

interface SeverityMeta {
  color: string;
  label: string;
  /** 1..4 — drives the gauge fill width so coarser bands still read. */
  tier: number;
}

const SEVERITY_META: Record<Severity, SeverityMeta> = {
  healthy: { color: "#a9e5c8", label: "Healthy", tier: 1 },
  watch: { color: "#e0b056", label: "Watch", tier: 2 },
  degraded: { color: "#ff8e5a", label: "Degraded", tier: 3 },
  critical: { color: "#ff5a3a", label: "Critical", tier: 4 },
};

/** Maps a 0..1 drop fraction to a coarse severity band. Thresholds are
 *  deliberately conservative: even 0.1% of frames dropped to backpressure on a
 *  LAN input stream is worth attention, and 5% is a degraded experience. */
function severityFor(fraction: number): Severity {
  if (fraction >= 0.05) return "critical";
  if (fraction >= 0.01) return "degraded";
  if (fraction >= 0.001) return "watch";
  return "healthy";
}

interface HealthMeterProps {
  title: string;
  badge?: string;
  /** One gauge row per host. `fraction` is clamped to 0..1. */
  hosts: Array<{ name: string; fraction: number; detail: string }>;
}

/** A status gauge — a fourth display type alongside line charts, tables, and
 *  stacked bars. Each host's drop rate maps to a severity band whose color and
 *  fill width convey health at a glance; the raw percentage and a short
 *  detail (drops vs. frames) anchor the visual to real counts. */
export function HealthMeter({ title, badge = "HEALTH", hosts }: HealthMeterProps) {
  return (
    <div className="dash-chart-card">
      <div className="dash-chart-head">
        <span>{title}</span>
        <em>{badge}</em>
      </div>
      <div className="dash-health">
        {hosts.length === 0 && <div className="dash-chart-empty">No session telemetry yet.</div>}
        {hosts.map((host) => {
          const fraction = Math.max(0, Math.min(1, host.fraction));
          const meta = SEVERITY_META[severityFor(fraction)];
          const pct = fraction * 100;
          const pctText = pct < 0.01 ? pct.toFixed(4) : pct < 1 ? pct.toFixed(3) : pct.toFixed(2);
          return (
            <div className="dash-health-row" key={host.name}>
              <div className="dash-health-label" title={host.name}>{host.name}</div>
              <div className="dash-health-meter" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Number(pct.toFixed(3))} aria-label={`${host.name} drop rate`}>
                <div className="dash-health-fill" style={{ width: `${(meta.tier / 4) * 100}%`, background: meta.color }} />
                {[1, 2, 3, 4].map((band) => (
                  <span key={band} className="dash-health-tick" aria-hidden="true" />
                ))}
              </div>
              <div className="dash-health-readout">
                <strong style={{ color: meta.color }}>{pctText}%</strong>
                <span style={{ color: meta.color }}>{meta.label}</span>
              </div>
              <div className="dash-health-detail">{host.detail}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
