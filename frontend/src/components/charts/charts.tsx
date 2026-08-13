"use client";

/**
 * The three overview charts, drawn as plain SVG.
 *
 * No charting library: these are a stacked bar, a donut and an area line, and a
 * dependency that ships a layout engine and a tooltip system to draw them would
 * be more attack surface and more bundle than the job needs. Every one is a
 * pure function of its data, and every one renders its own legend so the chart
 * is readable without hovering.
 *
 * All three treat "no data" as a first-class case rather than drawing an empty
 * axis, because an empty chart and a broken chart look identical otherwise.
 */

import { SEVERITY_COLOR, SEVERITY_ORDER } from "@/components/ui/badge";
import { formatDay, humanise } from "@/lib/format";
import type { CountByDay, CountByKey, Severity } from "@/types/api";

const PALETTE = [
  "#38bdf8",
  "#a78bfa",
  "#34d399",
  "#fbbf24",
  "#fb7185",
  "#22d3ee",
  "#f472b6",
  "#84cc16",
];

function NoData({ message = "No data in this window" }: { message?: string }) {
  return (
    <div className="flex h-40 items-center justify-center text-sm text-soc-faint">
      {message}
    </div>
  );
}

/**
 * Incidents by severity, as a horizontal bar per level.
 *
 * Ordered critical-first and always showing every level, including the ones at
 * zero: the absence of criticals is information, and a chart that hides empty
 * rows makes "none" and "not measured" look the same.
 */
export function SeverityBars({ data }: { data: CountByKey[] }) {
  const counts = new Map(data.map((item) => [item.key, item.count]));
  const max = Math.max(1, ...data.map((item) => item.count));
  const total = data.reduce((sum, item) => sum + item.count, 0);

  if (total === 0) return <NoData message="No incidents recorded" />;

  return (
    <div className="space-y-3">
      {SEVERITY_ORDER.map((severity) => {
        const count = counts.get(severity) ?? 0;
        const width = (count / max) * 100;
        return (
          <div key={severity} className="flex items-center gap-3">
            <span className="w-16 text-xs capitalize text-soc-muted">{severity}</span>
            <div className="h-6 flex-1 overflow-hidden rounded-md bg-soc-raised">
              <div
                className="h-full rounded-md transition-[width] duration-500"
                style={{
                  width: `${width}%`,
                  backgroundColor: SEVERITY_COLOR[severity as Severity],
                  opacity: count === 0 ? 0.15 : 0.85,
                }}
              />
            </div>
            <span className="w-10 text-right text-sm tabular-nums text-soc-text">
              {count}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Incidents over time, as an area chart.
 *
 * Days with no incidents are filled in as zero by the caller; drawing only the
 * days that have rows would compress a quiet week into a single step and make a
 * flat period look like a spike.
 */
export function TimeSeries({ data }: { data: CountByDay[] }) {
  if (data.length === 0) return <NoData />;

  const width = 640;
  const height = 180;
  const padding = { top: 12, right: 8, bottom: 24, left: 28 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  const max = Math.max(1, ...data.map((point) => point.count));
  // A single point has no span to divide by; place it mid-plot.
  const stepX = data.length > 1 ? plotWidth / (data.length - 1) : 0;

  const pointAt = (index: number, count: number) => {
    const x = padding.left + (data.length > 1 ? index * stepX : plotWidth / 2);
    const y = padding.top + plotHeight - (count / max) * plotHeight;
    return [x, y] as const;
  };

  const line = data
    .map((point, index) => {
      const [x, y] = pointAt(index, point.count);
      return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  const [firstX] = pointAt(0, data[0].count);
  const [lastX] = pointAt(data.length - 1, data[data.length - 1].count);
  const baseline = padding.top + plotHeight;
  const area = `${line} L${lastX.toFixed(1)},${baseline} L${firstX.toFixed(1)},${baseline} Z`;

  // Four gridlines is enough to read a value off without becoming a table.
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((fraction) => ({
    value: Math.round(max * fraction),
    y: padding.top + plotHeight - fraction * plotHeight,
  }));

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="h-48 w-full"
      role="img"
      aria-label={`Incidents per day over the last ${data.length} days`}
    >
      <defs>
        <linearGradient id="soc-area" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
        </linearGradient>
      </defs>

      {ticks.map((tick) => (
        <g key={tick.y}>
          <line
            x1={padding.left}
            y1={tick.y}
            x2={width - padding.right}
            y2={tick.y}
            stroke="#22304a"
            strokeWidth="1"
          />
          <text x={4} y={tick.y + 4} fill="#5d6d86" fontSize="10">
            {tick.value}
          </text>
        </g>
      ))}

      <path d={area} fill="url(#soc-area)" />
      <path d={line} fill="none" stroke="#38bdf8" strokeWidth="2" strokeLinejoin="round" />

      {data.map((point, index) => {
        const [x, y] = pointAt(index, point.count);
        return (
          <circle key={point.day} cx={x} cy={y} r="2.5" fill="#38bdf8">
            <title>{`${formatDay(point.day)}: ${point.count}`}</title>
          </circle>
        );
      })}

      {/* Only the ends are labelled; a tick per day is unreadable at 30 days. */}
      <text x={padding.left} y={height - 6} fill="#5d6d86" fontSize="10">
        {formatDay(data[0].day)}
      </text>
      <text
        x={width - padding.right}
        y={height - 6}
        fill="#5d6d86"
        fontSize="10"
        textAnchor="end"
      >
        {formatDay(data[data.length - 1].day)}
      </text>
    </svg>
  );
}

/** Anomaly distribution by detection family, as a donut with a legend. */
export function Donut({ data }: { data: CountByKey[] }) {
  const present = data.filter((item) => item.count > 0);
  const total = present.reduce((sum, item) => sum + item.count, 0);

  if (total === 0) return <NoData message="No anomalies detected" />;

  const radius = 60;
  const thickness = 18;
  const circumference = 2 * Math.PI * radius;

  // Each arc starts where the previous one ended, so the offsets are a running
  // total. Accumulated with `reduce` rather than a mutable counter: the segment
  // list is derived state, and a variable reassigned during render is exactly
  // the thing that goes stale on the next one.
  const segments = present.reduce<
    {
      key: string;
      count: number;
      color: string;
      dash: number;
      offset: number;
      fraction: number;
    }[]
  >((accumulated, item, index) => {
    const fraction = item.count / total;
    const previous = accumulated[accumulated.length - 1];
    const offset = previous ? previous.offset + previous.dash : 0;
    accumulated.push({
      key: item.key,
      count: item.count,
      color: PALETTE[index % PALETTE.length],
      dash: fraction * circumference,
      offset,
      fraction,
    });
    return accumulated;
  }, []);

  return (
    <div className="flex flex-wrap items-center justify-center gap-6">
      <svg viewBox="0 0 160 160" className="h-40 w-40 -rotate-90" role="img" aria-label="Anomaly distribution">
        <circle cx="80" cy="80" r={radius} fill="none" stroke="#172030" strokeWidth={thickness} />
        {segments.map((segment) => (
          <circle
            key={segment.key}
            cx="80"
            cy="80"
            r={radius}
            fill="none"
            stroke={segment.color}
            strokeWidth={thickness}
            strokeDasharray={`${segment.dash} ${circumference - segment.dash}`}
            strokeDashoffset={-segment.offset}
          >
            <title>{`${humanise(segment.key)}: ${segment.count}`}</title>
          </circle>
        ))}
      </svg>

      <ul className="space-y-2 text-sm">
        {segments.map((segment) => (
          <li key={segment.key} className="flex items-center gap-2">
            <span
              className="h-2.5 w-2.5 rounded-sm"
              style={{ backgroundColor: segment.color }}
              aria-hidden
            />
            <span className="text-soc-text">{humanise(segment.key)}</span>
            <span className="tabular-nums text-soc-muted">
              {segment.count} ({Math.round(segment.fraction * 100)}%)
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
