/**
 * Severity and status indicators.
 *
 * Colour is never the only signal: each badge carries its own label, so the
 * scale survives a greyscale display and a red/green colour deficiency. The
 * severity ordering is fixed here so lists and charts sort the same way.
 */

import type { AnomalyStatus, IncidentStatus, LogSourceStatus, Severity } from "@/types/api";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-rose-500/40 bg-rose-500/15 text-rose-300",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  medium: "border-yellow-500/40 bg-yellow-500/15 text-yellow-200",
  low: "border-sky-500/40 bg-sky-500/15 text-sky-300",
  info: "border-slate-500/40 bg-slate-500/15 text-slate-300",
};

/** Chart-facing hex, matching the badge palette in `globals.css`. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#facc15",
  low: "#38bdf8",
  info: "#64748b",
};

const BASE =
  "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium capitalize whitespace-nowrap";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`${BASE} ${SEVERITY_STYLES[severity]}`}>
      <span
        className="h-1.5 w-1.5 rounded-full bg-current"
        aria-hidden
      />
      {severity}
    </span>
  );
}

const INCIDENT_STATUS_STYLES: Record<IncidentStatus, string> = {
  open: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  investigating: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  resolved: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
};

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return <span className={`${BASE} ${INCIDENT_STATUS_STYLES[status]}`}>{status}</span>;
}

const ANOMALY_STATUS_STYLES: Record<AnomalyStatus, string> = {
  new: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  triaged: "border-indigo-500/40 bg-indigo-500/10 text-indigo-300",
  investigating: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  confirmed: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  false_positive: "border-slate-500/40 bg-slate-500/10 text-slate-400",
  dismissed: "border-slate-500/40 bg-slate-500/10 text-slate-400",
};

export function AnomalyStatusBadge({ status }: { status: AnomalyStatus }) {
  return (
    <span className={`${BASE} ${ANOMALY_STATUS_STYLES[status]}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

const SOURCE_STATUS_STYLES: Record<LogSourceStatus, string> = {
  active: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  pending: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  paused: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  error: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  disabled: "border-slate-500/40 bg-slate-500/10 text-slate-400",
};

export function SourceStatusBadge({ status }: { status: LogSourceStatus }) {
  return <span className={`${BASE} ${SOURCE_STATUS_STYLES[status]}`}>{status}</span>;
}

/** A neutral label for tags, attack types and detector names. */
export function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center rounded-md border border-soc-border bg-soc-raised px-2 py-0.5 text-xs text-soc-muted">
      {children}
    </span>
  );
}
