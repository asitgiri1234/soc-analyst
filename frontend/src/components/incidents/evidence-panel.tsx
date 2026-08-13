"use client";

/**
 * Related anomalies and the log evidence behind them.
 *
 * The two are one panel because they are one argument: the detector's claim,
 * and the raw events it was made from. An analyst confirming or dismissing an
 * incident needs both in view.
 *
 * Log messages are rendered as text. They are attacker-influenced by
 * definition -- an event message is whatever the remote party caused it to say.
 */

import { useState } from "react";

import { AnomalyStatusBadge, SeverityBadge, Tag } from "@/components/ui/badge";
import { Card, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { formatDateTime, formatRelative, humanise } from "@/lib/format";
import { useApi } from "@/lib/use-api";
import type { Anomaly, LinkedAnomaly, LogEntry } from "@/types/api";

export function AnomaliesPanel({ anomalies }: { anomalies: LinkedAnomaly[] }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  return (
    <Card>
      <CardHeader
        title="Related anomalies"
        subtitle={`${anomalies.length} detection${anomalies.length === 1 ? "" : "s"} linked to this incident`}
      />

      {anomalies.length === 0 ? (
        <EmptyState
          title="No anomalies linked"
          description="This incident was raised without linked detections."
        />
      ) : (
        <ul className="divide-y divide-soc-border">
          {anomalies.map((anomaly) => (
            <li key={anomaly.id}>
              <button
                type="button"
                onClick={() =>
                  setExpandedId((current) => (current === anomaly.id ? null : anomaly.id))
                }
                aria-expanded={expandedId === anomaly.id}
                className="flex w-full items-start justify-between gap-3 px-5 py-3 text-left transition-colors hover:bg-soc-hover"
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium text-soc-text">{anomaly.title}</p>
                  <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-soc-muted">
                    <span>{anomaly.detector}</span>
                    <span aria-hidden>·</span>
                    <span>{humanise(anomaly.anomaly_type)}</span>
                    <span aria-hidden>·</span>
                    <span title={formatDateTime(anomaly.detected_at)}>
                      {formatRelative(anomaly.detected_at)}
                    </span>
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span className="font-mono text-xs text-soc-muted">
                    {anomaly.score.toFixed(2)}
                  </span>
                  <SeverityBadge severity={anomaly.severity} />
                </div>
              </button>

              {expandedId === anomaly.id && <AnomalyDetail anomalyId={anomaly.id} />}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** The full anomaly, fetched only when an analyst opens it. */
function AnomalyDetail({ anomalyId }: { anomalyId: string }) {
  const { data, error, loading, forbidden, reload } = useApi<Anomaly>(
    `/anomalies/${anomalyId}`,
  );

  if (loading) return <LoadingState rows={2} label="Loading detection detail" />;
  if (error) return <ErrorState message={error} forbidden={forbidden} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="space-y-3 border-t border-soc-border bg-soc-base px-5 py-4">
      {data.description && (
        <p className="text-sm leading-relaxed text-soc-text">{data.description}</p>
      )}

      <div className="flex flex-wrap gap-2">
        <AnomalyStatusBadge status={data.status} />
        {data.mitre_techniques.map((technique) => (
          <Tag key={technique}>{technique}</Tag>
        ))}
      </div>

      {Object.keys(data.evidence).length > 0 && (
        <div>
          <p className="mb-1 text-[10px] tracking-wide text-soc-muted uppercase">
            Evidence
          </p>
          <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
            {Object.entries(data.evidence).map(([key, value]) => (
              <div key={key} className="flex justify-between gap-3 text-xs">
                <dt className="text-soc-muted">{humanise(key)}</dt>
                <dd className="truncate font-mono text-soc-text">
                  {typeof value === "object" ? JSON.stringify(value) : String(value)}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

export function LogEvidencePanel({ incidentId }: { incidentId: string }) {
  const { data, error, loading, forbidden, reload } = useApi<LogEntry[]>(
    `/incidents/${incidentId}/evidence?limit=100`,
  );

  return (
    <Card>
      <CardHeader
        title="Log evidence"
        subtitle="The events the linked detections were argued from"
      />

      {loading && <LoadingState rows={5} label="Loading log evidence" />}
      {error && !loading && (
        <ErrorState message={error} forbidden={forbidden} onRetry={reload} />
      )}
      {data && data.length === 0 && (
        <EmptyState
          title="No log evidence"
          description="The linked anomalies do not cite specific log entries."
        />
      )}

      {data && data.length > 0 && (
        <div className="max-h-[28rem] overflow-auto">
          <table className="w-full min-w-[46rem] text-left text-xs">
            <thead className="sticky top-0 border-b border-soc-border bg-soc-surface text-[10px] tracking-wide text-soc-muted uppercase">
              <tr>
                <th scope="col" className="px-5 py-2 font-medium">
                  Time
                </th>
                <th scope="col" className="px-5 py-2 font-medium">
                  Severity
                </th>
                <th scope="col" className="px-5 py-2 font-medium">
                  Source
                </th>
                <th scope="col" className="px-5 py-2 font-medium">
                  User
                </th>
                <th scope="col" className="px-5 py-2 font-medium">
                  Message
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {data.map((entry) => (
                <tr key={entry.id} className="align-top hover:bg-soc-hover">
                  <td
                    className="px-5 py-2 whitespace-nowrap text-soc-muted"
                    title={formatDateTime(entry.event_timestamp)}
                  >
                    {formatRelative(entry.event_timestamp)}
                  </td>
                  <td className="px-5 py-2">
                    <SeverityBadge severity={entry.severity} />
                  </td>
                  <td className="px-5 py-2 font-mono text-soc-muted">
                    {entry.source_ip ?? entry.host ?? "—"}
                  </td>
                  <td className="px-5 py-2 text-soc-muted">{entry.username ?? "—"}</td>
                  <td className="max-w-md px-5 py-2 break-words text-soc-text">
                    {entry.message}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
