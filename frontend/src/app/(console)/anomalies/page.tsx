"use client";

/**
 * The detection feed.
 *
 * Anomalies are what the detectors argued for; incidents are what an analyst
 * decided about them. This page is the triage queue between the two, so it
 * leads with the score and the detector's own reason rather than with an id.
 */

import { useState } from "react";

import { AnomalyStatusBadge, SeverityBadge, Tag } from "@/components/ui/badge";
import { PageHeader } from "@/components/layout/app-shell";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { query } from "@/lib/api-client";
import { formatDateTime, formatRelative, humanise } from "@/lib/format";
import { useApi } from "@/lib/use-api";
import type { Anomaly, AnomalyStatus, Severity } from "@/types/api";

const PAGE_SIZE = 25;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: AnomalyStatus[] = [
  "new",
  "triaged",
  "investigating",
  "confirmed",
  "false_positive",
  "dismissed",
];

const SELECT_CLASS =
  "rounded-lg border border-soc-border bg-soc-surface px-3 py-1.5 text-sm text-soc-text focus:border-soc-accent focus:outline-none";

export default function AnomaliesPage() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const path = `/anomalies${query({
    severity: severity || undefined,
    status: status || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })}`;

  const { data, error, loading, forbidden, reload } = useApi<Anomaly[]>(path);
  const hasNextPage = (data?.length ?? 0) === PAGE_SIZE;

  return (
    <>
      <PageHeader
        title="Anomalies"
        description="Detections raised by the rule and statistical engines."
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label htmlFor="anomaly-severity" className="sr-only">
          Filter by severity
        </label>
        <select
          id="anomaly-severity"
          value={severity}
          onChange={(event) => {
            setSeverity(event.target.value);
            setPage(0);
          }}
          className={SELECT_CLASS}
        >
          <option value="">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {humanise(value)}
            </option>
          ))}
        </select>

        <label htmlFor="anomaly-status" className="sr-only">
          Filter by triage state
        </label>
        <select
          id="anomaly-status"
          value={status}
          onChange={(event) => {
            setStatus(event.target.value);
            setPage(0);
          }}
          className={SELECT_CLASS}
        >
          <option value="">All triage states</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {humanise(value)}
            </option>
          ))}
        </select>
      </div>

      <Card>
        {loading && <LoadingState rows={6} label="Loading anomalies" />}
        {error && !loading && (
          <ErrorState message={error} forbidden={forbidden} onRetry={reload} />
        )}
        {data && data.length === 0 && (
          <EmptyState
            title={severity || status ? "No matching anomalies" : "No anomalies detected"}
            description={
              severity || status
                ? "Try widening the filters."
                : "Run an analysis over ingested logs to populate the detection feed."
            }
          />
        )}

        {data && data.length > 0 && (
          <ul className="divide-y divide-soc-border">
            {data.map((anomaly) => (
              <li key={anomaly.id}>
                <button
                  type="button"
                  onClick={() =>
                    setExpanded((current) => (current === anomaly.id ? null : anomaly.id))
                  }
                  aria-expanded={expanded === anomaly.id}
                  className="flex w-full items-start justify-between gap-4 px-5 py-3 text-left transition-colors hover:bg-soc-hover"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-soc-text">{anomaly.title}</p>
                    <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-soc-muted">
                      <span className="font-mono">{anomaly.detector}</span>
                      <span aria-hidden>·</span>
                      <span>{humanise(anomaly.anomaly_type)}</span>
                      <span aria-hidden>·</span>
                      <span title={formatDateTime(anomaly.detected_at)}>
                        {formatRelative(anomaly.detected_at)}
                      </span>
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <ScoreBar score={anomaly.score} />
                    <SeverityBadge severity={anomaly.severity} />
                    <AnomalyStatusBadge status={anomaly.status} />
                  </div>
                </button>

                {expanded === anomaly.id && (
                  <div className="space-y-3 border-t border-soc-border bg-soc-base px-5 py-4">
                    {anomaly.description && (
                      <p className="text-sm leading-relaxed text-soc-text">
                        {anomaly.description}
                      </p>
                    )}

                    {anomaly.mitre_techniques.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        {anomaly.mitre_techniques.map((technique) => (
                          <Tag key={technique}>{technique}</Tag>
                        ))}
                      </div>
                    )}

                    {Object.keys(anomaly.evidence).length > 0 && (
                      <div>
                        <p className="mb-1 text-[10px] tracking-wide text-soc-muted uppercase">
                          Evidence
                        </p>
                        <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
                          {Object.entries(anomaly.evidence).map(([key, value]) => (
                            <div key={key} className="flex justify-between gap-3 text-xs">
                              <dt className="text-soc-muted">{humanise(key)}</dt>
                              <dd className="truncate font-mono text-soc-text">
                                {typeof value === "object"
                                  ? JSON.stringify(value)
                                  : String(value)}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}

        {data && (page > 0 || hasNextPage) && (
          <div className="flex items-center justify-between border-t border-soc-border px-5 py-3 text-sm">
            <span className="text-soc-muted">
              Showing {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + data.length}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setPage((value) => Math.max(0, value - 1))}
                disabled={page === 0}
                className="rounded-lg border border-soc-border px-3 py-1.5 transition-colors hover:bg-soc-hover disabled:cursor-not-allowed disabled:opacity-40"
              >
                Previous
              </button>
              <button
                type="button"
                onClick={() => setPage((value) => value + 1)}
                disabled={!hasNextPage}
                className="rounded-lg border border-soc-border px-3 py-1.5 transition-colors hover:bg-soc-hover disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </Card>
    </>
  );
}

/** The 0–1 anomaly score, shown as a bar so a queue can be scanned. */
function ScoreBar({ score }: { score: number }) {
  const percent = Math.round(Math.min(1, Math.max(0, score)) * 100);
  return (
    <span className="hidden items-center gap-2 sm:flex" title={`Score ${score.toFixed(3)}`}>
      <span className="h-1.5 w-16 overflow-hidden rounded-full bg-soc-raised">
        <span
          className="block h-full rounded-full bg-sky-400"
          style={{ width: `${percent}%` }}
        />
      </span>
      <span className="w-8 font-mono text-xs text-soc-muted">{score.toFixed(2)}</span>
    </span>
  );
}
