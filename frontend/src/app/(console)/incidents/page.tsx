"use client";

/**
 * The incident queue.
 *
 * Filtering and paging are query parameters on the API, not array operations
 * here: the backend already ranks and limits, and re-filtering a page in the
 * browser would silently show "the criticals among the newest fifty" while
 * labelling it "the criticals".
 */

import Link from "next/link";
import { useState } from "react";

import { PageHeader } from "@/components/layout/app-shell";
import { IncidentStatusBadge, SeverityBadge, Tag } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { formatDateTime, formatRelative, humanise } from "@/lib/format";
import { query } from "@/lib/api-client";
import { useApi } from "@/lib/use-api";
import type { IncidentStatus, IncidentSummary, Severity } from "@/types/api";

const PAGE_SIZE = 25;

const STATUSES: IncidentStatus[] = ["open", "investigating", "resolved"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SELECT_CLASS =
  "rounded-lg border border-soc-border bg-soc-surface px-3 py-1.5 text-sm text-soc-text focus:border-soc-accent focus:outline-none";

export default function IncidentsPage() {
  const [status, setStatus] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [page, setPage] = useState(0);

  const path = `/incidents${query({
    status: status || undefined,
    severity: severity || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })}`;

  const { data, error, loading, forbidden, reload } = useApi<IncidentSummary[]>(path);

  // The list endpoint returns an array, not a total. A full page means there
  // may be another; it is honest about what it knows.
  const hasNextPage = (data?.length ?? 0) === PAGE_SIZE;

  function changeFilter(setter: (value: string) => void) {
    return (value: string) => {
      setter(value);
      setPage(0);
    };
  }

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Investigations raised from detected anomalies."
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="sr-only" htmlFor="status-filter">
          Filter by status
        </label>
        <select
          id="status-filter"
          value={status}
          onChange={(event) => changeFilter(setStatus)(event.target.value)}
          className={SELECT_CLASS}
        >
          <option value="">All statuses</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {humanise(value)}
            </option>
          ))}
        </select>

        <label className="sr-only" htmlFor="severity-filter">
          Filter by severity
        </label>
        <select
          id="severity-filter"
          value={severity}
          onChange={(event) => changeFilter(setSeverity)(event.target.value)}
          className={SELECT_CLASS}
        >
          <option value="">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {humanise(value)}
            </option>
          ))}
        </select>

        {(status || severity) && (
          <button
            type="button"
            onClick={() => {
              setStatus("");
              setSeverity("");
              setPage(0);
            }}
            className="text-sm text-soc-muted hover:text-soc-text"
          >
            Clear filters
          </button>
        )}
      </div>

      <Card>
        {loading && <LoadingState rows={6} label="Loading incidents" />}

        {error && !loading && (
          <ErrorState message={error} forbidden={forbidden} onRetry={reload} />
        )}

        {data && data.length === 0 && (
          <EmptyState
            title={status || severity ? "No matching incidents" : "No incidents"}
            description={
              status || severity
                ? "No incidents match these filters. Try widening them."
                : "Incidents appear here once an analyst raises one from a detected anomaly."
            }
          />
        )}

        {data && data.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[52rem] text-left text-sm">
              <thead className="border-b border-soc-border text-xs tracking-wide text-soc-muted uppercase">
                <tr>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Reference
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Title
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Severity
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Status
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Attack type
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Detected
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {data.map((incident) => (
                  <tr key={incident.id} className="transition-colors hover:bg-soc-hover">
                    <td className="px-5 py-3 font-mono text-xs text-soc-muted">
                      <Link
                        href={`/incidents/${incident.id}`}
                        className="hover:text-sky-300"
                      >
                        {incident.reference}
                      </Link>
                    </td>
                    <td className="max-w-md px-5 py-3">
                      <Link
                        href={`/incidents/${incident.id}`}
                        className="block truncate font-medium text-soc-text hover:text-sky-300"
                      >
                        {incident.title}
                      </Link>
                    </td>
                    <td className="px-5 py-3">
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className="px-5 py-3">
                      <IncidentStatusBadge status={incident.status} />
                    </td>
                    <td className="px-5 py-3">
                      <Tag>{humanise(incident.attack_type)}</Tag>
                    </td>
                    <td
                      className="px-5 py-3 whitespace-nowrap text-soc-muted"
                      title={formatDateTime(incident.detected_at)}
                    >
                      {formatRelative(incident.detected_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
