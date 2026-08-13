"use client";

/**
 * The SOC overview.
 *
 * Every number here is counted by the database over the whole table, not
 * tallied from a page of rows in the browser: see `app/api/v1/endpoints/
 * dashboard.py`. The page's job is to arrange them, not to compute them.
 */

import Link from "next/link";
import { useMemo } from "react";

import { Donut, SeverityBars, TimeSeries } from "@/components/charts/charts";
import { PageHeader } from "@/components/layout/app-shell";
import { IncidentStatusBadge, SeverityBadge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader, StatCard } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { formatNumber, formatRelative, humanise } from "@/lib/format";
import { useApi } from "@/lib/use-api";
import type { CountByDay, DashboardStats, IncidentSummary } from "@/types/api";

const WINDOW_DAYS = 30;

/**
 * Fill the gaps in a sparse day series.
 *
 * The API returns only days that had incidents. Plotting those alone would draw
 * a straight line between two spikes a fortnight apart and imply activity that
 * never happened.
 */
function densify(points: CountByDay[], days: number): CountByDay[] {
  const counts = new Map(points.map((point) => [point.day, point.count]));
  const series: CountByDay[] = [];
  const today = new Date();

  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const date = new Date(today);
    date.setUTCDate(date.getUTCDate() - offset);
    const key = date.toISOString().slice(0, 10);
    series.push({ day: key, count: counts.get(key) ?? 0 });
  }
  return series;
}

export default function DashboardPage() {
  const stats = useApi<DashboardStats>(`/dashboard/stats?days=${WINDOW_DAYS}`);
  const recent = useApi<IncidentSummary[]>("/incidents?limit=6");

  const series = useMemo(
    () => (stats.data ? densify(stats.data.incidents_over_time, WINDOW_DAYS) : []),
    [stats.data],
  );

  return (
    <>
      <PageHeader
        title="Security overview"
        description={`Detection and response activity across the estate, last ${WINDOW_DAYS} days.`}
      />

      {stats.loading && <LoadingState rows={3} label="Loading overview" />}

      {stats.error && !stats.loading && (
        <Card>
          <ErrorState
            message={stats.error}
            forbidden={stats.forbidden}
            onRetry={stats.reload}
          />
        </Card>
      )}

      {stats.data && (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Open incidents"
              value={formatNumber(stats.data.incidents_open)}
              hint={`${formatNumber(stats.data.incidents_total)} total recorded`}
              tone={stats.data.incidents_open > 0 ? "danger" : "ok"}
            />
            <StatCard
              label="Investigating"
              value={formatNumber(stats.data.incidents_investigating)}
              hint={`${formatNumber(stats.data.incidents_resolved)} resolved`}
              tone={stats.data.incidents_investigating > 0 ? "warn" : "neutral"}
            />
            <StatCard
              label="Anomalies"
              value={formatNumber(stats.data.anomalies_total)}
              hint="Detected across all sources"
            />
            <StatCard
              label="Events ingested"
              value={formatNumber(stats.data.log_entries_total)}
              hint={`${formatNumber(stats.data.log_sources_total)} log source(s)`}
            />
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader
                title="Incidents over time"
                subtitle={`Opened per day, last ${WINDOW_DAYS} days`}
              />
              <CardBody>
                <TimeSeries data={series} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="Incidents by severity" subtitle="All recorded incidents" />
              <CardBody>
                <SeverityBars data={stats.data.incidents_by_severity} />
              </CardBody>
            </Card>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader
                title="Anomaly distribution"
                subtitle="By detection family"
              />
              <CardBody>
                <Donut data={stats.data.anomalies_by_type} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="Recent incidents"
                subtitle="Newest first"
                action={
                  <Link
                    href="/incidents"
                    className="text-xs text-sky-400 hover:text-sky-300"
                  >
                    View all →
                  </Link>
                }
              />
              {recent.loading && <LoadingState rows={4} />}
              {recent.error && !recent.loading && (
                <ErrorState
                  message={recent.error}
                  forbidden={recent.forbidden}
                  onRetry={recent.reload}
                />
              )}
              {recent.data && recent.data.length === 0 && (
                <EmptyState
                  title="No incidents yet"
                  description="Incidents appear here once an analyst raises one from a detected anomaly."
                />
              )}
              {recent.data && recent.data.length > 0 && (
                <ul className="divide-y divide-soc-border">
                  {recent.data.map((incident) => (
                    <li key={incident.id}>
                      <Link
                        href={`/incidents/${incident.id}`}
                        className="flex items-center justify-between gap-3 px-5 py-3 transition-colors hover:bg-soc-hover"
                      >
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-soc-text">
                            {incident.title}
                          </p>
                          <p className="mt-0.5 text-xs text-soc-muted">
                            {incident.reference} · {humanise(incident.attack_type)} ·{" "}
                            {formatRelative(incident.detected_at)}
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          <SeverityBadge severity={incident.severity} />
                          <IncidentStatusBadge status={incident.status} />
                        </div>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
