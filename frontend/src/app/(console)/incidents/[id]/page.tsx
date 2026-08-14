"use client";

/**
 * One incident, in full.
 *
 * The incident record itself is fetched here and passed down; the panels that
 * change it call `reload` rather than patching local state, so what is on
 * screen is always what the server stored. An optimistic update would be a
 * second, quieter copy of the lifecycle rules.
 */

import Link from "next/link";
import { use } from "react";

import { AttachmentsPanel } from "@/components/incidents/attachments-panel";
import { DeleteIncidentButton } from "@/components/incidents/delete-incident";
import { AnomaliesPanel, LogEvidencePanel } from "@/components/incidents/evidence-panel";
import { NotesPanel } from "@/components/incidents/notes-panel";
import { ReportPanel } from "@/components/incidents/report-panel";
import { StatusControl } from "@/components/incidents/status-control";
import { Tag } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { useAuth } from "@/lib/auth";
import { formatDateTime, formatRelative, humanise } from "@/lib/format";
import { canDeleteIncident } from "@/lib/rbac";
import { useApi } from "@/lib/use-api";
import type { Incident } from "@/types/api";

export default function IncidentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  // Route params are a promise in Next 16.
  const { id } = use(params);
  const { data, error, loading, forbidden, reload } = useApi<Incident>(`/incidents/${id}`);
  const { user } = useAuth();

  if (loading) {
    return (
      <Card>
        <LoadingState rows={6} label="Loading incident" />
      </Card>
    );
  }

  if (error || !data) {
    return (
      <>
        <Link href="/incidents" className="text-sm text-sky-400 hover:text-sky-300">
          ← Back to incidents
        </Link>
        <Card className="mt-4">
          <ErrorState
            message={error ?? "This incident could not be loaded."}
            forbidden={forbidden}
            onRetry={reload}
          />
        </Card>
      </>
    );
  }

  return (
    <>
      <Link href="/incidents" className="text-sm text-sky-400 hover:text-sky-300">
        ← Back to incidents
      </Link>

      <header className="mt-4 mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="font-mono text-xs text-soc-muted">{data.reference}</p>
          <h1 className="mt-1 text-xl font-semibold tracking-tight text-soc-text">
            {data.title}
          </h1>
          <p className="mt-2 flex flex-wrap items-center gap-2 text-xs text-soc-muted">
            <span title={formatDateTime(data.detected_at)}>
              Detected {formatRelative(data.detected_at)}
            </span>
            <span aria-hidden>·</span>
            <span>Priority {data.priority.toUpperCase()}</span>
            {data.resolved_at && (
              <>
                <span aria-hidden>·</span>
                <span title={formatDateTime(data.resolved_at)}>
                  Resolved {formatRelative(data.resolved_at)}
                </span>
              </>
            )}
          </p>
        </div>

        <div className="flex flex-col items-end gap-2">
          <StatusControl incident={data} onChanged={reload} />
          {canDeleteIncident(user?.role) && <DeleteIncidentButton incident={data} />}
        </div>
      </header>

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="space-y-6 xl:col-span-2">
          <Card>
            <CardHeader
              title="Incident detail"
              subtitle={humanise(data.attack_type)}
            />
            <CardBody className="space-y-4">
              {data.summary && (
                <p className="text-sm leading-relaxed text-soc-text">{data.summary}</p>
              )}
              {data.description && (
                <p className="text-sm leading-relaxed whitespace-pre-wrap text-soc-muted">
                  {data.description}
                </p>
              )}
              {!data.summary && !data.description && (
                <p className="text-sm text-soc-faint">
                  No description was recorded when this incident was raised.
                </p>
              )}

              {(data.tags.length > 0 || data.mitre_techniques.length > 0) && (
                <div className="flex flex-wrap gap-2 pt-1">
                  {data.tags.map((tag) => (
                    <Tag key={tag}>{tag}</Tag>
                  ))}
                  {data.mitre_techniques.map((technique) => (
                    <Tag key={technique}>{technique}</Tag>
                  ))}
                </div>
              )}
            </CardBody>
          </Card>

          <ReportPanel incidentId={data.id} />
          <AnomaliesPanel anomalies={data.anomalies} />
          <LogEvidencePanel incidentId={data.id} />
        </div>

        <div className="space-y-6">
          <AttachmentsPanel incidentId={data.id} />
          <NotesPanel incidentId={data.id} notes={data.notes} onChanged={reload} />
        </div>
      </div>
    </>
  );
}
