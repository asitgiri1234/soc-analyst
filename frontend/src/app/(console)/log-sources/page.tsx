"use client";

/**
 * Collector health.
 *
 * The number that matters on this page is `last_ingested_at`. A source that is
 * enabled and silent is the failure mode that hides an attack: the console
 * looks calm because nothing is arriving, not because nothing is happening. So
 * a stale source is called out rather than shown as merely "active".
 */

import { useState } from "react";

import { PageHeader } from "@/components/layout/app-shell";
import { AddSourceModal, UploadModal } from "@/components/log-sources/ingest-panel";
import { SourceStatusBadge, Tag } from "@/components/ui/badge";
import { Card, CardHeader } from "@/components/ui/card";
import { PrimaryButton, SecondaryButton } from "@/components/ui/modal";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { useAuth } from "@/lib/auth";
import { formatDateTime, formatNumber, formatRelative, humanise } from "@/lib/format";
import { canInvestigate } from "@/lib/rbac";
import { useApi } from "@/lib/use-api";
import type { LogSource } from "@/types/api";

/** Treated as stale after a day without a delivery. */
const STALE_AFTER_MS = 24 * 60 * 60 * 1000;

function isStale(source: LogSource): boolean {
  if (!source.is_enabled) return false;
  if (!source.last_ingested_at) return true;
  return Date.now() - new Date(source.last_ingested_at).getTime() > STALE_AFTER_MS;
}

export default function LogSourcesPage() {
  const { data, error, loading, forbidden, reload } =
    useApi<LogSource[]>("/log-sources?limit=100");
  const { user } = useAuth();
  const mayIngest = canInvestigate(user?.role);

  const [addOpen, setAddOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);

  const stale = data?.filter(isStale) ?? [];

  return (
    <>
      <PageHeader
        title="Log sources"
        description="Collectors feeding the detection pipeline."
        actions={
          mayIngest && (
            <div className="flex gap-2">
              <SecondaryButton onClick={() => setAddOpen(true)}>
                Add source
              </SecondaryButton>
              <PrimaryButton onClick={() => setUploadOpen(true)}>
                Upload logs
              </PrimaryButton>
            </div>
          )
        }
      />

      <AddSourceModal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onCreated={reload}
      />
      <UploadModal
        open={uploadOpen}
        sources={data ?? []}
        onClose={() => setUploadOpen(false)}
        onIngested={reload}
      />

      {stale.length > 0 && (
        <div className="mb-4 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3">
          <p className="text-sm text-amber-200">
            <span className="font-medium">{stale.length} source</span>
            {stale.length === 1 ? " has" : "s have"} not delivered events in the last 24
            hours. A silent collector looks the same as a quiet network.
          </p>
        </div>
      )}

      <Card>
        <CardHeader
          title="Registered sources"
          subtitle={data ? `${data.length} configured` : undefined}
        />

        {loading && <LoadingState rows={5} label="Loading log sources" />}
        {error && !loading && (
          <ErrorState message={error} forbidden={forbidden} onRetry={reload} />
        )}
        {data && data.length === 0 && (
          <EmptyState
            title="No log sources"
            description="Register a source and upload a CSV or JSON log file to start ingesting events."
            action={
              mayIngest && (
                <PrimaryButton onClick={() => setAddOpen(true)}>
                  Register a source
                </PrimaryButton>
              )
            }
          />
        )}

        {data && data.length > 0 && (
          <ul className="divide-y divide-soc-border">
            {data.map((source) => (
              <li key={source.id} className="px-5 py-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="text-sm font-medium text-soc-text">{source.name}</p>
                      <SourceStatusBadge status={source.status} />
                      {isStale(source) && (
                        <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">
                          stale
                        </span>
                      )}
                      {!source.is_enabled && <Tag>disabled</Tag>}
                    </div>

                    <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-soc-muted">
                      <span>{humanise(source.source_type)}</span>
                      {source.vendor && (
                        <>
                          <span aria-hidden>·</span>
                          <span>{source.vendor}</span>
                        </>
                      )}
                      {source.hostname && (
                        <>
                          <span aria-hidden>·</span>
                          <span className="font-mono">{source.hostname}</span>
                        </>
                      )}
                    </p>

                    {source.description && (
                      <p className="mt-1 text-xs text-soc-faint">{source.description}</p>
                    )}

                    {source.last_error && (
                      <p className="mt-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-xs text-rose-300">
                        {source.last_error}
                      </p>
                    )}
                  </div>

                  <div className="text-right">
                    <p className="text-lg font-semibold tabular-nums text-soc-text">
                      {formatNumber(source.events_ingested)}
                    </p>
                    <p className="text-[10px] tracking-wide text-soc-muted uppercase">
                      events
                    </p>
                    <p
                      className="mt-1 text-xs text-soc-faint"
                      title={formatDateTime(source.last_ingested_at)}
                    >
                      {source.last_ingested_at
                        ? `Last ${formatRelative(source.last_ingested_at)}`
                        : "Never ingested"}
                    </p>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
