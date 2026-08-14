"use client";

/**
 * Context files attached to an incident.
 *
 * Attachment text is displayed in a `<pre>`, never as markup. A file is a
 * document somebody forwarded, so its content is attacker-influenced in exactly
 * the way a log line is -- the analyst passed it on, they did not write it.
 *
 * The panel says plainly that the model reads these, because that is the point
 * of attaching one and it changes what an analyst chooses to upload.
 */

import { useRef, useState, type FormEvent } from "react";

import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { FormError, PrimaryButton } from "@/components/ui/modal";
import { EmptyState, ErrorState, LoadingState, Spinner } from "@/components/ui/states";
import { ApiError, apiFetch } from "@/lib/api-client";
import { useAuth } from "@/lib/auth";
import { formatDateTime, formatRelative } from "@/lib/format";
import { canInvestigate } from "@/lib/rbac";
import { useApi } from "@/lib/use-api";
import type { IncidentAttachment, IncidentAttachmentDetail } from "@/types/api";

export const ATTACHMENT_ACCEPT =
  ".txt,.log,.md,.csv,.tsv,.json,.jsonl,.ndjson,.yaml,.yml,.xml,.conf,.ini";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function AttachmentsPanel({ incidentId }: { incidentId: string }) {
  const { user } = useAuth();
  const mayEdit = canInvestigate(user?.role);

  const attachments = useApi<IncidentAttachment[]>(
    `/incidents/${incidentId}/attachments`,
  );

  const fileRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) return;

    setUploading(true);
    setError(null);

    const form = new FormData();
    form.append("file", file);

    try {
      await apiFetch<IncidentAttachment>(`/incidents/${incidentId}/attachments`, {
        method: "POST",
        body: form,
      });
      if (fileRef.current) fileRef.current.value = "";
      attachments.reload();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The file was not attached.");
    } finally {
      setUploading(false);
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      await apiFetch<void>(`/incidents/${incidentId}/attachments/${id}`, {
        method: "DELETE",
      });
      if (openId === id) setOpenId(null);
      attachments.reload();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The file was not removed.");
    }
  }

  return (
    <Card>
      <CardHeader
        title="Attachments"
        subtitle="Context files. The AI analysis reads these alongside the log evidence."
      />

      {mayEdit && (
        <CardBody className="border-b border-soc-border">
          <form onSubmit={submit} className="space-y-2">
            <label htmlFor="attachment-file" className="sr-only">
              Attach a file
            </label>
            <input
              id="attachment-file"
              ref={fileRef}
              type="file"
              accept={ATTACHMENT_ACCEPT}
              className="w-full rounded-lg border border-soc-border bg-soc-base px-3 py-2 text-sm text-soc-muted file:mr-3 file:rounded-md file:border-0 file:bg-soc-raised file:px-3 file:py-1 file:text-sm file:text-soc-text"
            />
            <p className="text-xs text-soc-faint">
              Text documents up to 2 MB — advisories, exports, notes from another tool.
            </p>
            <FormError message={error} />
            <div className="flex justify-end">
              <PrimaryButton type="submit" disabled={uploading}>
                {uploading && <Spinner />}
                {uploading ? "Attaching…" : "Attach file"}
              </PrimaryButton>
            </div>
          </form>
        </CardBody>
      )}

      {attachments.loading && <LoadingState rows={2} label="Loading attachments" />}
      {attachments.error && !attachments.loading && (
        <ErrorState
          message={attachments.error}
          forbidden={attachments.forbidden}
          onRetry={attachments.reload}
        />
      )}
      {attachments.data && attachments.data.length === 0 && (
        <EmptyState
          title="No attachments"
          description={
            mayEdit
              ? "Attach an advisory, an export or a colleague's note to give the analysis more to work from."
              : "No context files have been attached to this incident."
          }
        />
      )}

      {attachments.data && attachments.data.length > 0 && (
        <ul className="divide-y divide-soc-border">
          {attachments.data.map((attachment) => (
            <li key={attachment.id}>
              <div className="flex items-start justify-between gap-3 px-5 py-3">
                <button
                  type="button"
                  onClick={() =>
                    setOpenId((current) =>
                      current === attachment.id ? null : attachment.id,
                    )
                  }
                  aria-expanded={openId === attachment.id}
                  className="min-w-0 text-left"
                >
                  <p className="truncate text-sm font-medium text-soc-text hover:text-sky-300">
                    {attachment.filename}
                  </p>
                  <p className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-soc-muted">
                    <span>{formatBytes(attachment.size_bytes)}</span>
                    <span aria-hidden>·</span>
                    <span>{attachment.uploaded_by_username ?? "unknown"}</span>
                    <span aria-hidden>·</span>
                    <span title={formatDateTime(attachment.created_at)}>
                      {formatRelative(attachment.created_at)}
                    </span>
                    {attachment.truncated && (
                      <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-300">
                        truncated
                      </span>
                    )}
                  </p>
                </button>

                {mayEdit && (
                  <button
                    type="button"
                    onClick={() => void remove(attachment.id)}
                    className="shrink-0 rounded-lg px-2 py-1 text-xs text-soc-muted transition-colors hover:bg-rose-500/10 hover:text-rose-300"
                  >
                    Remove
                  </button>
                )}
              </div>

              {openId === attachment.id && (
                <AttachmentBody incidentId={incidentId} attachmentId={attachment.id} />
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** The extracted text, fetched only when opened. */
function AttachmentBody({
  incidentId,
  attachmentId,
}: {
  incidentId: string;
  attachmentId: string;
}) {
  const { data, error, loading, forbidden, reload } = useApi<IncidentAttachmentDetail>(
    `/incidents/${incidentId}/attachments/${attachmentId}`,
  );

  if (loading) return <LoadingState rows={2} label="Loading file" />;
  if (error) return <ErrorState message={error} forbidden={forbidden} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="border-t border-soc-border bg-soc-base px-5 py-3">
      {/*
        Text, never markup. This content came from a file somebody forwarded.
      */}
      <pre className="max-h-80 overflow-auto text-xs leading-relaxed whitespace-pre-wrap text-soc-muted">
        {data.content}
      </pre>
      {data.truncated && (
        <p className="mt-2 text-xs text-amber-300">
          Stored truncated — the analysis saw only this much of the file.
        </p>
      )}
    </div>
  );
}
