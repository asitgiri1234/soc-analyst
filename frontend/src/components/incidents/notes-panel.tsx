"use client";

/**
 * The investigation log.
 *
 * Notes are append-only, which is the backend's design and the right one: a
 * note records what an analyst believed at a moment during an investigation,
 * and editing that away destroys the account of how a conclusion was reached.
 * Correcting an earlier note means adding one that says so.
 *
 * System notes -- the ones the server writes on a status change -- are marked
 * distinctly, so an automated entry is never mistaken for an analyst's
 * judgement.
 */

import { useState, type FormEvent } from "react";

import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState, Spinner } from "@/components/ui/states";
import { ApiError, apiFetch } from "@/lib/api-client";
import { useAuth } from "@/lib/auth";
import { formatDateTime, formatRelative } from "@/lib/format";
import { canInvestigate } from "@/lib/rbac";
import type { IncidentNote } from "@/types/api";

export function NotesPanel({
  incidentId,
  notes,
  onChanged,
}: {
  incidentId: string;
  notes: IncidentNote[];
  onChanged: () => void;
}) {
  const { user } = useAuth();
  const mayWrite = canInvestigate(user?.role);

  const [body, setBody] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const trimmed = body.trim();
    if (!trimmed) return;

    setSubmitting(true);
    setError(null);
    try {
      await apiFetch(`/incidents/${incidentId}/notes`, {
        method: "POST",
        body: { body: trimmed },
      });
      setBody("");
      onChanged();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The note was not saved.");
    } finally {
      setSubmitting(false);
    }
  }

  const ordered = [...notes].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );

  return (
    <Card>
      <CardHeader
        title="Investigation notes"
        subtitle={`${notes.length} entr${notes.length === 1 ? "y" : "ies"} · append-only`}
      />

      {mayWrite && (
        <CardBody className="border-b border-soc-border">
          <form onSubmit={submit} className="space-y-2">
            <label htmlFor="note-body" className="sr-only">
              Add a note
            </label>
            <textarea
              id="note-body"
              value={body}
              onChange={(event) => setBody(event.target.value)}
              rows={3}
              maxLength={10000}
              placeholder="Record what you checked, what you found, and what you concluded…"
              className="w-full resize-y rounded-lg border border-soc-border bg-soc-base px-3 py-2 text-sm text-soc-text placeholder:text-soc-faint focus:border-soc-accent focus:outline-none"
            />
            {error && (
              <p role="alert" className="text-sm text-rose-300">
                {error}
              </p>
            )}
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={submitting || body.trim().length === 0}
                className="flex items-center gap-2 rounded-lg bg-sky-500 px-3 py-1.5 text-sm font-medium text-slate-950 transition-colors hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting && <Spinner />}
                Add note
              </button>
            </div>
          </form>
        </CardBody>
      )}

      {ordered.length === 0 ? (
        <EmptyState
          title="No notes yet"
          description={
            mayWrite
              ? "Record your findings as you work the incident."
              : "No analyst has recorded findings on this incident."
          }
        />
      ) : (
        <ul className="divide-y divide-soc-border">
          {ordered.map((note) => (
            <li key={note.id} className="px-5 py-3">
              <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                <span className="font-medium text-soc-text">
                  {note.author_username ?? "System"}
                </span>
                {note.is_system && (
                  <span className="rounded border border-soc-border px-1.5 py-0.5 text-[10px] tracking-wide text-soc-faint uppercase">
                    automated
                  </span>
                )}
                <span className="text-soc-faint" title={formatDateTime(note.created_at)}>
                  {formatRelative(note.created_at)}
                </span>
              </div>
              <p className="text-sm leading-relaxed whitespace-pre-wrap text-soc-text">
                {note.body}
              </p>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
