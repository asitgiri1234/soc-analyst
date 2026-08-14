"use client";

/**
 * Registering a collector and uploading logs to it.
 *
 * The upload result is the important part of this screen, not the submission.
 * Ingestion is deliberately partial-tolerant -- a file of five thousand events
 * with forty bad rows stores 4,960 and reports the forty -- so the UI has to
 * show *what was rejected and why*, per row. A green tick that hides forty
 * dropped events would misrepresent the state of the evidence.
 */

import { useRef, useState, type FormEvent } from "react";

import {
  Field,
  FormError,
  Modal,
  PrimaryButton,
  SecondaryButton,
  inputClass,
} from "@/components/ui/modal";
import { Spinner } from "@/components/ui/states";
import { ApiError, apiFetch } from "@/lib/api-client";
import { formatNumber } from "@/lib/format";
import type { IngestionJob, LogSource, LogSourceType } from "@/types/api";

const SOURCE_TYPES: LogSourceType[] = [
  "authentication",
  "firewall",
  "endpoint",
  "ids",
  "syslog",
  "application",
  "cloud_trail",
  "network_flow",
  "database",
  "other",
];

const ACCEPTED = ".csv,.json,.jsonl,.ndjson";

export function AddSourceModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (source: LogSource) => void;
}) {
  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState<LogSourceType>("authentication");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const created = await apiFetch<LogSource>("/log-sources", {
        method: "POST",
        body: {
          name: name.trim(),
          source_type: sourceType,
          description: description.trim() || null,
        },
      });
      onCreated(created);
      setName("");
      setDescription("");
      onClose();
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : "The source was not created.",
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Register a log source"
      description="A collector that events will be ingested against."
    >
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name" htmlFor="source-name">
          <input
            id="source-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            minLength={1}
            maxLength={128}
            placeholder="bastion-auth"
            className={inputClass}
          />
        </Field>

        <Field label="Type" htmlFor="source-type">
          <select
            id="source-type"
            value={sourceType}
            onChange={(event) => setSourceType(event.target.value as LogSourceType)}
            className={inputClass}
          >
            {SOURCE_TYPES.map((value) => (
              <option key={value} value={value}>
                {value.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </Field>

        <Field label="Description" htmlFor="source-description" hint="Optional.">
          <input
            id="source-description"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            maxLength={2000}
            placeholder="SSH authentication log from the bastion host"
            className={inputClass}
          />
        </Field>

        <FormError message={error} />

        <div className="flex justify-end gap-2 pt-1">
          <SecondaryButton onClick={onClose} disabled={saving}>
            Cancel
          </SecondaryButton>
          <PrimaryButton type="submit" disabled={saving || name.trim().length === 0}>
            {saving && <Spinner />}
            Register source
          </PrimaryButton>
        </div>
      </form>
    </Modal>
  );
}

export function UploadModal({
  open,
  sources,
  onClose,
  onIngested,
}: {
  open: boolean;
  sources: LogSource[];
  onClose: () => void;
  onIngested: () => void;
}) {
  const [sourceId, setSourceId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<IngestionJob | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const selected = sourceId || sources[0]?.id || "";

  async function submit(event: FormEvent) {
    event.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file || !selected) return;

    setUploading(true);
    setError(null);
    setResult(null);

    const form = new FormData();
    form.append("file", file);

    try {
      const job = await apiFetch<IngestionJob>(`/log-sources/${selected}/ingest`, {
        method: "POST",
        body: form,
      });
      setResult(job);
      onIngested();
    } catch (caught) {
      // A file where every row is malformed answers 422 with a job attached;
      // the message carries the reason, which is what the analyst needs.
      setError(caught instanceof ApiError ? caught.message : "The upload failed.");
    } finally {
      setUploading(false);
    }
  }

  function close() {
    setResult(null);
    setError(null);
    onClose();
  }

  return (
    <Modal
      open={open}
      onClose={close}
      title="Upload logs"
      description="CSV, JSON or NDJSON. Malformed rows are rejected individually."
    >
      {sources.length === 0 ? (
        <p className="text-sm text-soc-muted">
          Register a log source first — events are always ingested against one.
        </p>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <Field label="Log source" htmlFor="upload-source">
            <select
              id="upload-source"
              value={selected}
              onChange={(event) => setSourceId(event.target.value)}
              className={inputClass}
            >
              {sources.map((source) => (
                <option key={source.id} value={source.id}>
                  {source.name}
                </option>
              ))}
            </select>
          </Field>

          <Field
            label="File"
            htmlFor="upload-file"
            hint="Up to 10 MB, UTF-8. A timestamp column is required; other fields are matched against common vendor spellings."
          >
            <input
              id="upload-file"
              ref={fileRef}
              type="file"
              accept={ACCEPTED}
              required
              className="w-full rounded-lg border border-soc-border bg-soc-base px-3 py-2 text-sm text-soc-muted file:mr-3 file:rounded-md file:border-0 file:bg-soc-raised file:px-3 file:py-1 file:text-sm file:text-soc-text"
            />
          </Field>

          <FormError message={error} />
          {result && <IngestionResult job={result} />}

          <div className="flex justify-end gap-2 pt-1">
            <SecondaryButton onClick={close} disabled={uploading}>
              {result ? "Done" : "Cancel"}
            </SecondaryButton>
            <PrimaryButton type="submit" disabled={uploading}>
              {uploading && <Spinner />}
              {uploading ? "Ingesting…" : "Upload"}
            </PrimaryButton>
          </div>
        </form>
      )}
    </Modal>
  );
}

const STATUS_TONE: Record<string, string> = {
  completed: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  partial: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  failed: "border-rose-500/40 bg-rose-500/10 text-rose-300",
};

/** What was stored, what was not, and why. */
function IngestionResult({ job }: { job: IngestionJob }) {
  const tone = STATUS_TONE[job.status] ?? "border-soc-border bg-soc-raised text-soc-text";

  return (
    <div className={`space-y-3 rounded-lg border px-3 py-3 ${tone}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium capitalize">{job.status}</span>
        <span className="text-xs">
          {formatNumber(job.accepted_records)} stored · {formatNumber(job.rejected_records)}{" "}
          rejected
        </span>
      </div>

      {job.errors.length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] tracking-wide uppercase opacity-80">
            Rejected rows
          </p>
          <ul className="max-h-40 space-y-1 overflow-auto">
            {job.errors.map((rowError, index) => (
              <li key={index} className="font-mono text-xs opacity-90">
                line {rowError.line}
                {rowError.field ? ` · ${rowError.field}` : ""} — {rowError.reason}
              </li>
            ))}
          </ul>
          {job.rejected_records > job.errors.length && (
            <p className="text-xs opacity-75">
              …and {formatNumber(job.rejected_records - job.errors.length)} more.
            </p>
          )}
        </div>
      )}

      {job.error_detail && <p className="text-xs">{job.error_detail}</p>}

      {job.accepted_records > 0 && (
        <p className="text-xs opacity-90">
          Run detection to score the new events.
        </p>
      )}
    </div>
  );
}
