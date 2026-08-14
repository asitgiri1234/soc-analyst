"use client";

/**
 * Running the detectors, and turning what they found into an investigation.
 *
 * These are the two steps that used to require curl, and their absence is what
 * made the console a viewer rather than a tool: events could be ingested and
 * anomalies could be read, but nothing in between could be *done*.
 *
 * Detection is analyst-and-above, matching the endpoint. The window defaults
 * wide because the common case here is "score everything I just uploaded",
 * and log files carry their own timestamps -- often older than the moment they
 * were ingested.
 */

import { useRouter } from "next/navigation";
import { useRef, useState, type FormEvent } from "react";

import { ATTACHMENT_ACCEPT } from "@/components/incidents/attachments-panel";

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
import { formatNumber, humanise } from "@/lib/format";
import type {
  AnalyzeResponse,
  AttackType,
  Incident,
  Severity,
} from "@/types/api";

/** Wide enough to cover logs whose events predate their upload. */
const WIDE_WINDOW_START = "2020-01-01T00:00:00Z";

export function RunDetectionButton({ onComplete }: { onComplete: () => void }) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const response = await apiFetch<AnalyzeResponse>("/detection/analyze", {
        method: "POST",
        body: { window_start: WIDE_WINDOW_START, persist: true },
      });
      setResult(response);
      onComplete();
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : "The detection run failed.",
      );
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-2">
      <PrimaryButton onClick={() => void run()} disabled={running}>
        {running && <Spinner />}
        {running ? "Analysing…" : "Run detection"}
      </PrimaryButton>

      {error && <p className="text-sm text-rose-300">{error}</p>}

      {result && (
        <p className="text-xs text-soc-muted">
          Analysed {formatNumber(result.summary.entries_analysed)} events ·{" "}
          {formatNumber(result.summary.findings)} finding
          {result.summary.findings === 1 ? "" : "s"} ·{" "}
          {formatNumber(result.summary.persisted)} new
          {result.summary.duplicates_skipped > 0 &&
            ` · ${formatNumber(result.summary.duplicates_skipped)} already recorded`}
        </p>
      )}
    </div>
  );
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const ATTACK_TYPES: AttackType[] = [
  "brute_force",
  "credential_access",
  "privilege_escalation",
  "lateral_movement",
  "malware",
  "ransomware",
  "phishing",
  "data_exfiltration",
  "denial_of_service",
  "reconnaissance",
  "insider_threat",
  "policy_violation",
  "misconfiguration",
  "unknown",
  "other",
];

/**
 * Raise an incident from the selected anomalies.
 *
 * The selection is carried in rather than re-chosen here: an analyst has
 * already decided which detections belong together by ticking them, and asking
 * again in a dialog would be asking them to repeat themselves.
 */
export function RaiseIncidentModal({
  open,
  anomalyIds,
  suggestedTitle,
  onClose,
}: {
  open: boolean;
  anomalyIds: string[];
  suggestedTitle: string;
  onClose: () => void;
}) {
  const router = useRouter();
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<Severity>("high");
  const [attackType, setAttackType] = useState<AttackType>("unknown");
  const [summary, setSummary] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const effectiveTitle = title.trim() || suggestedTitle;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const incident = await apiFetch<Incident>("/incidents", {
        method: "POST",
        body: {
          title: effectiveTitle,
          summary: summary.trim() || null,
          severity,
          attack_type: attackType,
          anomaly_ids: anomalyIds,
        },
      });

      // The attachment needs an incident to hang off, so it is a second call.
      // A failure here must not lose the incident that was just created: the
      // analyst is told, and lands on the incident to retry from its panel.
      const file = fileRef.current?.files?.[0];
      if (file) {
        const form = new FormData();
        form.append("file", file);
        try {
          await apiFetch(`/incidents/${incident.id}/attachments`, {
            method: "POST",
            body: form,
          });
        } catch (caught) {
          setError(
            caught instanceof ApiError
              ? `Incident created, but the file was not attached: ${caught.message}`
              : "Incident created, but the file was not attached.",
          );
          setSaving(false);
          router.push(`/incidents/${incident.id}`);
          return;
        }
      }

      onClose();
      // Straight to the incident, where the AI analysis can be generated.
      router.push(`/incidents/${incident.id}`);
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : "The incident was not created.",
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Raise an incident"
      description={`${anomalyIds.length} anomal${anomalyIds.length === 1 ? "y" : "ies"} will be linked as evidence.`}
    >
      <form onSubmit={submit} className="space-y-4">
        <Field label="Title" htmlFor="incident-title">
          <input
            id="incident-title"
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            placeholder={suggestedTitle}
            minLength={3}
            maxLength={255}
            className={inputClass}
          />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Severity" htmlFor="incident-severity">
            <select
              id="incident-severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value as Severity)}
              className={inputClass}
            >
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {humanise(value)}
                </option>
              ))}
            </select>
          </Field>

          <Field label="Attack type" htmlFor="incident-attack-type">
            <select
              id="incident-attack-type"
              value={attackType}
              onChange={(event) => setAttackType(event.target.value as AttackType)}
              className={inputClass}
            >
              {ATTACK_TYPES.map((value) => (
                <option key={value} value={value}>
                  {humanise(value)}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <Field
          label="Summary"
          htmlFor="incident-summary"
          hint="Optional. The AI analysis reads this alongside the linked evidence."
        >
          <textarea
            id="incident-summary"
            value={summary}
            onChange={(event) => setSummary(event.target.value)}
            rows={3}
            maxLength={4000}
            className={`${inputClass} resize-y`}
          />
        </Field>

        <Field
          label="Attach a file"
          htmlFor="incident-attachment"
          hint="Optional. A text document up to 2 MB — an advisory, an export, a colleague's note. The AI analysis reads it alongside the log evidence."
        >
          <input
            id="incident-attachment"
            ref={fileRef}
            type="file"
            accept={ATTACHMENT_ACCEPT}
            className="w-full rounded-lg border border-soc-border bg-soc-base px-3 py-2 text-sm text-soc-muted file:mr-3 file:rounded-md file:border-0 file:bg-soc-raised file:px-3 file:py-1 file:text-sm file:text-soc-text"
          />
        </Field>

        <FormError message={error} />

        <div className="flex justify-end gap-2 pt-1">
          <SecondaryButton onClick={onClose} disabled={saving}>
            Cancel
          </SecondaryButton>
          <PrimaryButton
            type="submit"
            disabled={saving || effectiveTitle.trim().length < 3}
          >
            {saving && <Spinner />}
            Raise incident
          </PrimaryButton>
        </div>
      </form>
    </Modal>
  );
}
