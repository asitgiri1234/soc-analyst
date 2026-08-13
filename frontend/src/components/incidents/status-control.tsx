"use client";

/**
 * Status and severity, for analysts.
 *
 * The lifecycle rules -- when `resolved_at` is stamped, when reopening clears
 * it -- live in the backend and are not restated here. This control sends the
 * new value and re-reads the incident; the server decides what that transition
 * means, so there is one implementation of the rule rather than two that can
 * disagree.
 *
 * Viewers see the current state as static text.
 */

import { useState } from "react";

import { IncidentStatusBadge, SeverityBadge } from "@/components/ui/badge";
import { Spinner } from "@/components/ui/states";
import { ApiError, apiFetch } from "@/lib/api-client";
import { useAuth } from "@/lib/auth";
import { humanise } from "@/lib/format";
import { canInvestigate } from "@/lib/rbac";
import type { Incident, IncidentStatus, Severity } from "@/types/api";

const STATUSES: IncidentStatus[] = ["open", "investigating", "resolved"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function StatusControl({
  incident,
  onChanged,
}: {
  incident: Incident;
  onChanged: () => void;
}) {
  const { user } = useAuth();
  const mayEdit = canInvestigate(user?.role);

  const [saving, setSaving] = useState<"status" | "severity" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function patch(field: "status" | "severity", value: string) {
    setSaving(field);
    setError(null);
    try {
      await apiFetch<Incident>(`/incidents/${incident.id}`, {
        method: "PATCH",
        body: { [field]: value },
      });
      onChanged();
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : "The change could not be saved.",
      );
    } finally {
      setSaving(null);
    }
  }

  if (!mayEdit) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={incident.severity} />
        <IncidentStatusBadge status={incident.status} />
      </div>
    );
  }

  const selectClass =
    "rounded-lg border border-soc-border bg-soc-surface px-3 py-1.5 text-sm text-soc-text focus:border-soc-accent focus:outline-none disabled:opacity-50";

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="incident-severity" className="sr-only">
          Severity
        </label>
        <select
          id="incident-severity"
          value={incident.severity}
          disabled={saving !== null}
          onChange={(event) => void patch("severity", event.target.value)}
          className={selectClass}
        >
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {humanise(value)}
            </option>
          ))}
        </select>

        <label htmlFor="incident-status" className="sr-only">
          Status
        </label>
        <select
          id="incident-status"
          value={incident.status}
          disabled={saving !== null}
          onChange={(event) => void patch("status", event.target.value)}
          className={selectClass}
        >
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {humanise(value)}
            </option>
          ))}
        </select>

        {saving && <Spinner className="h-4 w-4 text-soc-muted" />}
      </div>

      {error && (
        <p role="alert" className="text-sm text-rose-300">
          {error}
        </p>
      )}
    </div>
  );
}
