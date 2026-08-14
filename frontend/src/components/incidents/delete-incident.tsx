"use client";

/**
 * Deleting an incident.
 *
 * Irreversible, and it takes more with it than the row: the investigation
 * notes and every AI report version go too, while the linked anomalies survive
 * and return to the unlinked pool. The dialog says all of that plainly, because
 * an analyst deciding whether to delete needs to know what they are about to
 * lose, not just that something will be lost.
 *
 * Confirmation is by typing the incident reference. A single "are you sure"
 * button is dismissed reflexively; typing INC-1897 requires having read which
 * incident is about to go, which is exactly the mistake being guarded against.
 *
 * Admin only, mirroring the endpoint. The audit trail records who did it and
 * what the incident was called, and that record outlives the incident.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  Field,
  FormError,
  Modal,
  SecondaryButton,
  inputClass,
} from "@/components/ui/modal";
import { Spinner } from "@/components/ui/states";
import { ApiError, apiFetch } from "@/lib/api-client";
import type { Incident } from "@/types/api";

export function DeleteIncidentButton({ incident }: { incident: Incident }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const confirmed =
    confirmation.trim().toUpperCase() === incident.reference.toUpperCase();

  async function remove() {
    if (!confirmed) return;
    setDeleting(true);
    setError(null);
    try {
      // 204 No Content; the fetch wrapper returns undefined rather than
      // trying to parse an empty body.
      await apiFetch<void>(`/incidents/${incident.id}`, { method: "DELETE" });
      close();
      // Back to the queue -- this incident's page no longer exists.
      router.replace("/incidents");
      // The list is client-fetched, so ask for it again rather than letting
      // the router serve the copy it rendered before the deletion.
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : "The incident was not deleted.",
      );
      setDeleting(false);
    }
  }

  function close() {
    setOpen(false);
    setConfirmation("");
    setError(null);
  }

  const noteCount = incident.notes.length;
  const anomalyCount = incident.anomalies.length;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="rounded-lg border border-rose-500/40 px-3 py-1.5 text-sm text-rose-300 transition-colors hover:bg-rose-500/10"
      >
        Delete
      </button>

      <Modal
        open={open}
        onClose={close}
        title={`Delete ${incident.reference}`}
        description="This cannot be undone."
      >
        <div className="space-y-4">
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-3 text-sm text-rose-200">
            <p className="font-medium">{incident.title}</p>
            <ul className="mt-2 space-y-1 text-xs">
              <li>
                · The incident record and{" "}
                {noteCount === 0
                  ? "its (empty) investigation log"
                  : `${noteCount} investigation note${noteCount === 1 ? "" : "s"}`}{" "}
                will be destroyed.
              </li>
              <li>· Every AI report generated for it will be destroyed.</li>
              <li>
                ·{" "}
                {anomalyCount === 0
                  ? "No anomalies are linked."
                  : `${anomalyCount} linked anomal${anomalyCount === 1 ? "y" : "ies"} will survive, returning to the unlinked pool.`}
              </li>
              <li>· The audit trail keeps a record that you deleted it.</li>
            </ul>
          </div>

          <Field
            label={`Type ${incident.reference} to confirm`}
            htmlFor="delete-confirmation"
          >
            <input
              id="delete-confirmation"
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
              placeholder={incident.reference}
              autoComplete="off"
              className={inputClass}
            />
          </Field>

          <FormError message={error} />

          <div className="flex justify-end gap-2 pt-1">
            <SecondaryButton onClick={close} disabled={deleting}>
              Cancel
            </SecondaryButton>
            <button
              type="button"
              onClick={() => void remove()}
              disabled={!confirmed || deleting}
              className="flex items-center justify-center gap-2 rounded-lg bg-rose-500 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-rose-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {deleting && <Spinner />}
              {deleting ? "Deleting…" : "Delete permanently"}
            </button>
          </div>
        </div>
      </Modal>
    </>
  );
}
