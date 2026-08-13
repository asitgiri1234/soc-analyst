"use client";

/**
 * AI incident reports: generate, regenerate, and read.
 *
 * *Model output is never rendered as HTML.* The report body is markdown
 * produced by an LLM that read attacker-controlled log lines. It is displayed
 * as text in a `<pre>`, and the structured fields are rendered through React,
 * which escapes. There is no `dangerouslySetInnerHTML` anywhere in this app,
 * and a markdown renderer here would be the one place a prompt injection could
 * turn into stored XSS.
 *
 * Generation is offered only to analysts and above, matching the endpoint's own
 * rule. A viewer sees the reports and is told plainly why the button is absent
 * rather than being shown a control that 403s.
 */

import { useState } from "react";

import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState, Spinner } from "@/components/ui/states";
import { ApiError, apiFetch } from "@/lib/api-client";
import { useAuth } from "@/lib/auth";
import { formatDateTime, formatPercent, humanise } from "@/lib/format";
import { canGenerateReport } from "@/lib/rbac";
import { useApi } from "@/lib/use-api";
import type { IncidentReport } from "@/types/api";

export function ReportPanel({ incidentId }: { incidentId: string }) {
  const { user } = useAuth();
  const mayGenerate = canGenerateReport(user?.role);

  const reports = useApi<IncidentReport[]>(`/incidents/${incidentId}/reports`);
  const [generating, setGenerating] = useState(false);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Reports come back newest version first.
  const selected =
    reports.data?.find((report) => report.id === selectedId) ?? reports.data?.[0] ?? null;

  async function generate() {
    setGenerating(true);
    setGenerateError(null);
    try {
      const report = await apiFetch<IncidentReport>(
        `/incidents/${incidentId}/analyze`,
        { method: "POST", body: { include_knowledge: true } },
      );
      setSelectedId(report.id);
      reports.reload();
    } catch (caught) {
      setGenerateError(
        caught instanceof ApiError
          ? caught.message
          : "The analysis could not be generated.",
      );
    } finally {
      setGenerating(false);
    }
  }

  return (
    <Card>
      <CardHeader
        title="AI analysis"
        subtitle={
          selected
            ? `Version ${selected.version} · ${formatDateTime(selected.created_at)}`
            : "Correlates the incident, its anomalies, log evidence and the knowledge base"
        }
        action={
          mayGenerate && (
            <button
              type="button"
              onClick={() => void generate()}
              disabled={generating}
              className="flex items-center gap-2 rounded-lg bg-sky-500 px-3 py-1.5 text-sm font-medium text-slate-950 transition-colors hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {generating && <Spinner />}
              {generating
                ? "Analysing…"
                : reports.data && reports.data.length > 0
                  ? "Regenerate"
                  : "Generate report"}
            </button>
          )
        }
      />

      {generateError && (
        <div className="border-b border-soc-border px-5 py-3">
          <p
            role="alert"
            className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300"
          >
            {generateError}
          </p>
        </div>
      )}

      {reports.loading && <LoadingState rows={3} label="Loading reports" />}

      {reports.error && !reports.loading && (
        <ErrorState
          message={reports.error}
          forbidden={reports.forbidden}
          onRetry={reports.reload}
        />
      )}

      {reports.data && reports.data.length === 0 && (
        <EmptyState
          title="No analysis yet"
          description={
            mayGenerate
              ? "Generate a report to have the model correlate this incident against the knowledge base."
              : "No analysis has been generated for this incident. Generating one requires the analyst role."
          }
        />
      )}

      {selected && (
        <CardBody className="space-y-5">
          {reports.data && reports.data.length > 1 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-soc-muted">Versions:</span>
              {reports.data.map((report) => (
                <button
                  key={report.id}
                  type="button"
                  onClick={() => setSelectedId(report.id)}
                  className={`rounded-md border px-2 py-0.5 text-xs transition-colors ${
                    report.id === selected.id
                      ? "border-sky-500/50 bg-sky-500/10 text-sky-300"
                      : "border-soc-border text-soc-muted hover:bg-soc-hover"
                  }`}
                >
                  v{report.version}
                </button>
              ))}
            </div>
          )}

          <div className="grid gap-3 sm:grid-cols-3">
            <Figure label="Attack type" value={humanise(selected.sections.attack_type)} />
            <Figure label="Assessed severity" value={humanise(selected.sections.severity)} />
            <Figure
              label="Model confidence"
              value={formatPercent(selected.sections.confidence)}
            />
          </div>

          {selected.executive_summary && (
            <Section title="Summary">
              <p className="text-sm leading-relaxed text-soc-text">
                {selected.executive_summary}
              </p>
            </Section>
          )}

          {selected.sections.likely_cause && (
            <Section title="Likely cause">
              <p className="text-sm leading-relaxed text-soc-text">
                {selected.sections.likely_cause}
              </p>
            </Section>
          )}

          {selected.sections.evidence && selected.sections.evidence.length > 0 && (
            <Section title="Evidence cited">
              <ul className="space-y-1.5">
                {selected.sections.evidence.map((item, index) => (
                  <li key={index} className="flex gap-2 text-sm text-soc-text">
                    <span className="text-soc-faint" aria-hidden>
                      ·
                    </span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {selected.recommendations.length > 0 && (
            <Section title="Recommended actions">
              <ol className="space-y-2">
                {selected.recommendations.map((action, index) => (
                  <li
                    key={index}
                    className="rounded-lg border border-soc-border bg-soc-raised px-3 py-2"
                  >
                    <div className="flex items-start gap-2">
                      <span className="mt-0.5 rounded border border-soc-border px-1.5 py-0.5 text-[10px] tracking-wide text-soc-muted uppercase">
                        {action.priority}
                      </span>
                      <div className="min-w-0">
                        <p className="text-sm text-soc-text">{action.action}</p>
                        {action.rationale && (
                          <p className="mt-1 text-xs text-soc-muted">{action.rationale}</p>
                        )}
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            </Section>
          )}

          <details className="rounded-lg border border-soc-border">
            <summary className="cursor-pointer px-3 py-2 text-sm text-soc-muted hover:text-soc-text">
              Full report body
            </summary>
            {/*
              Plain text, deliberately. This is model output derived from
              untrusted logs; rendering it as markup would make an injected log
              line a scripting vector.
            */}
            <pre className="max-h-96 overflow-auto border-t border-soc-border px-3 py-3 text-xs leading-relaxed whitespace-pre-wrap text-soc-muted">
              {selected.content}
            </pre>
          </details>

          <p className="text-xs text-soc-faint">
            AI-generated assessment. Verify against the evidence before acting on it.
          </p>
        </CardBody>
      )}
    </Card>
  );
}

function Figure({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-soc-border bg-soc-raised px-3 py-2">
      <p className="text-[10px] tracking-wide text-soc-muted uppercase">{label}</p>
      <p className="mt-1 text-sm font-medium text-soc-text">{value}</p>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold tracking-wide text-soc-muted uppercase">
        {title}
      </h3>
      {children}
    </div>
  );
}
