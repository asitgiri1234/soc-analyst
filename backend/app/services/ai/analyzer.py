"""Gathering a case, asking a model about it, and storing the answer.

The analyzer owns the sequence: collect the incident and its anomalies, pull
the log evidence behind those anomalies, retrieve relevant knowledge through
the existing RAG service, build a prompt that keeps all of it clearly marked as
data, call the provider, and validate the answer against a Pydantic schema
before any of it reaches the database.

Nothing is written until the analysis validates. A model that returns prose, or
invents a severity, produces an error rather than a half-populated report.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.models.anomaly import Anomaly
from app.models.enums import AttackType, ReportFormat, ReportStatus, Severity
from app.models.incident import Incident
from app.models.incident_attachment import IncidentAttachment
from app.models.incident_report import IncidentReport
from app.models.log_entry import LogEntry
from app.schemas.analysis import IncidentAnalysis, analysis_json_schema
from app.services.ai import prompts
from app.services.ai.base import LLMError, LLMProvider, LLMResponseError
from app.services.rag import retrieval

logger = get_logger(__name__)

# Prompt revision, recorded on every report. When the prompt changes, reports
# generated before and after are no longer strictly comparable.
PROMPT_VERSION = "1.0"


@dataclass(slots=True)
class AnalysisContext:
    """Everything gathered about an incident before the model is asked."""

    incident: dict[str, Any]
    anomalies: list[dict[str, Any]]
    log_evidence: list[dict[str, Any]]
    knowledge: list[dict[str, Any]]
    # Files an analyst attached. Untrusted like everything else here: an
    # attachment is a document someone uploaded, and its text is as capable of
    # carrying an injection attempt as a log line is.
    attachments: list[dict[str, Any]] = field(default_factory=list)
    # What the detectors computed, kept apart from the untrusted views above
    # because it is the platform's own arithmetic rather than log content.
    assessment: dict[str, Any] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "anomalies": len(self.anomalies),
            "log_entries": len(self.log_evidence),
            "knowledge_chunks": len(self.knowledge),
            "attachments": len(self.attachments),
        }


def _incident_view(incident: Incident) -> dict[str, Any]:
    """The incident fields worth showing a model."""
    return {
        "reference": incident.reference,
        "title": incident.title,
        "summary": incident.summary,
        "description": incident.description,
        "status": incident.status.value,
        "severity_assigned_by_analyst": incident.severity.value,
        "attack_type_assigned_by_analyst": incident.attack_type.value,
        "detected_at": incident.detected_at,
        "tags": incident.tags,
        "affected_assets": incident.affected_assets,
        "indicators": incident.indicators,
    }


def _anomaly_view(anomaly: Anomaly) -> dict[str, Any]:
    return {
        "title": anomaly.title,
        "description": anomaly.description,
        "type": anomaly.anomaly_type.value,
        "severity": anomaly.severity.value,
        "score": anomaly.score,
        "detector": anomaly.detector,
        "detected_at": anomaly.detected_at,
        "evidence": anomaly.evidence,
        "mitre_techniques": anomaly.mitre_techniques,
    }


def _log_view(entry: LogEntry) -> dict[str, Any]:
    return {
        "event_timestamp": entry.event_timestamp,
        "severity": entry.severity.value,
        "event_type": entry.event_type,
        "action": entry.action,
        "outcome": entry.outcome,
        "host": entry.host,
        "username": entry.username,
        "source_ip": entry.source_ip,
        "destination_ip": entry.destination_ip,
        "destination_port": entry.destination_port,
        "message": entry.message,
    }


def _attachment_view(attachment: IncidentAttachment) -> dict[str, Any]:
    """An attached file as the model sees it.

    The text is cut to its own budget before it reaches the prompt builder, so
    one long document cannot consume the context that the log evidence needs.
    The cut is declared rather than hidden: an analysis performed on the first
    few thousand characters should say so.
    """
    body = attachment.content[: settings.ATTACHMENT_PROMPT_CHARS]
    clipped = attachment.truncated or len(attachment.content) > len(body)

    return {
        "filename": attachment.filename,
        "uploaded_by": attachment.uploaded_by_username,
        "uploaded_at": attachment.created_at,
        "truncated": clipped,
        "content": body,
    }


def knowledge_query(incident: Incident, anomalies: list[Anomaly]) -> str:
    """Build the retrieval query from the incident and its detections.

    Uses the incident's own words plus the anomaly titles and detector names,
    which is what actually distinguishes a brute-force case from an
    exfiltration one.
    """
    parts = [incident.title, incident.attack_type.value.replace("_", " ")]
    if incident.summary:
        parts.append(incident.summary)
    for anomaly in anomalies[:5]:
        parts.append(anomaly.title)
    return " ".join(part for part in parts if part)[:1000]


async def gather_context(
    session: AsyncSession,
    incident: Incident,
    *,
    include_knowledge: bool = True,
    max_log_entries: int | None = None,
) -> AnalysisContext:
    """Collect the case: anomalies, the logs behind them, and guidance."""
    anomalies = list(
        (
            await session.execute(
                select(Anomaly)
                .where(Anomaly.incident_id == incident.id)
                .order_by(Anomaly.score.desc())
                .limit(settings.AI_MAX_ANOMALIES)
            )
        ).scalars()
    )

    # The log entries the linked anomalies actually point at, plus their
    # neighbours from the same sources -- an anomaly cites a representative
    # entry, and the surrounding traffic is what makes it interpretable.
    log_limit = (
        max_log_entries if max_log_entries is not None else settings.AI_MAX_LOG_ENTRIES
    )
    entries: list[LogEntry] = []
    if log_limit:
        entry_ids = [a.log_entry_id for a in anomalies if a.log_entry_id]
        source_ids = [a.log_source_id for a in anomalies if a.log_source_id]
        conditions = []
        if entry_ids:
            conditions.append(LogEntry.id.in_(entry_ids))
        if source_ids:
            conditions.append(LogEntry.log_source_id.in_(source_ids))

        if conditions:
            entries = list(
                (
                    await session.execute(
                        select(LogEntry)
                        .where(or_(*conditions))
                        .order_by(LogEntry.event_timestamp.desc())
                        .limit(log_limit)
                    )
                ).scalars()
            )

    knowledge: list[dict[str, Any]] = []
    if include_knowledge and settings.AI_KNOWLEDGE_TOP_K:
        hits = await retrieval.search(
            session,
            knowledge_query(incident, anomalies),
            top_k=settings.AI_KNOWLEDGE_TOP_K,
        )
        knowledge = [
            {
                "source": hit.document_title,
                "document_type": hit.document_type.value,
                "relevance": hit.similarity,
                "excerpt": hit.content,
            }
            for hit in hits
        ]

    # Newest first: when an analyst has attached several files, the most recent
    # is the one most likely to describe where the investigation has got to.
    attached = list(
        (
            await session.execute(
                select(IncidentAttachment)
                .where(IncidentAttachment.incident_id == incident.id)
                .order_by(IncidentAttachment.created_at.desc())
                .limit(settings.AI_MAX_ATTACHMENTS)
            )
        ).scalars()
    )

    return AnalysisContext(
        incident=_incident_view(incident),
        anomalies=[_anomaly_view(a) for a in anomalies],
        log_evidence=[_log_view(e) for e in entries],
        knowledge=knowledge,
        attachments=[_attachment_view(a) for a in attached],
        assessment=build_assessment(anomalies),
    )


# Severity order, lowest first. Used to compare the model's judgement with the
# detectors' arithmetic.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def build_assessment(anomalies: list[Anomaly]) -> dict[str, Any]:
    """Summarise what the detectors concluded, for the model to work from.

    The incident takes the *highest* severity among its anomalies rather than an
    average: an incident containing one critical detection is a critical
    incident, and averaging it against two low ones would report a calmer
    situation than the evidence supports.

    Only computed values travel -- scores, counts, signal names. Titles and
    messages stay in the untrusted section where they belong.
    """
    if not anomalies:
        return {}

    top = max(anomalies, key=lambda anomaly: anomaly.score)
    corroborating: set[str] = set()
    metrics: dict[str, Any] = {}

    for anomaly in anomalies:
        evidence = anomaly.evidence or {}
        for name in evidence.get("corroborating_signals") or []:
            corroborating.add(str(name))

    # Carried from the strongest detection, since that is the one setting the
    # severity the model is being asked to respect.
    for key in (
        "failed_attempts",
        "attempts_per_minute",
        "invalid_user_attempts",
        "service_penalties",
        "successful_after_failures",
        "distinct_accounts",
    ):
        value = (top.evidence or {}).get(key)
        if value is not None:
            metrics[key] = value

    confidences = [a.confidence for a in anomalies if a.confidence is not None]

    return {
        "severity": top.severity.value,
        "score": top.score,
        "confidence": max(confidences) if confidences else 0.0,
        "anomaly_count": len(anomalies),
        "corroborating_signals": sorted(corroborating),
        "metrics": metrics,
    }


def reconcile_severity(
    analysis: IncidentAnalysis, assessment: dict[str, Any]
) -> tuple[IncidentAnalysis, dict[str, Any]]:
    """Hold the model to the detectors' severity unless it argues otherwise.

    The detectors counted evidence; the model formed a judgement. A judgement
    that rates an incident *below* the arithmetic may be right -- a known
    scanner, a test harness, a misconfigured client -- but it has to say so.
    Left unexplained, the count wins, because the failure being corrected here
    is exactly that: an obvious brute-force burst quietly rated MEDIUM.

    Raising severity is never blocked. The model sees context the detectors do
    not, and erring upward is the safe direction in a SOC.
    """
    note: dict[str, Any] = {"severity_adjusted": False}

    computed = assessment.get("severity")
    if not computed or not settings.AI_ENFORCE_DETERMINISTIC_SEVERITY:
        return analysis, note

    floor = Severity(computed)
    if _SEVERITY_RANK[analysis.severity] >= _SEVERITY_RANK[floor]:
        return analysis, note

    if analysis.severity_override_reason:
        # Argued for, so it stands -- and the argument is recorded.
        note["severity_downgrade_accepted"] = {
            "from": floor.value,
            "to": analysis.severity.value,
            "reason": analysis.severity_override_reason,
        }
        return analysis, note

    logger.warning(
        "model rated incident %s below the computed %s without justification; "
        "keeping the computed severity",
        analysis.severity.value,
        floor.value,
    )
    note = {
        "severity_adjusted": True,
        "model_severity": analysis.severity.value,
        "enforced_severity": floor.value,
        "reason": "computed severity kept: the model gave no justification for a downgrade",
    }
    # Confidence is about the evidence, and the detectors' corroboration is
    # part of that evidence. A model that misjudged the severity should not
    # also be trusted to have judged its own certainty well, so the stronger of
    # the two is taken.
    detector_confidence = float(assessment.get("confidence") or 0.0)
    return (
        analysis.model_copy(
            update={
                "severity": floor,
                "confidence": max(analysis.confidence, detector_confidence),
            }
        ),
        note,
    )


def parse_analysis(text: str) -> IncidentAnalysis:
    """Validate a model's answer against the schema.

    Tolerates a model that wraps its JSON in a markdown fence -- a common habit
    even under JSON mode -- but nothing looser than that. This is schema
    validation, not text scraping: anything that does not parse and validate is
    rejected rather than salvaged.
    """
    candidate = text.strip()
    if candidate.startswith("```"):
        # Strip a ```json ... ``` wrapper.
        candidate = candidate.split("```")[1] if "```" in candidate[3:] else candidate
        candidate = candidate.removeprefix("json").strip()

    # A model may still emit a leading sentence; take the outermost JSON object.
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMResponseError("model response contained no JSON object")

    try:
        data = json.loads(candidate[start : end + 1])
    except ValueError as exc:
        raise LLMResponseError(f"model response was not valid JSON: {exc}") from exc

    try:
        return IncidentAnalysis.model_validate(data)
    except ValidationError as exc:
        raise LLMResponseError(
            f"model response did not match the analysis schema: {exc.error_count()} "
            f"problem(s): {exc.errors()[0].get('msg', 'unknown')}"
        ) from exc


def render_markdown(analysis: IncidentAnalysis, incident: Incident) -> str:
    """A human-readable report body beside the structured fields."""
    lines = [
        f"# {incident.reference}: {incident.title}",
        "",
        "## Summary",
        analysis.summary,
        "",
        "## Assessment",
        f"- **Attack type:** {analysis.attack_type.value}",
        f"- **Severity:** {analysis.severity.value}",
        f"- **Confidence:** {analysis.confidence:.0%}",
        "",
        "## Likely cause",
        analysis.likely_cause,
    ]

    if analysis.evidence:
        lines += ["", "## Evidence"]
        lines += [f"- {item}" for item in analysis.evidence]

    if analysis.recommended_actions:
        lines += ["", "## Recommended actions"]
        for action in analysis.recommended_actions:
            lines.append(f"- **[{action.priority}]** {action.action}")
            if action.rationale:
                lines.append(f"  - {action.rationale}")

    lines += [
        "",
        "---",
        "*Generated by AI analysis. Review before acting on it.*",
    ]
    return "\n".join(lines)


async def analyze_incident(
    session: AsyncSession,
    incident: Incident,
    *,
    provider: LLMProvider,
    author_id: uuid.UUID | None = None,
    include_knowledge: bool = True,
    max_log_entries: int | None = None,
    publish: bool = False,
) -> tuple[IncidentReport, IncidentAnalysis, AnalysisContext]:
    """Analyse an incident and store the result as a new report version.

    Each call produces a new version rather than overwriting: an earlier
    analysis may already have been acted on, and the trail of what was believed
    when matters more than tidiness.
    """
    context = await gather_context(
        session,
        incident,
        include_knowledge=include_knowledge,
        max_log_entries=max_log_entries,
    )

    system = prompts.build_system_prompt(
        attack_types=[item.value for item in AttackType],
        severities=[item.value for item in Severity],
    )
    user = prompts.render_case(
        incident=context.incident,
        anomalies=context.anomalies,
        log_evidence=context.log_evidence,
        knowledge=context.knowledge,
        attachments=context.attachments,
        assessment=context.assessment,
    )

    completion = await provider.complete(
        system=system, user=user, json_schema=analysis_json_schema()
    )
    analysis = parse_analysis(completion.text)
    # The detectors' severity stands unless the model argued for lowering it.
    analysis, severity_note = reconcile_severity(analysis, context.assessment)

    next_version = (
        await session.execute(
            select(func.coalesce(func.max(IncidentReport.version), 0) + 1).where(
                IncidentReport.incident_id == incident.id
            )
        )
    ).scalar_one()

    report = IncidentReport(
        incident_id=incident.id,
        author_id=author_id,
        title=f"AI analysis of {incident.reference}",
        version=next_version,
        status=ReportStatus.PUBLISHED if publish else ReportStatus.DRAFT,
        format=ReportFormat.MARKDOWN,
        executive_summary=analysis.summary,
        content=render_markdown(analysis, incident),
        sections={
            "summary": analysis.summary,
            "attack_type": analysis.attack_type.value,
            "severity": analysis.severity.value,
            "evidence": analysis.evidence,
            "likely_cause": analysis.likely_cause,
            "confidence": analysis.confidence,
        },
        recommendations=[action.model_dump() for action in analysis.recommended_actions],
        is_ai_generated=True,
        generation_metadata={
            "provider": provider.name,
            "model": completion.model,
            "prompt_version": PROMPT_VERSION,
            "usage": completion.usage,
            "context": context.counts,
            "knowledge_used": include_knowledge,
            # What the detectors computed, and whether the model's severity was
            # kept or overridden. Recorded so a report can be audited against
            # the arithmetic it was supposed to respect.
            "assessment": context.assessment,
            "severity_reconciliation": severity_note,
            "generated_at": datetime.now(UTC).isoformat(),
        },
        published_at=datetime.now(UTC) if publish else None,
    )
    session.add(report)
    await session.flush()

    logger.info(
        "generated AI report v%d for %s (%s/%s, confidence %.2f)",
        next_version,
        incident.reference,
        provider.name,
        completion.model,
        analysis.confidence,
    )
    return report, analysis, context


__all__ = [
    "AnalysisContext",
    "LLMError",
    "analyze_incident",
    "build_assessment",
    "gather_context",
    "parse_analysis",
    "reconcile_severity",
    "render_markdown",
]
