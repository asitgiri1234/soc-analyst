"""Holding the model to the detectors' arithmetic.

The detectors count evidence; the model forms a judgement. When the judgement
rates an incident *below* the count and offers no reason, the count wins --
which is the second half of the reported failure: an obvious brute-force burst
reaching the model as strong evidence and coming back as MEDIUM.

Raising severity is never blocked. The model sees context the detectors do not,
and in a SOC the safe direction to err is upward.
"""

from __future__ import annotations

import uuid

import pytest

from app.models.anomaly import Anomaly
from app.models.enums import AnomalyType, Severity
from app.schemas.analysis import IncidentAnalysis
from app.services.ai import prompts
from app.services.ai.analyzer import build_assessment, reconcile_severity


def anomaly(
    *,
    score: float = 0.78,
    confidence: float = 0.88,
    signals: list[str] | None = None,
    attempts: int = 10,
) -> Anomaly:
    return Anomaly(
        id=uuid.uuid4(),
        title="Repeated failed logins for 'nonexistent' from 127.0.0.1",
        anomaly_type=AnomalyType.THRESHOLD,
        severity=Severity.HIGH,
        score=score,
        confidence=confidence,
        detector="rule.brute_force",
        detector_version="2.0",
        evidence={
            "failed_attempts": attempts,
            "attempts_per_minute": 120.0,
            "invalid_user_attempts": attempts,
            "corroborating_signals": signals
            if signals is not None
            else ["machine_speed", "invalid_user"],
        },
        features={},
        mitre_techniques=["T1110"],
    )


def analysis(
    *, severity: Severity, confidence: float = 0.7, reason: str | None = None
) -> IncidentAnalysis:
    return IncidentAnalysis(
        summary="Repeated failed SSH authentication from a single source.",
        attack_type="brute_force",
        severity=severity,
        evidence=["10 failed attempts"],
        likely_cause="Automated password guessing.",
        recommended_actions=[],
        confidence=confidence,
        severity_override_reason=reason,
    )


# --- The assessment --------------------------------------------------------


def test_the_assessment_takes_the_highest_severity() -> None:
    """One critical detection makes a critical incident; averaging would hide it."""
    assessment = build_assessment(
        [anomaly(score=0.42), anomaly(score=0.91), anomaly(score=0.55)]
    )
    assert assessment["score"] == 0.91
    assert assessment["anomaly_count"] == 3


def test_the_assessment_collects_signals_from_every_anomaly() -> None:
    assessment = build_assessment(
        [anomaly(signals=["machine_speed"]), anomaly(signals=["invalid_user"])]
    )
    assert assessment["corroborating_signals"] == ["invalid_user", "machine_speed"]


def test_an_incident_without_anomalies_has_no_assessment() -> None:
    """Nothing was counted, so there is no arithmetic to hold the model to."""
    assert build_assessment([]) == {}


def test_the_assessment_carries_no_log_derived_text() -> None:
    """It is rendered outside the untrusted fence, so it must stay trustworthy.

    A title is built from log content; letting one into the trusted region would
    hand an attacker a way to write text the model treats as the platform's own.
    """
    rendered = prompts.render_assessment(build_assessment([anomaly()]))
    assert "nonexistent" not in rendered
    assert "Repeated failed logins" not in rendered
    assert "computed_severity" in rendered


# --- Reconciliation --------------------------------------------------------


def test_an_unexplained_downgrade_is_discarded() -> None:
    """The exact reported failure: strong evidence, model says MEDIUM."""
    assessment = build_assessment([anomaly()])
    result, note = reconcile_severity(analysis(severity=Severity.MEDIUM), assessment)

    assert result.severity is Severity.HIGH
    assert note["severity_adjusted"] is True
    assert note["model_severity"] == "medium"
    assert note["enforced_severity"] == "high"


def test_an_enforced_severity_lifts_confidence_to_the_detectors() -> None:
    """A model that misjudged severity is not the better judge of its certainty."""
    assessment = build_assessment([anomaly(confidence=0.88)])
    result, _ = reconcile_severity(
        analysis(severity=Severity.MEDIUM, confidence=0.70), assessment
    )
    assert result.confidence == pytest.approx(0.88)


def test_a_justified_downgrade_is_kept() -> None:
    """The model may know something the detectors cannot -- if it says so."""
    assessment = build_assessment([anomaly()])
    result, note = reconcile_severity(
        analysis(
            severity=Severity.LOW,
            reason="Source 127.0.0.1 is the loopback of the scanner host; this is the "
            "scheduled internal credential audit, not an intrusion attempt.",
        ),
        assessment,
    )

    assert result.severity is Severity.LOW
    assert note["severity_adjusted"] is False
    assert "scheduled internal credential audit" in note["severity_downgrade_accepted"]["reason"]


def test_an_upgrade_is_always_allowed() -> None:
    assessment = build_assessment([anomaly()])
    result, note = reconcile_severity(analysis(severity=Severity.CRITICAL), assessment)

    assert result.severity is Severity.CRITICAL
    assert note["severity_adjusted"] is False


def test_matching_severity_is_left_alone() -> None:
    assessment = build_assessment([anomaly()])
    result, note = reconcile_severity(
        analysis(severity=Severity.HIGH, confidence=0.6), assessment
    )

    assert result.severity is Severity.HIGH
    assert result.confidence == pytest.approx(0.6)
    assert note["severity_adjusted"] is False


def test_without_an_assessment_the_model_is_unconstrained() -> None:
    """No anomalies means nothing was counted; there is no floor to enforce."""
    result, note = reconcile_severity(analysis(severity=Severity.INFO), {})
    assert result.severity is Severity.INFO
    assert note["severity_adjusted"] is False


def test_enforcement_can_be_switched_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deployment that prefers the model's judgement can have it."""
    monkeypatch.setattr(
        "app.services.ai.analyzer.settings.AI_ENFORCE_DETERMINISTIC_SEVERITY", False
    )
    assessment = build_assessment([anomaly()])
    result, note = reconcile_severity(analysis(severity=Severity.MEDIUM), assessment)

    assert result.severity is Severity.MEDIUM
    assert note["severity_adjusted"] is False


# --- The prompt ------------------------------------------------------------


def test_the_system_prompt_states_the_floor_rule() -> None:
    system = prompts.build_system_prompt(
        attack_types=["brute_force"], severities=["low", "high"]
    )
    assert "floor" in system.lower()
    assert "severity_override_reason" in system


def test_the_prompt_refuses_the_common_excuses_for_downgrading() -> None:
    """Blocked, failed, or from a private address are not reasons to relax."""
    system = prompts.build_system_prompt(attack_types=["brute_force"], severities=["high"])
    assert "blocked" in system.lower()
    assert "loopback" in system.lower()


def test_the_assessment_reaches_the_user_message() -> None:
    rendered = prompts.render_case(
        incident={"title": "t"},
        anomalies=[],
        log_evidence=[],
        knowledge=[],
        assessment=build_assessment([anomaly()]),
    )
    assert "PLATFORM ASSESSMENT" in rendered
    assert "computed_severity: high" in rendered


def test_the_case_renders_without_an_assessment() -> None:
    """Incidents with no linked anomalies still analyse."""
    rendered = prompts.render_case(
        incident={"title": "t"}, anomalies=[], log_evidence=[], knowledge=[]
    )
    assert "PLATFORM ASSESSMENT" not in rendered
