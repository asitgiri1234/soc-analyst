"""Brute-force scoring: does the severity match the evidence?

Written against a real failure. A local SSH test produced ~10 failed
authentications against the nonexistent account "nonexistent" from 127.0.0.1
inside about five seconds, with OpenSSH itself reporting "penalty: failed
authentication". The platform classified it brute_force -- correctly -- and then
rated it MEDIUM at 70% confidence, because the only input to the score was the
attempt count and ten attempts sat halfway to the old saturation of thirty.

Counting attempts alone cannot tell a forgetful employee from a script. These
tests pin the signals that can: rate, whether the account exists, whether the
service itself started throttling, and whether anything eventually succeeded.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.enums import Severity
from app.services.detection.detectors.brute_force import BruteForceDetector
from app.services.detection.types import DetectionContext
from tests.synthetic import BASE_TIME, entry

SSH_HOST = "bastion-01"


def ssh_failure(
    *,
    offset_seconds: float,
    username: str = "nonexistent",
    source_ip: str = "127.0.0.1",
    invalid_user: bool = True,
    penalty: bool = False,
) -> object:
    """One failed SSH authentication, in the shape OpenSSH actually logs it."""
    if penalty:
        message = f"ssh_packet_read_poll_seqnr: penalty: failed authentication from {source_ip}"
    elif invalid_user:
        message = (
            f"Failed password for invalid user {username} from {source_ip} port 52814 ssh2"
        )
    else:
        message = f"Failed password for {username} from {source_ip} port 52814 ssh2"

    return entry(
        offset_seconds=offset_seconds,
        source_ip=source_ip,
        username=username,
        host=SSH_HOST,
        event_type="auth.login_failed",
        outcome="failure",
        severity=Severity.MEDIUM,
        message=message,
    )


def ssh_success(
    *, offset_seconds: float, username: str = "deploy", source_ip: str = "127.0.0.1"
) -> object:
    return entry(
        offset_seconds=offset_seconds,
        source_ip=source_ip,
        username=username,
        host=SSH_HOST,
        event_type="auth.login_succeeded",
        outcome="success",
        message=f"Accepted password for {username} from {source_ip} port 52999 ssh2",
    )


def analyse(entries: list) -> list:
    """Run only the per-account brute-force findings over a window."""
    context = DetectionContext(
        entries=entries,
        window_start=BASE_TIME - timedelta(hours=1),
        window_end=BASE_TIME + timedelta(hours=1),
    )
    return [
        finding
        for finding in BruteForceDetector().detect(context)
        if finding.entity and not finding.entity.startswith("spray|")
    ]


# --- The reported case -----------------------------------------------------


def test_the_reported_ssh_burst_is_high_severity() -> None:
    """The exact scenario that was rated MEDIUM: 10 invalid-user fails in ~5s."""
    entries = [ssh_failure(offset_seconds=index * 0.5) for index in range(10)]

    findings = analyse(entries)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.severity in {Severity.HIGH, Severity.CRITICAL}, (
        f"a machine-speed burst against a nonexistent account rated "
        f"{finding.severity.value} at score {finding.score}"
    )
    assert finding.confidence is not None and finding.confidence >= 0.75


def test_the_reported_burst_cites_its_corroborating_signals() -> None:
    """The score has to be checkable without rerunning the detector."""
    entries = [ssh_failure(offset_seconds=index * 0.5) for index in range(10)]
    evidence = analyse(entries)[0].evidence

    assert "machine_speed" in evidence["corroborating_signals"]
    assert "invalid_user" in evidence["corroborating_signals"]
    assert evidence["invalid_user_attempts"] == 10
    assert evidence["attempts_per_minute"] > 60


def test_an_ssh_penalty_line_raises_confidence() -> None:
    """The daemon throttling the client is the service's own conclusion."""
    plain = [ssh_failure(offset_seconds=index * 0.5) for index in range(10)]
    penalised = [*plain, ssh_failure(offset_seconds=5.5, penalty=True)]

    before = analyse(plain)[0]
    after = analyse(penalised)[0]

    assert "service_penalty" in after.evidence["corroborating_signals"]
    assert after.confidence > before.confidence
    assert after.score > before.score


# --- Required scenarios ----------------------------------------------------


def test_one_or_two_failures_raise_nothing() -> None:
    """A mistyped password is not an incident."""
    assert analyse([ssh_failure(offset_seconds=0)]) == []
    assert analyse([ssh_failure(offset_seconds=0), ssh_failure(offset_seconds=30)]) == []


def test_rapid_repeats_from_one_source_are_high_confidence() -> None:
    entries = [ssh_failure(offset_seconds=index * 0.4) for index in range(20)]
    finding = analyse(entries)[0]

    assert finding.severity in {Severity.HIGH, Severity.CRITICAL}
    assert finding.confidence is not None and finding.confidence >= 0.85
    assert finding.evidence["failed_attempts"] == 20


def test_invalid_user_attempts_score_above_valid_user_attempts() -> None:
    """Same count, same speed; only the account's existence differs.

    A real user can forget a password. Nobody accidentally authenticates as an
    account that does not exist, so this pair must not score the same.
    """
    invalid = [ssh_failure(offset_seconds=i * 0.5) for i in range(10)]
    valid = [
        ssh_failure(offset_seconds=i * 0.5, username="alice", invalid_user=False)
        for i in range(10)
    ]

    invalid_finding = analyse(invalid)[0]
    valid_finding = analyse(valid)[0]

    assert invalid_finding.score > valid_finding.score
    assert invalid_finding.confidence > valid_finding.confidence
    assert "invalid_user" not in valid_finding.evidence["corroborating_signals"]


def test_slow_failures_score_below_a_burst() -> None:
    """Ten failures over two hours is a person; ten in five seconds is not."""
    burst = [
        ssh_failure(offset_seconds=i * 0.5, invalid_user=False, username="alice")
        for i in range(10)
    ]
    spread = [
        ssh_failure(offset_seconds=i * 720, invalid_user=False, username="alice")
        for i in range(10)
    ]

    assert analyse(burst)[0].score > analyse(spread)[0].score
    assert "machine_speed" not in analyse(spread)[0].evidence["corroborating_signals"]


def test_distributed_failures_are_reported_per_source() -> None:
    """Five sources failing twice each is not one twenty-attempt attack.

    Grouping is per source and account, so distributed low-volume failures stay
    below the threshold instead of being summed into a false brute force. The
    spraying detector is what covers breadth.
    """
    entries = [
        ssh_failure(offset_seconds=index * 2, source_ip=f"203.0.113.{10 + index}")
        for index in range(5)
        for _ in range(2)
    ]

    assert analyse(entries) == []


def test_distributed_high_volume_reports_each_source_separately() -> None:
    entries = [
        ssh_failure(offset_seconds=index * 0.5, source_ip=source)
        for source in ("203.0.113.10", "203.0.113.11")
        for index in range(10)
    ]

    findings = analyse(entries)
    sources = {finding.evidence["source_ip"] for finding in findings}

    assert len(findings) == 2
    assert sources == {"203.0.113.10", "203.0.113.11"}


def test_a_successful_login_alone_raises_no_brute_force() -> None:
    """Normal SSH use must be silent."""
    entries = [
        ssh_success(offset_seconds=index * 60, username=f"analyst{index}")
        for index in range(5)
    ]
    assert analyse(entries) == []


def test_success_after_repeated_failures_is_critical() -> None:
    """The attacker got in. Nothing this detector sees is worse."""
    entries = [ssh_failure(offset_seconds=index * 0.5) for index in range(10)]
    entries.append(ssh_success(offset_seconds=6, username="nonexistent"))

    finding = analyse(entries)[0]
    assert finding.severity is Severity.CRITICAL
    assert "succeeded_after_failures" in finding.evidence["corroborating_signals"]
    assert "SUCCEEDED" in finding.reason


def test_a_success_before_the_failures_is_not_counted() -> None:
    """A login that predates the burst is not evidence the burst worked."""
    entries = [ssh_success(offset_seconds=0, username="deploy")]
    entries += [ssh_failure(offset_seconds=60 + index * 0.5) for index in range(10)]

    finding = analyse(entries)[0]
    assert "succeeded_after_failures" not in finding.evidence["corroborating_signals"]


# --- Ordering and configurability ------------------------------------------


def test_more_attempts_always_outrank_fewer() -> None:
    """Corroboration must raise a score without inverting the count ordering."""
    scores = [
        analyse([ssh_failure(offset_seconds=i * 0.5) for i in range(count)])[0].score
        for count in (6, 10, 20, 30)
    ]
    assert scores == sorted(scores)


def test_thresholds_are_configurable() -> None:
    """Tuning is a constructor argument, not an edit to the detector."""
    entries = [ssh_failure(offset_seconds=index * 0.5) for index in range(4)]
    context = DetectionContext(
        entries=entries,
        window_start=BASE_TIME - timedelta(hours=1),
        window_end=BASE_TIME + timedelta(hours=1),
    )

    assert BruteForceDetector().detect(context) == []
    strict = BruteForceDetector(attempt_threshold=3, attempt_saturation=10)
    assert [f for f in strict.detect(context) if not f.entity.startswith("spray|")]


def test_the_score_never_leaves_the_unit_interval() -> None:
    """Every signal at once must still produce a valid score."""
    entries = [ssh_failure(offset_seconds=index * 0.1) for index in range(200)]
    entries.append(ssh_failure(offset_seconds=20.5, penalty=True))
    entries.append(ssh_success(offset_seconds=21, username="nonexistent"))

    finding = analyse(entries)[0]
    assert 0.0 <= finding.score <= 1.0
    assert finding.confidence is not None and 0.0 <= finding.confidence <= 1.0


def test_events_are_scored_by_their_own_span_not_the_window() -> None:
    """A burst is a burst whether the request asked about an hour or a month."""
    entries = [ssh_failure(offset_seconds=index * 0.5) for index in range(10)]

    narrow = DetectionContext(
        entries=entries,
        window_start=BASE_TIME - timedelta(minutes=1),
        window_end=BASE_TIME + timedelta(minutes=1),
    )
    wide = DetectionContext(
        entries=entries,
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 12, 31, tzinfo=UTC),
    )

    detector = BruteForceDetector()

    def per_account(context: DetectionContext) -> float:
        findings = [
            f for f in detector.detect(context) if not f.entity.startswith("spray|")
        ]
        return findings[0].score

    assert per_account(narrow) == per_account(wide)
