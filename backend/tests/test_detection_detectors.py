"""The detectors, as pure functions over synthetic logs.

No database and no HTTP: each test builds a window, runs one detector and checks
what it argued for. Every detector is exercised against both the attack it looks
for and ordinary traffic, because a detector that fires on normal days is worse
than no detector.
"""

from __future__ import annotations

import pytest

from app.models.enums import AnomalyType, Severity
from app.services.detection import signals, statistics
from app.services.detection.detectors.brute_force import BruteForceDetector
from app.services.detection.detectors.event_burst import EventBurstDetector
from app.services.detection.detectors.request_frequency import RequestFrequencyDetector
from app.services.detection.detectors.suspicious_ip import SuspiciousIPDetector
from app.services.detection.types import BASE_SCORE, Finding, scale_score, severity_for
from tests import synthetic

ALL_DETECTORS = [
    BruteForceDetector(),
    RequestFrequencyDetector(),
    SuspiciousIPDetector(),
    EventBurstDetector(),
]


# --- Scoring and severity --------------------------------------------------


def test_a_finding_at_the_threshold_is_low() -> None:
    assert scale_score(5, 5, 30) == BASE_SCORE
    assert severity_for(BASE_SCORE) is Severity.LOW


def test_score_climbs_with_the_observation() -> None:
    scores = [scale_score(n, 5, 30) for n in (5, 10, 20, 30, 100)]
    assert scores == sorted(scores)
    assert scores[-1] == 1.0


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.40, Severity.LOW),
        (0.49, Severity.LOW),
        (0.50, Severity.MEDIUM),
        (0.69, Severity.MEDIUM),
        (0.70, Severity.HIGH),
        (0.84, Severity.HIGH),
        (0.85, Severity.CRITICAL),
        (1.00, Severity.CRITICAL),
    ],
)
def test_severity_bands(score: float, expected: Severity) -> None:
    assert severity_for(score) is expected


def test_every_severity_band_is_reachable() -> None:
    """A scale nothing can reach the top of would be useless."""
    produced = {severity_for(scale_score(n, 5, 30)) for n in range(5, 40)}
    assert produced == {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


# --- Robust statistics -----------------------------------------------------


def test_the_median_resists_the_outlier_it_is_measuring() -> None:
    """The reason for a modified z-score rather than a plain one."""
    quiet = [10.0] * 20
    population = [*quiet, 5000.0]

    z = statistics.modified_z_score(5000.0, population)
    assert z > 10

    # A mean-based score is dragged up by the outlier itself and understates it.
    mean = sum(population) / len(population)
    assert mean > 200  # the one value moved the mean twentyfold


def test_a_uniform_population_has_no_outliers() -> None:
    assert statistics.modified_z_score(10.0, [10.0] * 10) == 0.0


def test_mad_falls_back_when_it_is_zero() -> None:
    """Most values identical, one different: still detectable."""
    population = [10.0] * 12 + [90.0]
    assert statistics.modified_z_score(90.0, population) > 3.5


# --- Signal classification -------------------------------------------------


def test_a_successful_login_is_not_a_failure() -> None:
    entry = synthetic.successful_login(source_ip="10.0.0.1", username="a")
    assert signals.is_auth_event(entry)
    assert not signals.is_failure(entry)
    assert not signals.is_failed_auth(entry)


def test_a_failed_login_is_recognised() -> None:
    assert signals.is_failed_auth(synthetic.failed_login(source_ip="10.0.0.1", username="a"))


def test_an_explicit_success_outcome_overrides_other_markers() -> None:
    """'auth.login' with outcome success must not read as a failure."""
    entry = synthetic.entry(event_type="auth.login", outcome="success", message="failed earlier")
    assert not signals.is_failure(entry)


def test_the_free_text_message_does_not_drive_classification() -> None:
    """Matching 'denied' inside prose would misclassify ordinary events."""
    entry = synthetic.entry(
        event_type="firewall.connection_allowed",
        action="allow",
        message="Allowed after a previously denied attempt",
    )
    assert not signals.is_blocked(entry)


def test_a_blocked_connection_is_recognised() -> None:
    assert signals.is_blocked(synthetic.connection(source_ip="10.0.0.1", blocked=True))


# --- Normal traffic --------------------------------------------------------


@pytest.mark.parametrize("detector", ALL_DETECTORS, ids=lambda d: d.name)
def test_no_detector_fires_on_normal_traffic(detector) -> None:
    """The property that decides whether any of this is usable."""
    findings = detector.detect(synthetic.context(synthetic.normal_traffic()))
    assert findings == [], [f.title for f in findings]


@pytest.mark.parametrize("detector", ALL_DETECTORS, ids=lambda d: d.name)
def test_no_detector_fires_on_an_empty_window(detector) -> None:
    assert detector.detect(synthetic.context([])) == []


@pytest.mark.parametrize("detector", ALL_DETECTORS, ids=lambda d: d.name)
def test_no_detector_fires_on_a_single_event(detector) -> None:
    entries = [synthetic.connection(source_ip="10.20.4.10")]
    assert detector.detect(synthetic.context(entries)) == []


# --- Brute force -----------------------------------------------------------


def test_repeated_failures_against_one_account_are_detected() -> None:
    entries = synthetic.normal_traffic()
    entries += [
        synthetic.failed_login(
            source_ip="203.0.113.47", username="j.okafor", offset_seconds=600 + i * 3
        )
        for i in range(25)
    ]

    findings = BruteForceDetector().detect(synthetic.context(entries))
    brute = [f for f in findings if "Repeated failed logins" in f.title]

    assert len(brute) == 1
    finding = brute[0]
    assert finding.anomaly_type is AnomalyType.THRESHOLD
    assert finding.evidence["failed_attempts"] == 25
    assert finding.evidence["account"] == "j.okafor"
    assert finding.evidence["source_ip"] == "203.0.113.47"
    assert finding.severity in (Severity.HIGH, Severity.CRITICAL)
    assert "T1110" in finding.mitre_techniques


def test_the_brute_force_reason_states_the_arithmetic() -> None:
    """Explainability: the reason must carry the count and the threshold."""
    entries = [
        synthetic.failed_login(source_ip="203.0.113.47", username="j.okafor", offset_seconds=i)
        for i in range(12)
    ]
    finding = BruteForceDetector().detect(synthetic.context(entries))[0]

    assert "12 failed authentication attempts" in finding.reason
    assert "j.okafor" in finding.reason
    assert "threshold of 5" in finding.reason


def test_more_attempts_score_higher() -> None:
    def score_for(count: int) -> float:
        entries = [
            synthetic.failed_login(source_ip="203.0.113.47", username="u", offset_seconds=i)
            for i in range(count)
        ]
        return BruteForceDetector().detect(synthetic.context(entries))[0].score

    assert score_for(6) < score_for(15) < score_for(30)


def test_failures_below_the_threshold_are_ignored() -> None:
    entries = [
        synthetic.failed_login(source_ip="203.0.113.47", username="j.okafor", offset_seconds=i)
        for i in range(4)
    ]
    assert BruteForceDetector().detect(synthetic.context(entries)) == []


def test_failures_spread_across_accounts_are_spraying_not_brute_force() -> None:
    """Two attempts each against fifteen accounts trips no per-account threshold."""
    entries = []
    for index in range(15):
        for attempt in range(2):
            entries.append(
                synthetic.failed_login(
                    source_ip="198.51.100.7",
                    username=f"user{index:02d}",
                    offset_seconds=index * 10 + attempt,
                )
            )

    findings = BruteForceDetector().detect(synthetic.context(entries))

    assert [f.title for f in findings] == ["Password spraying from 198.51.100.7"]
    finding = findings[0]
    assert finding.anomaly_type is AnomalyType.BEHAVIORAL
    assert finding.evidence["distinct_accounts"] == 15
    assert finding.evidence["failed_attempts"] == 30
    assert "T1110.003" in finding.mitre_techniques


def test_spraying_that_also_succeeded_scores_higher() -> None:
    """A spray with a success may already have found a working credential."""

    def entries_for(with_success: bool):
        items = [
            synthetic.failed_login(
                source_ip="198.51.100.7", username=f"user{i:02d}", offset_seconds=i * 5
            )
            for i in range(12)
        ]
        if with_success:
            items.append(
                synthetic.successful_login(
                    source_ip="198.51.100.7", username="user07", offset_seconds=200
                )
            )
        return items

    def spray(with_success: bool) -> Finding:
        findings = BruteForceDetector().detect(synthetic.context(entries_for(with_success)))
        return next(f for f in findings if "spraying" in f.title)

    without, with_hit = spray(False), spray(True)
    assert with_hit.score > without.score
    assert with_hit.evidence["successful_attempts"] == 1
    assert "succeeded in the same window" in with_hit.reason


def test_brute_force_separates_distinct_sources() -> None:
    entries = []
    for ip in ("203.0.113.10", "203.0.113.11"):
        entries += [
            synthetic.failed_login(source_ip=ip, username="j.okafor", offset_seconds=i)
            for i in range(8)
        ]

    findings = BruteForceDetector().detect(synthetic.context(entries))
    sources = {f.evidence["source_ip"] for f in findings if "Repeated" in f.title}
    assert sources == {"203.0.113.10", "203.0.113.11"}


# --- Request frequency -----------------------------------------------------


def test_a_source_far_above_its_peers_is_flagged() -> None:
    entries = synthetic.normal_traffic(sources=10, per_source=10)
    entries += [
        synthetic.connection(source_ip="203.0.113.200", offset_seconds=1000 + i)
        for i in range(400)
    ]

    findings = RequestFrequencyDetector().detect(synthetic.context(entries))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.anomaly_type is AnomalyType.STATISTICAL
    assert finding.evidence["source"] == "203.0.113.200"
    assert finding.evidence["event_count"] == 400
    assert finding.evidence["modified_z_score"] >= 3.5
    assert finding.severity in (Severity.HIGH, Severity.CRITICAL)


def test_the_frequency_rate_reflects_the_traffic_not_the_query() -> None:
    """400 events in 400 seconds is ~60/min however wide a window was asked for."""
    entries = synthetic.normal_traffic(sources=10, per_source=10)
    entries += [
        synthetic.connection(source_ip="203.0.113.200", offset_seconds=1000 + i)
        for i in range(400)
    ]
    # A window far wider than the traffic it contains.
    finding = RequestFrequencyDetector().detect(synthetic.context(entries, hours=720))[0]

    assert finding.evidence["source"] == "203.0.113.200"
    assert finding.evidence["events_per_minute"] > 50
    assert finding.evidence["active_span_seconds"] == pytest.approx(399, abs=2)


def test_the_frequency_reason_quotes_its_baseline() -> None:
    entries = synthetic.normal_traffic(sources=10, per_source=10)
    entries += [
        synthetic.connection(source_ip="203.0.113.200", offset_seconds=1000 + i)
        for i in range(400)
    ]
    finding = RequestFrequencyDetector().detect(synthetic.context(entries))[0]

    assert "400 events" in finding.reason
    assert "median" in finding.reason
    assert "robust deviations" in finding.reason


def test_frequency_needs_enough_peers_to_compare_against() -> None:
    """Two sources are not a population; "unusual" would be meaningless."""
    entries = [synthetic.connection(source_ip="10.20.4.1", offset_seconds=i) for i in range(20)]
    entries += [
        synthetic.connection(source_ip="203.0.113.9", offset_seconds=i) for i in range(500)
    ]

    assert RequestFrequencyDetector().detect(synthetic.context(entries)) == []


def test_frequency_ignores_a_small_absolute_count() -> None:
    """Four events where peers sent one is not a flood."""
    entries = []
    for index in range(10):
        entries.append(synthetic.connection(source_ip=f"10.20.4.{index}", offset_seconds=index))
    entries += [
        synthetic.connection(source_ip="10.20.4.99", offset_seconds=100 + i) for i in range(4)
    ]

    assert RequestFrequencyDetector().detect(synthetic.context(entries)) == []


# --- Suspicious IP ---------------------------------------------------------


def test_a_port_scan_is_detected() -> None:
    entries = [
        synthetic.connection(
            source_ip="203.0.113.99",
            destination_ip="10.20.3.15",
            destination_port=port,
            offset_seconds=port % 100,
            blocked=True,
        )
        for port in range(1, 61)
    ]

    findings = SuspiciousIPDetector().detect(synthetic.context(entries))

    assert len(findings) == 1
    finding = findings[0]
    assert "port_scan" in finding.evidence["indicators"]
    assert finding.evidence["distinct_destination_ports"] == 60
    assert finding.anomaly_type is AnomalyType.BEHAVIORAL
    assert "T1046" in finding.mitre_techniques


def test_a_host_sweep_is_detected() -> None:
    entries = [
        synthetic.connection(
            source_ip="203.0.113.98",
            destination_ip=f"10.20.3.{host}",
            destination_port=445,
            offset_seconds=host,
        )
        for host in range(1, 41)
    ]

    findings = SuspiciousIPDetector().detect(synthetic.context(entries))
    assert "host_sweep" in findings[0].evidence["indicators"]
    assert findings[0].evidence["distinct_destination_hosts"] == 40


def test_a_mostly_blocked_source_is_detected() -> None:
    entries = [
        synthetic.connection(
            source_ip="192.0.2.180",
            destination_ip="10.20.3.15",
            destination_port=445,
            offset_seconds=i,
            blocked=True,
        )
        for i in range(30)
    ]

    findings = SuspiciousIPDetector().detect(synthetic.context(entries))
    assert "mostly_blocked" in findings[0].evidence["indicators"]
    assert findings[0].evidence["blocked_ratio"] == 1.0


def test_several_indicators_at_once_score_higher_than_one() -> None:
    def score(entries) -> float:
        return SuspiciousIPDetector().detect(synthetic.context(entries))[0].score

    scan_only = [
        synthetic.connection(
            source_ip="203.0.113.97",
            destination_ip="10.20.3.15",
            destination_port=port,
            offset_seconds=port,
        )
        for port in range(1, 25)
    ]
    scan_and_sweep = [
        synthetic.connection(
            source_ip="203.0.113.96",
            destination_ip=f"10.20.3.{port % 30}",
            destination_port=port,
            offset_seconds=port,
            blocked=True,
        )
        for port in range(1, 25)
    ]

    assert score(scan_and_sweep) > score(scan_only)
    assert len(
        SuspiciousIPDetector().detect(synthetic.context(scan_and_sweep))[0].evidence["indicators"]
    ) > 1


def test_one_source_yields_one_finding_not_one_per_indicator() -> None:
    entries = [
        synthetic.connection(
            source_ip="203.0.113.95",
            destination_ip=f"10.20.3.{port % 40}",
            destination_port=port,
            offset_seconds=port,
            blocked=True,
        )
        for port in range(1, 80)
    ]
    assert len(SuspiciousIPDetector().detect(synthetic.context(entries))) == 1


def test_a_busy_but_ordinary_source_is_not_suspicious() -> None:
    """High volume to one port on one host is a backup job, not a scan."""
    entries = [
        synthetic.connection(
            source_ip="10.20.6.5",
            destination_ip="10.20.3.15",
            destination_port=443,
            offset_seconds=i,
        )
        for i in range(300)
    ]
    assert SuspiciousIPDetector().detect(synthetic.context(entries)) == []


# --- Event bursts ----------------------------------------------------------


def test_a_burst_is_detected() -> None:
    entries = [
        synthetic.connection(source_ip=f"10.20.4.{i % 20}", offset_seconds=i * 12)
        for i in range(100)
    ]
    # 200 events inside a single minute, from many sources at once.
    entries += [
        synthetic.connection(source_ip=f"10.20.5.{i % 50}", offset_seconds=600 + (i % 60))
        for i in range(200)
    ]

    findings = EventBurstDetector().detect(synthetic.context(entries))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.anomaly_type is AnomalyType.STATISTICAL
    assert finding.evidence["event_count"] >= 200
    assert finding.evidence["modified_z_score"] >= 3.5
    assert finding.evidence["top_sources"]


def test_the_burst_reason_quotes_the_bucket_and_baseline() -> None:
    entries = [
        synthetic.connection(source_ip=f"10.20.4.{i % 20}", offset_seconds=i * 12)
        for i in range(100)
    ]
    entries += [
        synthetic.connection(source_ip=f"10.20.5.{i % 50}", offset_seconds=600 + (i % 60))
        for i in range(200)
    ]
    finding = EventBurstDetector().detect(synthetic.context(entries))[0]

    assert "events in the minute beginning" in finding.reason
    assert "median" in finding.reason


def test_a_hostile_burst_outscores_a_noisy_one() -> None:
    """A spike made of failures is worse than a spike of ordinary traffic.

    Run with a raised saturation so neither variant is pinned at 1.0, where the
    difference would be invisible. Thresholds are dataclass fields precisely so
    they can be tuned per deployment.
    """
    detector = EventBurstDetector(z_saturation=60.0)

    def burst(failed: bool) -> float:
        entries = [
            synthetic.connection(source_ip=f"10.20.4.{i % 20}", offset_seconds=i * 12)
            for i in range(100)
        ]
        for i in range(40):
            if failed:
                entries.append(
                    synthetic.failed_login(
                        source_ip=f"10.20.5.{i % 20}",
                        username=f"u{i % 7}",
                        offset_seconds=600 + (i % 55),
                    )
                )
            else:
                entries.append(
                    synthetic.connection(
                        source_ip=f"10.20.5.{i % 20}", offset_seconds=600 + (i % 55)
                    )
                )
        return detector.detect(synthetic.context(entries))[0].score

    hostile, noisy = burst(failed=True), burst(failed=False)
    assert hostile > noisy
    assert round(hostile - noisy, 4) == 0.1  # the documented bonus


def test_steady_traffic_produces_no_burst() -> None:
    entries = [
        synthetic.connection(source_ip=f"10.20.4.{i % 10}", offset_seconds=i * 6)
        for i in range(600)
    ]
    assert EventBurstDetector().detect(synthetic.context(entries)) == []


def test_bursts_need_enough_buckets_for_a_baseline() -> None:
    """Everything inside two minutes is not evidence of anything."""
    entries = [
        synthetic.connection(source_ip="10.20.4.1", offset_seconds=i % 90) for i in range(200)
    ]
    context = synthetic.context(entries, hours=0.03)
    assert EventBurstDetector().detect(context) == []


# --- Finding identity ------------------------------------------------------


def test_the_same_burst_fingerprints_the_same_twice() -> None:
    entries = [
        synthetic.failed_login(source_ip="203.0.113.47", username="j.okafor", offset_seconds=i)
        for i in range(20)
    ]
    first = BruteForceDetector().detect(synthetic.context(entries))[0]
    second = BruteForceDetector().detect(synthetic.context(entries))[0]

    assert first.fingerprint(None) == second.fingerprint(None)


def test_the_fingerprint_ignores_the_score() -> None:
    """Re-analysis with a slightly different window must not duplicate."""
    entries = [
        synthetic.failed_login(source_ip="203.0.113.47", username="j.okafor", offset_seconds=i)
        for i in range(20)
    ]
    base = BruteForceDetector().detect(synthetic.context(entries))[0]
    hotter = BruteForceDetector().detect(synthetic.context(entries + entries[:5]))[0]

    assert hotter.score != base.score or hotter.evidence != base.evidence
    assert hotter.fingerprint(None) == base.fingerprint(None)


def test_different_targets_fingerprint_differently() -> None:
    def finding_for(account: str) -> Finding:
        entries = [
            synthetic.failed_login(
                source_ip="203.0.113.47", username=account, offset_seconds=i
            )
            for i in range(20)
        ]
        return BruteForceDetector().detect(synthetic.context(entries))[0]

    assert finding_for("alice").fingerprint(None) != finding_for("bob").fingerprint(None)


# --- Every finding is explainable ------------------------------------------


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param(
            [
                synthetic.failed_login(
                    source_ip="203.0.113.47", username="j.okafor", offset_seconds=i
                )
                for i in range(20)
            ],
            id="brute-force",
        ),
        pytest.param(
            [
                synthetic.connection(
                    source_ip="203.0.113.99",
                    destination_port=port,
                    offset_seconds=port,
                    blocked=True,
                )
                for port in range(1, 60)
            ],
            id="port-scan",
        ),
    ],
)
def test_every_finding_carries_its_argument(entries) -> None:
    """A finding with no reason or evidence would not be actionable."""
    findings = []
    for detector in ALL_DETECTORS:
        findings.extend(detector.detect(synthetic.context(entries)))

    assert findings
    for finding in findings:
        assert finding.title
        assert len(finding.reason) > 30
        assert finding.evidence
        assert finding.features
        assert 0.0 <= finding.score <= 1.0
        assert finding.severity in (
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        )
        assert finding.detector and finding.detector_version
        assert finding.entity and finding.window_key
