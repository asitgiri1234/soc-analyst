"""Sources whose request volume is unlike their peers'.

The baseline is the other sources in the same window rather than a fixed rate:
"200 requests an hour" means nothing without knowing whether the neighbours sent
2 or 2,000. Comparing an entity against its peers needs no historical state and
adapts to a quiet Sunday as readily as a busy Monday.

Two guards keep this quiet on normal traffic. A minimum population, because
"unlike its peers" is meaningless with three peers; and an absolute floor, so a
host sending 4 events where everyone else sent 1 is not reported as a flood.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from app.models.enums import AnomalyType
from app.models.log_entry import LogEntry
from app.services.detection import signals, statistics
from app.services.detection.types import DetectionContext, Finding, scale_score


@dataclass(frozen=True, slots=True)
class RequestFrequencyDetector:
    """Flags sources far above the median volume for the window."""

    name: str = "statistical.request_frequency"
    version: str = "1.0"

    # Distinct sources needed before a median means anything.
    min_population: int = 5
    # An entity must clear this many events regardless of how quiet its peers are.
    min_events: int = 20
    # Robust z-score at which to report, and at which to saturate the score.
    z_threshold: float = 3.5
    z_saturation: float = 12.0

    def detect(self, context: DetectionContext) -> list[Finding]:
        by_source: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in context.entries:
            key = entry.source_ip or entry.host
            if key:
                by_source[key].append(entry)

        if len(by_source) < self.min_population:
            return []

        counts = {source: len(group) for source, group in by_source.items()}
        population = list(counts.values())
        baseline = statistics.summarise([float(value) for value in population])

        findings = []
        for source, count in counts.items():
            if count < self.min_events:
                continue

            z = statistics.modified_z_score(float(count), [float(v) for v in population])
            if z < self.z_threshold:
                continue

            group = by_source[source]
            first_seen, last_seen = signals.time_span(group)
            score = scale_score(z, self.z_threshold, self.z_saturation)

            # Rate over the source's own active span, not the requested window:
            # 60 events in a minute is 60/min whether the analyst asked for the
            # last hour or the last month. Floored at one minute so a handful of
            # events milliseconds apart does not report an absurd rate.
            span = max(
                (
                    max(e.event_timestamp for e in group)
                    - min(e.event_timestamp for e in group)
                ).total_seconds(),
                60.0,
            )
            rate = round(count / (span / 60.0), 3)

            findings.append(
                Finding(
                    detector=self.name,
                    detector_version=self.version,
                    anomaly_type=AnomalyType.STATISTICAL,
                    title=f"Unusual request volume from {source}",
                    reason=(
                        f"{source} generated {count} events ({rate}/min) while the median "
                        f"across {baseline['count']} active sources was "
                        f"{baseline['median']:.0f}. That is {z:.1f} robust deviations above "
                        f"the median, past the reporting threshold of {self.z_threshold}."
                    ),
                    score=score,
                    confidence=0.7,
                    evidence={
                        "source": source,
                        "event_count": count,
                        "events_per_minute": rate,
                        "active_span_seconds": round(span, 1),
                        "population_median": baseline["median"],
                        "population_mad": baseline["mad"],
                        "active_sources": baseline["count"],
                        "modified_z_score": round(z, 3),
                        "z_threshold": self.z_threshold,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "sample_log_entry_ids": signals.sample_ids(group),
                    },
                    features={
                        "event_count": count,
                        "events_per_minute": rate,
                        "modified_z_score": round(z, 3),
                    },
                    mitre_techniques=["T1498"],
                    log_entry_id=group[-1].id,
                    entity=f"frequency|{source}",
                    window_key=context.window_start.isoformat()[:13],
                )
            )
        return findings
