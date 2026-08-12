"""Moments when the whole feed spikes.

The frequency detector compares sources against each other; this one compares
the feed against itself over time. They catch different things: a burst can come
from hundreds of sources at once, where no individual source stands out, and a
single loud source can run steadily without ever producing a spike.

Traffic is bucketed by minute and each bucket compared against the others by
robust z-score. Empty buckets count as zeros -- silence is part of the baseline,
and dropping it would make any activity after a lull look normal.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.models.enums import AnomalyType
from app.models.log_entry import LogEntry
from app.services.detection import signals, statistics
from app.services.detection.types import DetectionContext, Finding, scale_score


@dataclass(frozen=True, slots=True)
class EventBurstDetector:
    """Flags time buckets far above the window's typical rate."""

    name: str = "statistical.event_burst"
    version: str = "1.0"

    bucket_seconds: int = 60
    # Buckets needed before "typical" is a meaningful idea.
    min_buckets: int = 10
    # A bucket must hold this many events regardless of how quiet the rest were.
    min_events: int = 30
    z_threshold: float = 3.5
    z_saturation: float = 12.0
    # Bursts made mostly of failures or blocks are worse than bursts of noise.
    hostile_ratio: float = 0.5

    def detect(self, context: DetectionContext) -> list[Finding]:
        if not context.entries:
            return []

        bucketed: dict[datetime, list[LogEntry]] = defaultdict(list)
        for entry in context.entries:
            bucketed[self._bucket(entry.event_timestamp)].append(entry)

        counts = self._series(bucketed, context)
        if len(counts) < self.min_buckets:
            return []

        population = [float(count) for count in counts.values()]
        baseline = statistics.summarise(population)

        findings = []
        for bucket, count in counts.items():
            if count < self.min_events:
                continue

            z = statistics.modified_z_score(float(count), population)
            if z < self.z_threshold:
                continue

            group = bucketed[bucket]
            findings.append(self._finding(bucket, group, count, z, baseline, context))
        return findings

    def _bucket(self, moment: datetime) -> datetime:
        epoch = int(moment.timestamp())
        return datetime.fromtimestamp(
            epoch - (epoch % self.bucket_seconds), tz=moment.tzinfo
        )

    def _series(
        self, bucketed: dict[datetime, list[LogEntry]], context: DetectionContext
    ) -> dict[datetime, int]:
        """Bucket counts across the whole window, including the empty buckets."""
        counts = {bucket: len(group) for bucket, group in bucketed.items()}
        start = self._bucket(context.window_start)
        end = self._bucket(context.window_end)
        step = timedelta(seconds=self.bucket_seconds)

        # Guard against an implausibly long window producing millions of zeros.
        span = int((end - start).total_seconds() // self.bucket_seconds) + 1
        if span > 10_000:
            return counts

        cursor = start
        while cursor <= end:
            counts.setdefault(cursor, 0)
            cursor += step
        return counts

    def _finding(
        self,
        bucket: datetime,
        group: list[LogEntry],
        count: int,
        z: float,
        baseline: dict[str, float],
        context: DetectionContext,
    ) -> Finding:
        failures = [entry for entry in group if signals.is_failure(entry)]
        hostile_ratio = len(failures) / count if count else 0.0
        score = scale_score(z, self.z_threshold, self.z_saturation)

        top_sources = Counter(
            entry.source_ip or entry.host or "unknown" for entry in group
        ).most_common(5)
        top_types = Counter(entry.event_type or "unknown" for entry in group).most_common(5)

        reason = (
            f"{count} events in the minute beginning {bucket.isoformat()}, against a median "
            f"of {baseline['median']:.0f} across {baseline['count']} buckets "
            f"({z:.1f} robust deviations above it)."
        )
        if hostile_ratio >= self.hostile_ratio:
            reason += f" {hostile_ratio:.0%} of the burst was failures or denials."
            score = min(1.0, score + 0.1)

        finding = Finding(
            detector=self.name,
            detector_version=self.version,
            anomaly_type=AnomalyType.STATISTICAL,
            title=f"Event burst at {bucket.isoformat()}",
            reason=reason,
            score=round(score, 4),
            confidence=0.7,
            evidence={
                "bucket_start": bucket.isoformat(),
                "bucket_seconds": self.bucket_seconds,
                "event_count": count,
                "baseline_median": baseline["median"],
                "baseline_mad": baseline["mad"],
                "buckets_considered": baseline["count"],
                "modified_z_score": round(z, 3),
                "z_threshold": self.z_threshold,
                "failure_ratio": round(hostile_ratio, 3),
                "top_sources": [{"source": s, "events": c} for s, c in top_sources],
                "top_event_types": [{"event_type": t, "events": c} for t, c in top_types],
                "sample_log_entry_ids": signals.sample_ids(group),
            },
            features={
                "event_count": count,
                "modified_z_score": round(z, 3),
                "failure_ratio": round(hostile_ratio, 3),
            },
            mitre_techniques=["T1498"],
            log_entry_id=group[-1].id,
            entity=f"burst|{context.log_source_id or 'all'}",
            window_key=bucket.isoformat(),
        )
        return finding
