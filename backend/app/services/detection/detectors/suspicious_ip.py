"""Source addresses whose behaviour has a recognisable shape.

Volume alone says little; what an address *did* says more. Three shapes are
worth reporting on their own, and each is stronger when they co-occur:

*Port scanning* -- one source, one or few hosts, many destination ports.
*Host sweeping* -- one source, one or few ports, many destination hosts.
*Sustained rejection* -- most of what a source sent was refused by a control.

Each contributes to one finding per address rather than three, so an analyst
sees "this address is behaving like a scanner" once, with the reasons listed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.models.enums import AnomalyType
from app.models.log_entry import LogEntry
from app.services.detection import signals
from app.services.detection.types import BASE_SCORE, DetectionContext, Finding


@dataclass(frozen=True, slots=True)
class SuspiciousIPDetector:
    """Recognises scanning, sweeping and repeatedly blocked sources."""

    name: str = "rule.suspicious_ip"
    version: str = "1.0"

    port_threshold: int = 15
    port_saturation: int = 100
    host_threshold: int = 10
    host_saturation: int = 60
    # Rejection is only meaningful once there is enough traffic to have a ratio.
    min_events_for_ratio: int = 10
    blocked_ratio_threshold: float = 0.8

    def detect(self, context: DetectionContext) -> list[Finding]:
        by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in context.entries:
            if entry.source_ip:
                by_ip[entry.source_ip].append(entry)

        findings = []
        for ip, group in by_ip.items():
            finding = self._assess(ip, group)
            if finding is not None:
                findings.append(finding)
        return findings

    def _assess(self, ip: str, group: list[LogEntry]) -> Finding | None:
        ports = {e.destination_port for e in group if e.destination_port is not None}
        hosts = {e.destination_ip for e in group if e.destination_ip}
        blocked = [e for e in group if signals.is_blocked(e)]
        blocked_ratio = len(blocked) / len(group) if group else 0.0

        reasons: list[str] = []
        scores: list[float] = []
        indicators: dict[str, Any] = {}

        if len(ports) >= self.port_threshold:
            reasons.append(
                f"contacted {len(ports)} distinct destination ports across "
                f"{len(hosts) or 1} host(s), consistent with a port scan"
            )
            scores.append(self._ramp(len(ports), self.port_threshold, self.port_saturation))
            indicators["port_scan"] = True

        if len(hosts) >= self.host_threshold:
            reasons.append(
                f"contacted {len(hosts)} distinct destination hosts, consistent with a "
                f"host sweep"
            )
            scores.append(self._ramp(len(hosts), self.host_threshold, self.host_saturation))
            indicators["host_sweep"] = True

        enough_traffic = len(group) >= self.min_events_for_ratio
        if enough_traffic and blocked_ratio >= self.blocked_ratio_threshold:
            reasons.append(
                f"{len(blocked)} of {len(group)} events ({blocked_ratio:.0%}) were blocked "
                f"or denied by a control"
            )
            scores.append(self._ramp(blocked_ratio, self.blocked_ratio_threshold, 1.0))
            indicators["mostly_blocked"] = True

        if not reasons:
            return None

        # Several shapes at once is a stronger signal than the worst alone.
        score = max(scores)
        if len(scores) > 1:
            score = min(1.0, score + 0.1 * (len(scores) - 1))

        first_seen, last_seen = signals.time_span(group)
        return Finding(
            detector=self.name,
            detector_version=self.version,
            anomaly_type=AnomalyType.BEHAVIORAL,
            title=f"Suspicious activity from {ip}",
            reason=(
                f"Source {ip} " + "; ".join(reasons) + f", between {first_seen} and {last_seen}."
            ),
            score=round(score, 4),
            confidence=0.75,
            evidence={
                "source_ip": ip,
                "indicators": sorted(indicators),
                "event_count": len(group),
                "distinct_destination_ports": len(ports),
                "distinct_destination_hosts": len(hosts),
                "blocked_events": len(blocked),
                "blocked_ratio": round(blocked_ratio, 3),
                "ports_sample": sorted(p for p in ports if p is not None)[:25],
                "hosts_sample": sorted(hosts)[:25],
                "first_seen": first_seen,
                "last_seen": last_seen,
                "sample_log_entry_ids": signals.sample_ids(group),
            },
            features={
                "distinct_destination_ports": len(ports),
                "distinct_destination_hosts": len(hosts),
                "blocked_ratio": round(blocked_ratio, 3),
                "event_count": len(group),
            },
            mitre_techniques=["T1046"],
            log_entry_id=group[-1].id,
            entity=f"suspicious_ip|{ip}",
            window_key=first_seen[:13],
        )

    @staticmethod
    def _ramp(observed: float, threshold: float, saturation: float) -> float:
        if saturation <= threshold:
            return 1.0
        ratio = min(max((observed - threshold) / (saturation - threshold), 0.0), 1.0)
        return BASE_SCORE + (1.0 - BASE_SCORE) * ratio
