"""Repeated failed authentication.

Two shapes of the same abuse, which look different in the data and want
different thresholds:

*Brute force* -- one source, one account, many failures. Few attempts are needed
before it is worth reporting, because a legitimate user rarely misses ten times.

*Password spraying* -- one source, one or two attempts against each of many
accounts. The per-account count never trips a brute-force threshold, so the
signal is the *breadth* of accounts touched rather than the depth of attempts.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from app.models.enums import AnomalyType
from app.models.log_entry import LogEntry
from app.services.detection import signals
from app.services.detection.types import DetectionContext, Finding, scale_score


@dataclass(frozen=True, slots=True)
class BruteForceDetector:
    """Counts failed authentications per source and per account."""

    name: str = "rule.brute_force"
    version: str = "1.0"

    # Failures from one source against one account.
    attempt_threshold: int = 5
    attempt_saturation: int = 30
    # Distinct accounts one source failed against.
    spray_account_threshold: int = 5
    spray_account_saturation: int = 25
    # A source that also succeeded somewhere is more interesting, not less.
    success_bonus: float = 0.05

    def detect(self, context: DetectionContext) -> list[Finding]:
        failures = [entry for entry in context.entries if signals.is_failed_auth(entry)]
        if not failures:
            return []

        findings = self._per_account(failures)
        findings.extend(self._spraying(failures, context))
        return findings

    def _per_account(self, failures: list[LogEntry]) -> list[Finding]:
        grouped: dict[tuple[str, str], list[LogEntry]] = defaultdict(list)
        for entry in failures:
            source = entry.source_ip or entry.host or "unknown"
            account = signals.actor(entry) or "unknown"
            grouped[(source, account)].append(entry)

        findings = []
        for (source, account), group in grouped.items():
            count = len(group)
            if count < self.attempt_threshold:
                continue

            first_seen, last_seen = signals.time_span(group)
            score = scale_score(count, self.attempt_threshold, self.attempt_saturation)
            findings.append(
                Finding(
                    detector=self.name,
                    detector_version=self.version,
                    anomaly_type=AnomalyType.THRESHOLD,
                    title=f"Repeated failed logins for {account!r} from {source}",
                    reason=(
                        f"{count} failed authentication attempts against account "
                        f"{account!r} from {source} between {first_seen} and {last_seen}, "
                        f"exceeding the threshold of {self.attempt_threshold}."
                    ),
                    score=score,
                    confidence=0.9,
                    evidence={
                        "source_ip": source,
                        "account": account,
                        "failed_attempts": count,
                        "threshold": self.attempt_threshold,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "sample_log_entry_ids": signals.sample_ids(group),
                    },
                    features={
                        "failed_attempts": count,
                        "distinct_accounts": 1,
                    },
                    mitre_techniques=["T1110"],
                    log_entry_id=group[-1].id,
                    entity=f"{source}|{account}",
                    window_key=first_seen[:13],  # hour precision
                )
            )
        return findings

    def _spraying(self, failures: list[LogEntry], context: DetectionContext) -> list[Finding]:
        by_source: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in failures:
            by_source[entry.source_ip or entry.host or "unknown"].append(entry)

        findings = []
        for source, group in by_source.items():
            accounts = {signals.actor(entry) or "unknown" for entry in group}
            if len(accounts) < self.spray_account_threshold:
                continue

            first_seen, last_seen = signals.time_span(group)
            score = scale_score(
                len(accounts), self.spray_account_threshold, self.spray_account_saturation
            )

            # A source that failed widely *and* succeeded somewhere may already
            # have found a working credential.
            succeeded = [
                entry
                for entry in context.entries
                if (entry.source_ip or entry.host) == source
                and signals.is_auth_event(entry)
                and not signals.is_failure(entry)
            ]
            if succeeded:
                score = min(1.0, score + self.success_bonus)

            findings.append(
                Finding(
                    detector=self.name,
                    detector_version=self.version,
                    anomaly_type=AnomalyType.BEHAVIORAL,
                    title=f"Password spraying from {source}",
                    reason=(
                        f"{source} failed authentication against {len(accounts)} distinct "
                        f"accounts ({len(group)} attempts) between {first_seen} and "
                        f"{last_seen}. Spreading few attempts across many accounts evades "
                        f"per-account lockout."
                        + (
                            f" {len(succeeded)} authentication(s) from this source succeeded "
                            f"in the same window."
                            if succeeded
                            else ""
                        )
                    ),
                    score=score,
                    confidence=0.8,
                    evidence={
                        "source_ip": source,
                        "distinct_accounts": len(accounts),
                        "accounts": sorted(accounts)[:20],
                        "failed_attempts": len(group),
                        "successful_attempts": len(succeeded),
                        "threshold": self.spray_account_threshold,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "sample_log_entry_ids": signals.sample_ids(group),
                    },
                    features={
                        "distinct_accounts": len(accounts),
                        "failed_attempts": len(group),
                        "successful_attempts": len(succeeded),
                    },
                    mitre_techniques=["T1110.003"],
                    log_entry_id=group[-1].id,
                    entity=f"spray|{source}",
                    window_key=first_seen[:13],
                )
            )
        return findings
