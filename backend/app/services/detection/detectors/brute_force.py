"""Repeated failed authentication.

Two shapes of the same abuse, which look different in the data and want
different thresholds:

*Brute force* -- one source, one account, many failures. Few attempts are needed
before it is worth reporting, because a legitimate user rarely misses ten times.

*Password spraying* -- one source, one or two attempts against each of many
accounts. The per-account count never trips a brute-force threshold, so the
signal is the *breadth* of accounts touched rather than the depth of attempts.

SCORING
-------
The attempt count alone is a weak discriminator. Ten failures spread over a
working day is a forgetful employee; ten in five seconds is a script. Counting
only the failures rated both the same, which under-reported obvious attacks:
a textbook burst against a nonexistent account scored MEDIUM because it had not
yet reached twenty attempts.

So the count sets a floor and corroborating signals raise it:

* **rate** -- attempts per minute, against what a human could physically type
* **invalid user** -- attempts against accounts that do not exist, which no
  amount of forgetfulness explains
* **service penalty** -- the daemon itself reporting that it is throttling the
  client, i.e. the system under attack has already reached this conclusion
* **success after failures** -- the source eventually got in, which is the
  most serious shape this detector sees

Each raises the score through the *remaining headroom* rather than adding
flatly, so ordering by attempt count is preserved -- more attempts always
outrank fewer given the same corroboration -- while a modest count with strong
corroboration still reaches HIGH.

Confidence is derived the same way: it reflects how much independent evidence
agrees, not a constant the detector asserts about itself.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from app.core.config import settings
from app.models.enums import AnomalyType
from app.models.log_entry import LogEntry
from app.services.detection import signals
from app.services.detection.types import DetectionContext, Finding, scale_score


@dataclass(frozen=True, slots=True)
class BruteForceDetector:
    """Counts failed authentications per source and per account.

    Every threshold is a field with a settings-backed default, so a deployment
    tunes them through configuration and a test constructs the detector with
    explicit values instead of monkey-patching globals.
    """

    name: str = "rule.brute_force"
    version: str = "2.0"

    # Failures from one source against one account.
    attempt_threshold: int = field(
        default_factory=lambda: settings.BRUTE_FORCE_ATTEMPT_THRESHOLD
    )
    attempt_saturation: int = field(
        default_factory=lambda: settings.BRUTE_FORCE_ATTEMPT_SATURATION
    )
    # Attempts per minute at or above which the burst is machine-driven.
    machine_rate_per_minute: float = field(
        default_factory=lambda: settings.BRUTE_FORCE_MACHINE_RATE_PER_MINUTE
    )
    # How much each corroborating signal may close the gap to 1.0.
    rate_weight: float = field(
        default_factory=lambda: settings.BRUTE_FORCE_RATE_WEIGHT
    )
    invalid_user_weight: float = field(
        default_factory=lambda: settings.BRUTE_FORCE_INVALID_USER_WEIGHT
    )
    penalty_weight: float = field(
        default_factory=lambda: settings.BRUTE_FORCE_PENALTY_WEIGHT
    )
    success_weight: float = field(
        default_factory=lambda: settings.BRUTE_FORCE_SUCCESS_WEIGHT
    )
    # Distinct accounts one source failed against.
    spray_account_threshold: int = field(
        default_factory=lambda: settings.BRUTE_FORCE_SPRAY_ACCOUNT_THRESHOLD
    )
    spray_account_saturation: int = field(
        default_factory=lambda: settings.BRUTE_FORCE_SPRAY_ACCOUNT_SATURATION
    )
    # A source that also succeeded somewhere is more interesting, not less.
    success_bonus: float = 0.05

    def detect(self, context: DetectionContext) -> list[Finding]:
        failures = [entry for entry in context.entries if signals.is_failed_auth(entry)]
        if not failures:
            return []

        findings = self._per_account(failures, context)
        findings.extend(self._spraying(failures, context))
        return findings

    def _attempt_rate(self, group: list[LogEntry]) -> float:
        """Failed attempts per minute across the group's own span.

        Measured over the span of the attempts themselves, not the analysis
        window: sixty failures in a minute is a script whether the request
        asked about the last hour or the last month.
        """
        first, last = min(e.event_timestamp for e in group), max(
            e.event_timestamp for e in group
        )
        span_seconds = max((last - first).total_seconds(), 1.0)
        return len(group) * 60.0 / span_seconds

    def _per_account(
        self, failures: list[LogEntry], context: DetectionContext
    ) -> list[Finding]:
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
            base = scale_score(count, self.attempt_threshold, self.attempt_saturation)

            # --- Corroborating signals ---------------------------------
            rate = self._attempt_rate(group)
            rate_factor = min(1.0, rate / self.machine_rate_per_minute)

            invalid_hits = sum(1 for entry in group if signals.is_invalid_user(entry))
            invalid_ratio = invalid_hits / count

            penalty_hits = sum(1 for entry in group if signals.has_auth_penalty(entry))

            # Did this source get in, against any account, after it started
            # failing? A working credential changes what this incident is.
            first_failure = min(entry.event_timestamp for entry in group)
            succeeded = [
                entry
                for entry in context.entries
                if (entry.source_ip or entry.host or "unknown") == source
                and signals.is_auth_event(entry)
                and not signals.is_failure(entry)
                and entry.event_timestamp >= first_failure
            ]

            # Each signal closes part of the gap between the count-based score
            # and certainty. Proportional rather than additive, so a bigger
            # count always outranks a smaller one given equal corroboration.
            boost = min(
                1.0,
                self.rate_weight * rate_factor
                + self.invalid_user_weight * invalid_ratio
                + self.penalty_weight * (1.0 if penalty_hits else 0.0)
                + self.success_weight * (1.0 if succeeded else 0.0),
            )
            score = round(min(1.0, base + (1.0 - base) * boost), 4)

            corroboration = [
                name
                for name, present in (
                    ("machine_speed", rate_factor >= 1.0),
                    ("invalid_user", invalid_ratio > 0),
                    ("service_penalty", penalty_hits > 0),
                    ("succeeded_after_failures", bool(succeeded)),
                )
                if present
            ]

            # Confidence is about the evidence, not the severity: how much
            # independent signal agrees that this is what it looks like.
            count_ratio = min(
                1.0,
                (count - self.attempt_threshold)
                / max(self.attempt_saturation - self.attempt_threshold, 1),
            )
            confidence = round(
                min(0.99, 0.60 + 0.20 * count_ratio + 0.08 * len(corroboration)), 4
            )

            reason = (
                f"{count} failed authentication attempts against account "
                f"{account!r} from {source} between {first_seen} and {last_seen}, "
                f"exceeding the threshold of {self.attempt_threshold}."
            )
            if rate_factor >= 1.0:
                reason += (
                    f" Sustained {rate:.1f} attempts/minute, at or above the "
                    f"{self.machine_rate_per_minute:.0f}/minute expected of an "
                    f"automated tool rather than a person."
                )
            if invalid_hits:
                reason += (
                    f" {invalid_hits} of the attempts targeted an account the system "
                    f"does not recognise, which credential error does not explain."
                )
            if penalty_hits:
                reason += (
                    f" The service reported throttling or penalising this client "
                    f"{penalty_hits} time(s)."
                )
            if succeeded:
                reason += (
                    f" {len(succeeded)} authentication(s) from this source SUCCEEDED "
                    f"after the failures began; treat the credential as compromised."
                )

            findings.append(
                Finding(
                    detector=self.name,
                    detector_version=self.version,
                    anomaly_type=AnomalyType.THRESHOLD,
                    title=f"Repeated failed logins for {account!r} from {source}",
                    reason=reason,
                    score=score,
                    confidence=confidence,
                    evidence={
                        "source_ip": source,
                        "account": account,
                        "failed_attempts": count,
                        "threshold": self.attempt_threshold,
                        "attempts_per_minute": round(rate, 2),
                        "machine_rate_threshold": self.machine_rate_per_minute,
                        "invalid_user_attempts": invalid_hits,
                        "service_penalties": penalty_hits,
                        "successful_after_failures": len(succeeded),
                        "corroborating_signals": corroboration,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "sample_log_entry_ids": signals.sample_ids(group),
                    },
                    features={
                        "failed_attempts": count,
                        "distinct_accounts": 1,
                        "base_score": base,
                        "rate_factor": round(rate_factor, 4),
                        "invalid_user_ratio": round(invalid_ratio, 4),
                        "penalty_present": bool(penalty_hits),
                        "success_after_failures": bool(succeeded),
                        "evidence_boost": round(boost, 4),
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
