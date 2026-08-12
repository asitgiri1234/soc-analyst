"""Synthetic security logs for the detection tests.

Builds LogEntry objects in memory without a database, so the detectors can be
tested as pure functions. Everything is deterministic: no randomness, so a
failure reproduces exactly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.enums import Severity
from app.models.log_entry import LogEntry
from app.services.detection.types import DetectionContext

BASE_TIME = datetime(2026, 8, 10, 9, 0, 0, tzinfo=UTC)


def entry(
    *,
    offset_seconds: float = 0,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    event_type: str | None = None,
    outcome: str | None = None,
    action: str | None = None,
    username: str | None = None,
    host: str | None = None,
    message: str = "synthetic event",
    severity: Severity = Severity.INFO,
    at: datetime | None = None,
) -> LogEntry:
    """One log entry, already normalised as ingestion would leave it."""
    return LogEntry(
        id=uuid.uuid4(),
        log_source_id=uuid.uuid4(),
        event_timestamp=at or BASE_TIME + timedelta(seconds=offset_seconds),
        message=message,
        severity=severity,
        event_type=event_type,
        outcome=outcome,
        action=action,
        username=username,
        host=host,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        attributes={},
    )


def failed_login(
    *, source_ip: str, username: str, offset_seconds: float = 0, host: str = "sso-01"
) -> LogEntry:
    return entry(
        offset_seconds=offset_seconds,
        source_ip=source_ip,
        username=username,
        host=host,
        event_type="auth.login_failed",
        outcome="failure",
        severity=Severity.MEDIUM,
        message=f"Password authentication failed for {username}",
    )


def successful_login(
    *, source_ip: str, username: str, offset_seconds: float = 0, host: str = "sso-01"
) -> LogEntry:
    return entry(
        offset_seconds=offset_seconds,
        source_ip=source_ip,
        username=username,
        host=host,
        event_type="auth.login_succeeded",
        outcome="success",
        message=f"Login succeeded for {username}",
    )


def connection(
    *,
    source_ip: str,
    destination_ip: str = "10.20.3.15",
    destination_port: int = 443,
    offset_seconds: float = 0,
    blocked: bool = False,
) -> LogEntry:
    return entry(
        offset_seconds=offset_seconds,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        event_type="firewall.connection_blocked" if blocked else "firewall.connection_allowed",
        action="deny" if blocked else "allow",
        outcome="blocked" if blocked else "success",
        message="Connection " + ("blocked" if blocked else "allowed"),
    )


def normal_traffic(
    *, sources: int = 8, per_source: int = 12, spread_seconds: int = 3600
) -> list[LogEntry]:
    """A quiet, unremarkable window.

    Even volume across several sources, a couple of isolated login failures of
    the kind that happen every day, and nothing that should be reported.
    """
    entries: list[LogEntry] = []
    step = spread_seconds / max(sources * per_source, 1)
    tick = 0

    for index in range(sources):
        source_ip = f"10.20.4.{10 + index}"
        for item in range(per_source):
            tick += 1
            entries.append(
                connection(
                    source_ip=source_ip,
                    destination_ip="10.20.3.15",
                    destination_port=443 if item % 2 else 80,
                    offset_seconds=tick * step,
                )
            )

    # One user fumbling their password twice is normal, not an attack.
    entries.append(failed_login(source_ip="10.20.4.11", username="a.novak", offset_seconds=120))
    entries.append(failed_login(source_ip="10.20.4.11", username="a.novak", offset_seconds=180))
    entries.append(
        successful_login(source_ip="10.20.4.11", username="a.novak", offset_seconds=240)
    )
    return entries


def context(entries: list[LogEntry], *, hours: float = 1.0) -> DetectionContext:
    """Wrap entries in a window that comfortably contains them."""
    if entries:
        start = min(item.event_timestamp for item in entries)
        end = max(item.event_timestamp for item in entries)
    else:
        start = BASE_TIME
        end = BASE_TIME + timedelta(hours=hours)
    return DetectionContext(
        entries=sorted(entries, key=lambda item: item.event_timestamp),
        window_start=start,
        window_end=max(end, start + timedelta(hours=hours)),
    )
