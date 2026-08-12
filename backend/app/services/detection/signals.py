"""Reading intent out of a normalised log entry.

Ingestion normalises field *names*, not vocabulary: one product writes
``outcome="failure"``, another ``action="deny"``, a third puts ``login_failed``
in ``event_type``. These helpers are the single place that vocabulary is
interpreted, so a detector asks "did this fail?" rather than matching strings of
its own.

The matching is deliberately conservative. A false negative costs one detection;
a false positive spends an analyst's afternoon.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.models.log_entry import LogEntry

AUTH_MARKERS = ("auth", "login", "logon", "signin", "sign_in", "credential", "password")

FAILURE_MARKERS = (
    "fail", "denied", "deny", "reject", "invalid", "unauthorized", "unauthorised",
    "locked", "lockout", "error", "blocked", "block", "refused",
)

SUCCESS_MARKERS = ("success", "succeeded", "allow", "accept", "granted", "ok", "pass")

BLOCK_MARKERS = ("deny", "denied", "block", "blocked", "drop", "dropped", "reject", "refused")


def _haystack(entry: LogEntry, *, include_message: bool = False) -> str:
    """The fields worth searching, lower-cased and joined.

    The message is excluded by default: it is free text, and matching "failed"
    inside a sentence turns a successful login that mentions a previous failure
    into a failure.
    """
    parts = [entry.event_type, entry.action, entry.outcome, entry.category]
    if include_message:
        parts.append(entry.message)
    return " ".join(part.lower() for part in parts if part)


def _contains(haystack: str, markers: Iterable[str]) -> bool:
    return any(marker in haystack for marker in markers)


def is_auth_event(entry: LogEntry) -> bool:
    """Whether the entry concerns authentication."""
    return _contains(_haystack(entry), AUTH_MARKERS)


def is_failure(entry: LogEntry) -> bool:
    """Whether the entry records something that did not succeed.

    An explicit success in ``outcome`` wins over a failure marker elsewhere, so
    ``event_type="auth.login"`` with ``outcome="success"`` is never a failure.
    """
    outcome = (entry.outcome or "").lower()
    if outcome and _contains(outcome, SUCCESS_MARKERS):
        return False
    return _contains(_haystack(entry), FAILURE_MARKERS)


def is_failed_auth(entry: LogEntry) -> bool:
    """A failed authentication attempt: the brute-force signal."""
    return is_auth_event(entry) and is_failure(entry)


def is_blocked(entry: LogEntry) -> bool:
    """Whether a control refused the traffic."""
    return _contains(_haystack(entry), BLOCK_MARKERS)


def actor(entry: LogEntry) -> str | None:
    """The account an entry is about, if it names one."""
    return entry.username or None


def sample_ids(entries: Iterable[LogEntry], limit: int = 10) -> list[str]:
    """Entry ids an analyst can pull up to check a finding.

    Capped: a finding backed by 40,000 events must not write 40,000 ids into
    its evidence.
    """
    return [str(entry.id) for entry in list(entries)[:limit]]


def time_span(entries: list[LogEntry]) -> tuple[str, str]:
    """First and last event timestamps in a group, as ISO strings."""
    stamps = sorted(entry.event_timestamp for entry in entries)
    return stamps[0].isoformat(), stamps[-1].isoformat()
