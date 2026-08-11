"""Mapping a vendor's field names onto the LogEntry schema.

Every product spells the same things differently -- ``src_ip``, ``srcip``,
``source_address``, ``saddr`` -- so keys are canonicalised and looked up against
an alias table rather than matched exactly.

Two rules shape the rest:

*Nothing is discarded.* Fields that map to no column are kept in ``attributes``,
so a query can still reach them later.

*A field that fails to parse does not fail the record.* An unparseable IP is
left null and its original value preserved in ``attributes``; only a missing or
unparseable timestamp rejects the row, because an event that cannot be placed in
time is of no use to an investigation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any

from app.models.enums import Severity
from app.services.ingestion.types import RawRecord, RowError

# --- Field aliases ---------------------------------------------------------

ALIASES: dict[str, set[str]] = {
    "event_timestamp": {
        "timestamp", "time", "ts", "datetime", "date", "event_time", "eventtime",
        "event_timestamp", "occurred_at", "logged_at", "start_time", "first_seen",
    },
    "message": {
        "message", "msg", "description", "text", "summary", "details", "raw_message",
    },
    "source_ip": {
        "source_ip", "src_ip", "srcip", "src", "source", "client_ip", "clientip",
        "source_address", "src_addr", "saddr", "ip_src", "remote_addr", "remote_ip",
    },
    "destination_ip": {
        "destination_ip", "dest_ip", "dst_ip", "dstip", "dst", "destination",
        "server_ip", "destination_address", "dst_addr", "daddr", "ip_dst", "local_ip",
    },
    "source_port": {"source_port", "src_port", "sport", "spt", "client_port"},
    "destination_port": {
        "destination_port", "dest_port", "dst_port", "dport", "dpt", "server_port",
    },
    "event_type": {
        "event_type", "eventtype", "type", "event", "event_name", "eventname",
        "signature", "rule_name", "rule", "alert_type",
    },
    "severity": {"severity", "level", "priority", "log_level", "loglevel", "sev"},
    "action": {"action", "act", "disposition", "verdict", "operation"},
    "outcome": {"outcome", "result", "status", "event_outcome", "success"},
    "category": {"category", "cat", "class", "event_category", "facility"},
    "host": {
        "host", "hostname", "device", "device_name", "computer", "computer_name",
        "agent_host", "source_host", "machine",
    },
    "process": {"process", "process_name", "proc", "application", "app", "service"},
    "username": {
        "username", "user", "user_name", "account", "account_name", "subject_user",
        "login", "user_id", "actor",
    },
    "protocol": {"protocol", "proto", "ip_protocol", "transport"},
}

# Inverted for lookup: canonical alias -> target column.
_LOOKUP: dict[str, str] = {
    alias: target for target, aliases in ALIASES.items() for alias in aliases
}

# Fields whose contents are merged into attributes rather than mapped.
METADATA_KEYS = {"metadata", "meta", "extra", "fields", "labels", "tags", "attributes"}

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

MAX_MESSAGE_LENGTH = 8192


def canonical_key(key: str) -> str:
    """Reduce a field name to a comparable form: ``"Source IP" -> "source_ip"``."""
    return _NON_ALNUM.sub("_", key.strip().lower()).strip("_")


# --- Value parsing ---------------------------------------------------------

# Formats tried in order, after ISO 8601 and epoch.
TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",  # Apache / nginx
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%b %d %Y %H:%M:%S",
    "%a, %d %b %Y %H:%M:%S %z",  # RFC 822
)

# Seconds beyond which a numeric timestamp must be milliseconds. 10**11 seconds
# is the year 5138, so anything larger is not a second count.
_MILLISECOND_THRESHOLD = 10**11


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp, returning None when the value is not one.

    A value without a timezone is read as UTC: guessing the server's local zone
    would silently shift every event by the operator's offset.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _from_epoch(float(value))

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    # Epoch as a string, with or without fractional seconds.
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return _from_epoch(float(text))

    # fromisoformat covers most machine-written timestamps, including 'Z'.
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is not None:
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    for fmt in TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    return None


def _from_epoch(number: float) -> datetime | None:
    if abs(number) >= _MILLISECOND_THRESHOLD:
        number /= 1000.0
    try:
        return datetime.fromtimestamp(number, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def parse_ip(value: Any) -> str | None:
    """Return a valid IPv4/IPv6 address, or None.

    Rejecting anything else keeps PostgreSQL's INET column from raising mid-batch
    and taking the surrounding rows down with it.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def parse_port(value: Any) -> int | None:
    """Return a port in range, or None."""
    if isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


SEVERITY_WORDS: dict[str, Severity] = {
    "emerg": Severity.CRITICAL, "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL, "crit": Severity.CRITICAL,
    "critical": Severity.CRITICAL, "fatal": Severity.CRITICAL, "severe": Severity.CRITICAL,
    "err": Severity.HIGH, "error": Severity.HIGH, "high": Severity.HIGH,
    "warn": Severity.MEDIUM, "warning": Severity.MEDIUM, "medium": Severity.MEDIUM,
    "notice": Severity.LOW, "low": Severity.LOW,
    "info": Severity.INFO, "information": Severity.INFO, "informational": Severity.INFO,
    "debug": Severity.INFO, "trace": Severity.INFO, "none": Severity.INFO,
}

# Syslog numeric levels, RFC 5424.
SEVERITY_NUMBERS: dict[int, Severity] = {
    0: Severity.CRITICAL, 1: Severity.CRITICAL, 2: Severity.CRITICAL,
    3: Severity.HIGH, 4: Severity.MEDIUM, 5: Severity.LOW,
    6: Severity.INFO, 7: Severity.INFO,
}


def parse_severity(value: Any) -> Severity | None:
    """Map a vendor severity onto the platform's five-point scale."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return SEVERITY_NUMBERS.get(value)

    text = str(value).strip().lower()
    if not text:
        return None
    if text.isdigit():
        return SEVERITY_NUMBERS.get(int(text))
    return SEVERITY_WORDS.get(text)


def _clean_text(value: Any, limit: int) -> str | None:
    """Render a scalar as trimmed text, or None when it is empty."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    text = text.strip()
    if not text:
        return None
    return text[:limit]


# --- Normalisation ---------------------------------------------------------


def normalize(record: RawRecord) -> tuple[dict[str, Any] | None, RowError | None]:
    """Map one raw record onto LogEntry columns.

    Returns the column values, or a RowError explaining why the record could not
    be used. Exactly one of the two is not None.
    """
    if not record.data:
        return None, RowError(line=record.line, reason="record is empty")

    mapped: dict[str, Any] = {}
    attributes: dict[str, Any] = {}

    for key, value in record.data.items():
        canonical = canonical_key(str(key))
        if not canonical:
            continue

        if canonical in METADATA_KEYS:
            attributes.update(_as_attributes(canonical, value))
            continue

        target = _LOOKUP.get(canonical)
        # First alias wins: a later column named "source" must not overwrite the
        # "src_ip" already mapped.
        if target is None or target in mapped:
            attributes.setdefault(canonical, value)
            continue
        mapped[target] = value

    timestamp = parse_timestamp(mapped.get("event_timestamp"))
    if timestamp is None:
        raw_value = mapped.get("event_timestamp")
        if raw_value is None:
            reason = "no timestamp field found"
        elif isinstance(raw_value, str) and not raw_value.strip():
            reason = "timestamp is empty"
        else:
            reason = f"unparseable timestamp {raw_value!r}"
        return None, RowError(line=record.line, reason=reason, field="timestamp")

    values: dict[str, Any] = {
        "event_timestamp": timestamp,
        "severity": parse_severity(mapped.get("severity")) or Severity.INFO,
        "event_type": _clean_text(mapped.get("event_type"), 128),
        "action": _clean_text(mapped.get("action"), 128),
        "outcome": _clean_text(mapped.get("outcome"), 32),
        "category": _clean_text(mapped.get("category"), 64),
        "host": _clean_text(mapped.get("host"), 255),
        "process": _clean_text(mapped.get("process"), 255),
        "username": _clean_text(mapped.get("username"), 255),
        "protocol": _clean_text(mapped.get("protocol"), 16),
        "source_port": parse_port(mapped.get("source_port")),
        "destination_port": parse_port(mapped.get("destination_port")),
        "raw": record.raw,
    }

    # A value that looked like an address but was not one is kept verbatim, so
    # the information is not lost to a null column.
    for column in ("source_ip", "destination_ip"):
        original = mapped.get(column)
        parsed = parse_ip(original)
        values[column] = parsed
        if parsed is None and original not in (None, ""):
            attributes.setdefault(column, original)

    # A severity that was present but unrecognised is worth keeping.
    if mapped.get("severity") is not None and parse_severity(mapped["severity"]) is None:
        attributes.setdefault("severity", mapped["severity"])

    message = _clean_text(mapped.get("message"), MAX_MESSAGE_LENGTH)
    if message is None:
        # message is NOT NULL, and a record with no obvious message field still
        # carries its own content; fall back to the rendered record.
        message = record.raw[:MAX_MESSAGE_LENGTH]
    values["message"] = message

    values["attributes"] = _jsonable(attributes)
    values["fingerprint"] = _fingerprint(values)
    return values, None


def _as_attributes(key: str, value: Any) -> dict[str, Any]:
    """Merge a metadata field, whatever shape it arrived in."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{"):
            try:
                decoded = json.loads(text)
            except ValueError:
                return {key: value}
            if isinstance(decoded, dict):
                return decoded
    return {key: value}


def _jsonable(data: dict[str, Any]) -> dict[str, Any]:
    """Coerce attribute values to something JSONB will accept."""
    cleaned: dict[str, Any] = {}
    for key, value in data.items():
        if value is None or isinstance(value, (str, int, float, bool, list, dict)):
            cleaned[key] = value
        else:
            cleaned[key] = str(value)
    return cleaned


def _fingerprint(values: dict[str, Any]) -> str:
    """Stable hash of the identifying fields, for spotting redelivered events."""
    parts = [
        values["event_timestamp"].isoformat(),
        str(values.get("source_ip") or ""),
        str(values.get("destination_ip") or ""),
        str(values.get("event_type") or ""),
        str(values.get("message") or ""),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
