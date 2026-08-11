"""Parsing and normalisation, without a database or HTTP."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.models.enums import IngestionFormat, Severity
from app.services.ingestion import normalizer, parsers
from app.services.ingestion.normalizer import (
    canonical_key,
    parse_ip,
    parse_port,
    parse_severity,
    parse_timestamp,
)
from app.services.ingestion.types import RawRecord, RowError, UnreadableFileError


def _normalize(data: dict[str, Any], line: int = 1) -> dict[str, Any]:
    """Normalise a record, asserting it was accepted."""
    values, error = normalizer.normalize(RawRecord(line=line, data=data, raw=str(data)))
    assert error is None, error
    assert values is not None
    return values


# --- Format detection ------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("events.csv", IngestionFormat.CSV),
        ("EVENTS.CSV", IngestionFormat.CSV),
        ("events.json", IngestionFormat.JSON),
        ("events.jsonl", IngestionFormat.NDJSON),
        ("events.ndjson", IngestionFormat.NDJSON),
        ("syslog.log", IngestionFormat.NDJSON),
    ],
)
def test_format_comes_from_the_extension(filename: str, expected: IngestionFormat) -> None:
    assert parsers.detect_format(filename, None) is expected


def test_content_type_is_the_fallback() -> None:
    assert parsers.detect_format("export", "text/csv") is IngestionFormat.CSV
    assert parsers.detect_format("export", "application/json; charset=utf-8") is (
        IngestionFormat.JSON
    )


@pytest.mark.parametrize("filename", ["report.pdf", "archive.zip", "image.png", "notes.txt"])
def test_unsupported_types_are_not_detected(filename: str) -> None:
    assert parsers.detect_format(filename, "application/octet-stream") is None


# --- Decoding --------------------------------------------------------------


def test_a_byte_order_mark_is_stripped() -> None:
    """A spreadsheet export would otherwise name the first column "﻿timestamp"."""
    text = parsers.decode(b"\xef\xbb\xbftimestamp,message\n2026-01-01T00:00:00Z,hello\n")
    assert text.startswith("timestamp")


def test_non_utf8_input_is_refused() -> None:
    with pytest.raises(UnreadableFileError, match="UTF-8"):
        parsers.decode(b"timestamp,message\n\xff\xfe\x00bad\n")


# --- Timestamps ------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-08-10T09:14:22Z", datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)),
        ("2026-08-10T09:14:22+00:00", datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)),
        ("2026-08-10 09:14:22", datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)),
        ("2026/08/10 09:14:22", datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)),
        ("10/Aug/2026:09:14:22 +0000", datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)),
        (1786353262, datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)),
        ("1786353262", datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)),
        (1786353262000, datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)),
    ],
)
def test_timestamp_formats(value: Any, expected: datetime) -> None:
    assert parse_timestamp(value) == expected


def test_a_naive_timestamp_is_read_as_utc() -> None:
    """Guessing the server's local zone would shift every event."""
    parsed = parse_timestamp("2026-08-10 09:14:22")
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_an_offset_timestamp_keeps_its_instant() -> None:
    parsed = parse_timestamp("2026-08-10T11:14:22+02:00")
    assert parsed == datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)


@pytest.mark.parametrize("value", ["", "   ", "not-a-date", "yesterday", None, [], {}, True])
def test_unparseable_timestamps_return_none(value: Any) -> None:
    assert parse_timestamp(value) is None


# --- Addresses, ports, severity --------------------------------------------


@pytest.mark.parametrize(
    "value", ["10.20.3.15", "203.0.113.47", "2001:db8::1", " 10.0.0.1 "]
)
def test_valid_addresses_are_kept(value: str) -> None:
    assert parse_ip(value) is not None


@pytest.mark.parametrize(
    "value", ["999.999.999.999", "not-an-ip", "10.20.3", "", "10.20.3.15/24", None, 42]
)
def test_invalid_addresses_are_rejected(value: Any) -> None:
    assert parse_ip(value) is None


@pytest.mark.parametrize(("value", "expected"), [("443", 443), (22, 22), ("0", 0), (65535, 65535)])
def test_valid_ports(value: Any, expected: int) -> None:
    assert parse_port(value) == expected


@pytest.mark.parametrize("value", ["-1", "65536", "http", "", None, True])
def test_invalid_ports(value: Any) -> None:
    assert parse_port(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("fatal", Severity.CRITICAL),
        ("error", Severity.HIGH),
        ("err", Severity.HIGH),
        ("warning", Severity.MEDIUM),
        ("warn", Severity.MEDIUM),
        ("notice", Severity.LOW),
        ("info", Severity.INFO),
        ("debug", Severity.INFO),
        (0, Severity.CRITICAL),
        (3, Severity.HIGH),
        (4, Severity.MEDIUM),
        (6, Severity.INFO),
        ("7", Severity.INFO),
    ],
)
def test_severity_mapping(value: Any, expected: Severity) -> None:
    assert parse_severity(value) is expected


@pytest.mark.parametrize("value", ["", "unheard-of", None, 99])
def test_unrecognised_severity_is_none(value: Any) -> None:
    assert parse_severity(value) is None


# --- Key canonicalisation --------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("Source IP", "source_ip"),
        ("src-ip", "src_ip"),
        ("@timestamp", "timestamp"),
        ("  EventType  ", "eventtype"),
        ("dst.ip", "dst_ip"),
    ],
)
def test_keys_are_canonicalised(key: str, expected: str) -> None:
    assert canonical_key(key) == expected


# --- Normalisation ---------------------------------------------------------


def test_canonical_field_names_map_across() -> None:
    values = _normalize(
        {
            "timestamp": "2026-08-10T09:14:22Z",
            "source_ip": "203.0.113.47",
            "destination_ip": "10.20.3.15",
            "event_type": "firewall.blocked",
            "message": "Blocked inbound SSH",
        }
    )

    assert values["event_timestamp"] == datetime(2026, 8, 10, 9, 14, 22, tzinfo=UTC)
    assert values["source_ip"] == "203.0.113.47"
    assert values["destination_ip"] == "10.20.3.15"
    assert values["event_type"] == "firewall.blocked"
    assert values["message"] == "Blocked inbound SSH"


def test_vendor_spellings_map_to_the_same_columns() -> None:
    """The point of the alias table: two products, one schema."""
    values = _normalize(
        {
            "@timestamp": "2026-08-10T09:14:22Z",
            "srcip": "203.0.113.47",
            "dstip": "10.20.3.15",
            "eventtype": "ids.alert",
            "msg": "Signature match",
            "dport": "443",
            "proto": "TCP",
            "hostname": "sensor-01",
        }
    )

    assert values["source_ip"] == "203.0.113.47"
    assert values["destination_ip"] == "10.20.3.15"
    assert values["event_type"] == "ids.alert"
    assert values["message"] == "Signature match"
    assert values["destination_port"] == 443
    assert values["protocol"] == "TCP"
    assert values["host"] == "sensor-01"


def test_unmapped_fields_are_kept_in_attributes() -> None:
    """Nothing a source sent is thrown away."""
    values = _normalize(
        {
            "timestamp": "2026-08-10T09:14:22Z",
            "message": "hello",
            "rule_id": "SID-4821",
            "confidence": 0.93,
        }
    )

    assert values["attributes"]["rule_id"] == "SID-4821"
    assert values["attributes"]["confidence"] == 0.93


def test_a_metadata_field_is_merged_into_attributes() -> None:
    values = _normalize(
        {
            "timestamp": "2026-08-10T09:14:22Z",
            "message": "hello",
            "metadata": {"pid": 7712, "parent": "explorer.exe"},
        }
    )

    assert values["attributes"]["pid"] == 7712
    assert values["attributes"]["parent"] == "explorer.exe"


def test_metadata_encoded_as_a_json_string_is_merged() -> None:
    """CSV cannot nest, so a metadata column arrives as text."""
    values = _normalize(
        {
            "timestamp": "2026-08-10T09:14:22Z",
            "message": "hello",
            "metadata": '{"pid": 7712}',
        }
    )
    assert values["attributes"]["pid"] == 7712


def test_an_unparseable_address_is_preserved_rather_than_lost() -> None:
    values = _normalize(
        {
            "timestamp": "2026-08-10T09:14:22Z",
            "message": "hello",
            "source_ip": "not-an-ip",
        }
    )

    assert values["source_ip"] is None
    assert values["attributes"]["source_ip"] == "not-an-ip"


def test_an_unrecognised_severity_falls_back_but_is_preserved() -> None:
    values = _normalize(
        {"timestamp": "2026-08-10T09:14:22Z", "message": "hello", "severity": "spicy"}
    )

    assert values["severity"] is Severity.INFO
    assert values["attributes"]["severity"] == "spicy"


def test_a_record_without_a_message_falls_back_to_its_raw_form() -> None:
    """message is NOT NULL, and the record still carries content."""
    record = RawRecord(
        line=1,
        data={"timestamp": "2026-08-10T09:14:22Z", "rule_id": "SID-1"},
        raw='{"timestamp":"2026-08-10T09:14:22Z","rule_id":"SID-1"}',
    )
    values, error = normalizer.normalize(record)

    assert error is None
    assert values is not None
    assert "SID-1" in values["message"]


def test_the_first_alias_wins() -> None:
    """A later generic column must not overwrite a specific one."""
    values = _normalize(
        {
            "timestamp": "2026-08-10T09:14:22Z",
            "message": "hello",
            "src_ip": "203.0.113.47",
            "source": "firewall-01",
        }
    )

    assert values["source_ip"] == "203.0.113.47"
    assert values["attributes"]["source"] == "firewall-01"


def test_a_record_without_a_timestamp_is_rejected() -> None:
    values, error = normalizer.normalize(
        RawRecord(line=9, data={"message": "no time here"}, raw="{}")
    )

    assert values is None
    assert error is not None
    assert error.line == 9
    assert error.field == "timestamp"
    assert "no timestamp" in error.reason


def test_a_record_with_an_unparseable_timestamp_is_rejected() -> None:
    values, error = normalizer.normalize(
        RawRecord(line=4, data={"timestamp": "whenever", "message": "x"}, raw="{}")
    )

    assert values is None
    assert error is not None
    assert "unparseable" in error.reason


def test_a_blank_timestamp_says_so() -> None:
    """A CSV cell that is present but empty is a different fault from a missing column."""
    _, error = normalizer.normalize(
        RawRecord(line=4, data={"timestamp": "  ", "message": "x"}, raw="{}")
    )
    assert error is not None
    assert error.reason == "timestamp is empty"


def test_an_empty_record_is_rejected() -> None:
    values, error = normalizer.normalize(RawRecord(line=2, data={}, raw=""))
    assert values is None
    assert error is not None


def test_identical_events_share_a_fingerprint() -> None:
    """Redelivery of the same event is detectable."""
    data = {
        "timestamp": "2026-08-10T09:14:22Z",
        "source_ip": "203.0.113.47",
        "message": "Blocked",
    }
    assert _normalize(data)["fingerprint"] == _normalize(data)["fingerprint"]


def test_different_events_do_not() -> None:
    base = {"timestamp": "2026-08-10T09:14:22Z", "message": "Blocked"}
    other = {**base, "message": "Allowed"}
    assert _normalize(base)["fingerprint"] != _normalize(other)["fingerprint"]


# --- CSV parsing -----------------------------------------------------------


def _split(text: str, fmt: IngestionFormat) -> tuple[list[RawRecord], list[RowError]]:
    items = list(parsers.parse(text, fmt))
    return (
        [i for i in items if isinstance(i, RawRecord)],
        [i for i in items if isinstance(i, RowError)],
    )


def test_csv_rows_are_read_with_their_line_numbers() -> None:
    text = "timestamp,message\n2026-08-10T09:00:00Z,first\n2026-08-10T09:01:00Z,second\n"
    records, errors = _split(text, IngestionFormat.CSV)

    assert not errors
    assert [r.line for r in records] == [2, 3]  # line 1 is the header
    assert records[0].data["message"] == "first"


def test_csv_blank_lines_are_skipped_silently() -> None:
    text = "timestamp,message\n2026-08-10T09:00:00Z,first\n\n\n2026-08-10T09:01:00Z,second\n"
    records, errors = _split(text, IngestionFormat.CSV)

    assert len(records) == 2
    assert not errors


def test_csv_rows_of_the_wrong_width_are_rejected_individually() -> None:
    text = (
        "timestamp,message\n"
        "2026-08-10T09:00:00Z,good\n"
        "2026-08-10T09:01:00Z,too,many,columns\n"
        "2026-08-10T09:02:00Z\n"
        "2026-08-10T09:03:00Z,also good\n"
    )
    records, errors = _split(text, IngestionFormat.CSV)

    assert [r.data["message"] for r in records] == ["good", "also good"]
    assert [e.line for e in errors] == [3, 4]


def test_semicolon_delimited_csv_is_detected() -> None:
    text = "timestamp;message;severity\n2026-08-10T09:00:00Z;hello;info\n"
    records, errors = _split(text, IngestionFormat.CSV)

    assert not errors
    assert records[0].data["message"] == "hello"


def test_a_headerless_or_empty_csv_is_unreadable() -> None:
    with pytest.raises(UnreadableFileError):
        _split("", IngestionFormat.CSV)
    with pytest.raises(UnreadableFileError):
        _split("   \n  \n", IngestionFormat.CSV)


# --- JSON parsing ----------------------------------------------------------


def test_a_bare_json_array_is_read() -> None:
    records, errors = _split(
        '[{"timestamp":"2026-08-10T09:00:00Z","message":"a"},'
        '{"timestamp":"2026-08-10T09:01:00Z","message":"b"}]',
        IngestionFormat.JSON,
    )
    assert not errors
    assert [r.line for r in records] == [1, 2]


def test_an_enveloped_json_document_is_unwrapped() -> None:
    records, _ = _split(
        '{"source":"idp","events":[{"timestamp":"2026-08-10T09:00:00Z","message":"a"}]}',
        IngestionFormat.JSON,
    )
    assert len(records) == 1
    assert records[0].data["message"] == "a"


def test_a_single_json_object_is_one_record() -> None:
    records, _ = _split(
        '{"timestamp":"2026-08-10T09:00:00Z","message":"only"}', IngestionFormat.JSON
    )
    assert len(records) == 1


def test_non_object_entries_in_an_array_are_rejected() -> None:
    records, errors = _split(
        '[{"timestamp":"2026-08-10T09:00:00Z","message":"a"}, "just a string", 42]',
        IngestionFormat.JSON,
    )
    assert len(records) == 1
    assert [e.line for e in errors] == [2, 3]


def test_invalid_json_makes_the_whole_file_unreadable() -> None:
    """Unlike NDJSON, a broken bracket means nothing can be trusted."""
    with pytest.raises(UnreadableFileError, match="not valid JSON"):
        _split('[{"timestamp": "2026-08-10T09:00:00Z",', IngestionFormat.JSON)


# --- NDJSON parsing --------------------------------------------------------


def test_ndjson_reads_one_object_per_line() -> None:
    text = (
        '{"timestamp":"2026-08-10T09:00:00Z","message":"a"}\n'
        '{"timestamp":"2026-08-10T09:01:00Z","message":"b"}\n'
    )
    records, errors = _split(text, IngestionFormat.NDJSON)

    assert not errors
    assert [r.line for r in records] == [1, 2]


def test_one_broken_ndjson_line_does_not_stop_the_rest() -> None:
    text = (
        '{"timestamp":"2026-08-10T09:00:00Z","message":"a"}\n'
        "{not json at all\n"
        '{"timestamp":"2026-08-10T09:02:00Z","message":"c"}\n'
    )
    records, errors = _split(text, IngestionFormat.NDJSON)

    assert [r.data["message"] for r in records] == ["a", "c"]
    assert [e.line for e in errors] == [2]
