"""Log source registration and file upload over HTTP."""

from __future__ import annotations

import io
import json
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.enums import (
    IngestionFormat,
    IngestionStatus,
    LogSourceStatus,
    Severity,
    UserRole,
)
from app.models.log_entry import LogEntry
from app.models.log_source import LogSource

SAMPLE_DATA = Path(__file__).resolve().parent.parent / "sample_data"

VALID_CSV = (
    "timestamp,src_ip,dst_ip,event_type,severity,message\n"
    "2026-08-10T09:14:22Z,203.0.113.47,10.20.3.15,firewall.blocked,warning,Blocked inbound SSH\n"
    "2026-08-10T09:15:02Z,203.0.113.47,10.20.3.15,firewall.blocked,error,Blocked inbound RDP\n"
    "2026-08-10T09:16:44Z,10.20.4.88,198.51.100.23,firewall.allowed,info,Outbound HTTPS\n"
)

VALID_JSON = json.dumps(
    {
        "events": [
            {
                "timestamp": "2026-08-10T10:02:11Z",
                "event_type": "auth.login_failed",
                "severity": "warning",
                "user": "j.okafor",
                "source_ip": "203.0.113.91",
                "destination_ip": "10.20.5.10",
                "message": "Password authentication failed",
                "metadata": {"attempt": 1, "method": "password"},
            },
            {
                "timestamp": "2026-08-10T10:02:35Z",
                "event_type": "auth.account_locked",
                "severity": "critical",
                "user": "j.okafor",
                "source_ip": "203.0.113.91",
                "destination_ip": "10.20.5.10",
                "message": "Account locked after 3 failed attempts",
                "metadata": {"lockout_minutes": 30},
            },
        ]
    }
)


def upload(content: str | bytes, name: str, content_type: str) -> dict[str, Any]:
    """Build the multipart payload for httpx."""
    data = content.encode("utf-8") if isinstance(content, str) else content
    return {"file": (name, io.BytesIO(data), content_type)}


@pytest.fixture
async def analyst(make_user):
    return await make_user(UserRole.ANALYST)


@pytest.fixture
def analyst_headers(analyst, auth_header) -> dict[str, str]:
    return auth_header(analyst)


@pytest.fixture
async def source(session: AsyncSession, analyst) -> LogSource:
    from app.models.enums import LogSourceType

    log_source = LogSource(
        name=f"edge-firewall-{uuid.uuid4().hex[:8]}",
        source_type=LogSourceType.FIREWALL,
        created_by_id=analyst.id,
    )
    session.add(log_source)
    await session.flush()
    return log_source


async def _entries(session: AsyncSession, source_id: uuid.UUID) -> list[LogEntry]:
    result = await session.execute(
        select(LogEntry)
        .where(LogEntry.log_source_id == source_id)
        .order_by(LogEntry.event_timestamp)
    )
    return list(result.scalars())


# --- Log source creation ---------------------------------------------------


async def test_an_analyst_can_register_a_source(
    client: httpx.AsyncClient, analyst_headers: dict[str, str]
) -> None:
    response = await client.post(
        "/api/v1/log-sources",
        headers=analyst_headers,
        json={
            "name": "perimeter-ids",
            "source_type": "ids",
            "description": "Inline IDS at the perimeter",
            "hostname": "ids-01",
            "tags": ["perimeter", "inline"],
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "perimeter-ids"
    assert body["source_type"] == "ids"
    assert body["status"] == LogSourceStatus.PENDING.value
    assert body["events_ingested"] == 0
    assert body["tags"] == ["perimeter", "inline"]


async def test_a_viewer_cannot_register_a_source(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    viewer = await make_user(UserRole.VIEWER)
    response = await client.post(
        "/api/v1/log-sources",
        headers=auth_header(viewer),
        json={"name": "sneaky", "source_type": "ids"},
    )
    assert response.status_code == 403


async def test_registering_a_source_requires_authentication(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/log-sources", json={"name": "anon", "source_type": "ids"}
    )
    assert response.status_code == 401


async def test_duplicate_source_names_are_rejected(
    client: httpx.AsyncClient, analyst_headers: dict[str, str]
) -> None:
    payload = {"name": "duplicate-source", "source_type": "syslog"}
    assert (
        await client.post("/api/v1/log-sources", headers=analyst_headers, json=payload)
    ).status_code == 201

    second = await client.post("/api/v1/log-sources", headers=analyst_headers, json=payload)
    assert second.status_code == 409


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "no-type"},
        {"name": "", "source_type": "ids"},
        {"name": "bad-type", "source_type": "not-a-real-type"},
        {"name": "extra", "source_type": "ids", "events_ingested": 9999},
        {"name": "extra", "source_type": "ids", "status": "active"},
    ],
)
async def test_invalid_source_payloads_are_rejected(
    client: httpx.AsyncClient, analyst_headers: dict[str, str], payload: dict[str, Any]
) -> None:
    """Counters and status are the server's to set, not the client's."""
    response = await client.post("/api/v1/log-sources", headers=analyst_headers, json=payload)
    assert response.status_code == 422


async def test_a_viewer_can_list_sources(
    client: httpx.AsyncClient, source: LogSource, make_user, auth_header
) -> None:
    viewer = await make_user(UserRole.VIEWER)
    response = await client.get("/api/v1/log-sources", headers=auth_header(viewer))

    assert response.status_code == 200
    assert source.name in [item["name"] for item in response.json()]


# --- Valid CSV upload ------------------------------------------------------


async def test_valid_csv_upload(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(VALID_CSV, "firewall.csv", "text/csv"),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == IngestionStatus.COMPLETED.value
    assert body["format"] == IngestionFormat.CSV.value
    assert (body["total_records"], body["accepted_records"], body["rejected_records"]) == (3, 3, 0)
    assert body["errors"] == []

    entries = await _entries(session, source.id)
    assert len(entries) == 3
    assert entries[0].source_ip == "203.0.113.47"
    assert entries[0].destination_ip == "10.20.3.15"
    assert entries[0].event_type == "firewall.blocked"
    assert entries[0].message == "Blocked inbound SSH"
    assert entries[0].severity is Severity.MEDIUM  # "warning" maps to medium
    assert entries[0].raw is not None


async def test_csv_upload_updates_the_source_counters(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(VALID_CSV, "firewall.csv", "text/csv"),
    )

    await session.refresh(source)
    assert source.events_ingested == 3
    assert source.last_ingested_at is not None
    assert source.status is LogSourceStatus.ACTIVE


async def test_repeated_uploads_accumulate(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    for _ in range(3):
        await client.post(
            f"/api/v1/log-sources/{source.id}/ingest",
            headers=analyst_headers,
            files=upload(VALID_CSV, "firewall.csv", "text/csv"),
        )

    await session.refresh(source)
    assert source.events_ingested == 9
    assert len(await _entries(session, source.id)) == 9


# --- Valid JSON upload -----------------------------------------------------


async def test_valid_json_upload(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(VALID_JSON, "auth.json", "application/json"),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == IngestionStatus.COMPLETED.value
    assert body["format"] == IngestionFormat.JSON.value
    assert body["accepted_records"] == 2

    entries = await _entries(session, source.id)
    assert len(entries) == 2
    assert entries[0].username == "j.okafor"
    assert entries[0].event_type == "auth.login_failed"
    # The nested metadata object is merged into attributes.
    assert entries[0].attributes["attempt"] == 1
    assert entries[0].attributes["method"] == "password"
    assert entries[1].severity is Severity.CRITICAL


async def test_valid_ndjson_upload(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    """Vendor field spellings resolve through the alias table."""
    content = (
        '{"@timestamp":"2026-08-10T12:01:04Z","eventtype":"process.created",'
        '"level":"info","hostname":"wks-1","msg":"Process created"}\n'
        '{"@timestamp":"2026-08-10T12:01:09Z","eventtype":"process.connection",'
        '"level":"warn","srcip":"10.20.4.203","dstip":"185.220.101.34","dport":9001,'
        '"msg":"Outbound connection"}\n'
    )
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(content, "endpoint.jsonl", "application/x-ndjson"),
    )

    assert response.status_code == 201
    assert response.json()["format"] == IngestionFormat.NDJSON.value

    entries = await _entries(session, source.id)
    assert entries[0].host == "wks-1"
    assert entries[1].source_ip == "10.20.4.203"
    assert entries[1].destination_port == 9001
    assert entries[1].severity is Severity.MEDIUM


# --- Malformed logs --------------------------------------------------------


async def test_malformed_rows_are_rejected_without_losing_the_batch(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    content = (
        "timestamp,src_ip,message\n"
        "2026-08-10T09:00:00Z,203.0.113.1,kept one\n"
        "not-a-timestamp,203.0.113.2,rejected: bad timestamp\n"
        ",203.0.113.3,rejected: missing timestamp\n"
        "2026-08-10T09:03:00Z,203.0.113.4,kept two\n"
        "2026-08-10T09:04:00Z,203.0.113.5,rejected: too many,columns\n"
        "2026-08-10T09:05:00Z,203.0.113.6,kept three\n"
    )
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(content, "mixed.csv", "text/csv"),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == IngestionStatus.PARTIAL.value
    assert body["accepted_records"] == 3
    assert body["rejected_records"] == 3

    # Each failure names the line it came from.
    assert sorted(error["line"] for error in body["errors"]) == [3, 4, 6]

    entries = await _entries(session, source.id)
    assert [entry.message for entry in entries] == ["kept one", "kept two", "kept three"]


async def test_a_bad_field_costs_the_field_not_the_record(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    content = (
        "timestamp,src_ip,dst_port,message\n"
        "2026-08-10T09:00:00Z,999.999.999.999,not-a-port,still stored\n"
    )
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(content, "odd.csv", "text/csv"),
    )

    assert response.status_code == 201
    assert response.json()["accepted_records"] == 1

    entry = (await _entries(session, source.id))[0]
    assert entry.source_ip is None
    assert entry.destination_port is None
    # The unusable value is kept rather than dropped.
    assert entry.attributes["source_ip"] == "999.999.999.999"


async def test_a_file_where_every_row_fails_reports_422(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    content = "timestamp,message\nnope,one\nalso-nope,two\n"
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(content, "allbad.csv", "text/csv"),
    )

    assert response.status_code == 422
    body = response.json()
    assert body["status"] == IngestionStatus.FAILED.value
    assert body["accepted_records"] == 0
    assert body["rejected_records"] == 2
    assert await _entries(session, source.id) == []


async def test_structurally_invalid_json_fails_the_file(
    client: httpx.AsyncClient, source: LogSource, analyst_headers: dict[str, str]
) -> None:
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload('[{"timestamp": "2026-08-10T09:00:00Z",', "broken.json", "application/json"),
    )

    assert response.status_code == 422
    body = response.json()
    assert body["status"] == IngestionStatus.FAILED.value
    assert "not valid JSON" in body["error_detail"]


async def test_a_failed_file_marks_the_source(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload("{not json", "broken.json", "application/json"),
    )

    await session.refresh(source)
    assert source.status is LogSourceStatus.ERROR
    assert source.last_error is not None


async def test_non_utf8_uploads_are_refused(
    client: httpx.AsyncClient, source: LogSource, analyst_headers: dict[str, str]
) -> None:
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(b"timestamp,message\n\xff\xfe\x00x\n", "latin.csv", "text/csv"),
    )

    assert response.status_code == 422
    assert "UTF-8" in response.json()["error_detail"]


async def test_reported_errors_are_capped(
    client: httpx.AsyncClient, source: LogSource, analyst_headers: dict[str, str]
) -> None:
    """A file of entirely bad rows must not write an unbounded JSON column."""
    rows = "".join(f"bad-timestamp-{i},message {i}\n" for i in range(300))
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(f"timestamp,message\n{rows}", "many.csv", "text/csv"),
    )

    body = response.json()
    assert body["rejected_records"] == 300
    assert len(body["errors"]) == settings.INGEST_MAX_REPORTED_ERRORS


# --- Batch ingestion -------------------------------------------------------


async def test_batch_ingestion_spans_several_inserts(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    """More rows than one batch, to exercise the chunking."""
    count = settings.INGEST_BATCH_SIZE * 2 + 37
    rows = "".join(
        f"2026-08-10T09:00:00Z,10.20.4.{i % 255},event {i}\n" for i in range(count)
    )
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(f"timestamp,src_ip,message\n{rows}", "bulk.csv", "text/csv"),
    )

    assert response.status_code == 201
    assert response.json()["accepted_records"] == count

    stored = await session.execute(
        select(func.count())
        .select_from(LogEntry)
        .where(LogEntry.log_source_id == source.id)
    )
    assert stored.scalar_one() == count


# --- File type and size restrictions ---------------------------------------


@pytest.mark.parametrize(
    ("name", "content_type"),
    [
        ("report.pdf", "application/pdf"),
        ("archive.zip", "application/zip"),
        ("image.png", "image/png"),
        ("notes.txt", "text/plain"),
        ("noextension", "application/octet-stream"),
    ],
)
async def test_unsupported_file_types_are_refused(
    client: httpx.AsyncClient,
    source: LogSource,
    analyst_headers: dict[str, str],
    name: str,
    content_type: str,
) -> None:
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload("whatever", name, content_type),
    )
    assert response.status_code == 415


async def test_oversized_uploads_are_refused(
    client: httpx.AsyncClient,
    source: LogSource,
    analyst_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 2048)
    oversized = "timestamp,message\n" + "".join(
        f"2026-08-10T09:00:00Z,padding padding padding {i}\n" for i in range(200)
    )

    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(oversized, "big.csv", "text/csv"),
    )
    assert response.status_code == 413


async def test_an_empty_upload_is_refused(
    client: httpx.AsyncClient, source: LogSource, analyst_headers: dict[str, str]
) -> None:
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload("", "empty.csv", "text/csv"),
    )
    assert response.status_code == 400


async def test_a_viewer_cannot_upload(
    client: httpx.AsyncClient, source: LogSource, make_user, auth_header
) -> None:
    viewer = await make_user(UserRole.VIEWER)
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=auth_header(viewer),
        files=upload(VALID_CSV, "firewall.csv", "text/csv"),
    )
    assert response.status_code == 403


async def test_uploading_requires_authentication(
    client: httpx.AsyncClient, source: LogSource
) -> None:
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        files=upload(VALID_CSV, "firewall.csv", "text/csv"),
    )
    assert response.status_code == 401


async def test_uploading_to_an_unknown_source_is_not_found(
    client: httpx.AsyncClient, analyst_headers: dict[str, str]
) -> None:
    response = await client.post(
        f"/api/v1/log-sources/{uuid.uuid4()}/ingest",
        headers=analyst_headers,
        files=upload(VALID_CSV, "firewall.csv", "text/csv"),
    )
    assert response.status_code == 404


# --- Status tracking -------------------------------------------------------


async def test_the_job_is_retrievable_afterwards(
    client: httpx.AsyncClient, source: LogSource, analyst_headers: dict[str, str]
) -> None:
    created = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(VALID_CSV, "firewall.csv", "text/csv"),
    )
    job_id = created.json()["id"]

    fetched = await client.get(f"/api/v1/ingestion-jobs/{job_id}", headers=analyst_headers)

    assert fetched.status_code == 200
    body = fetched.json()
    assert body["id"] == job_id
    assert body["filename"] == "firewall.csv"
    assert body["accepted_records"] == 3
    assert body["started_at"] is not None
    assert body["finished_at"] is not None


async def test_jobs_can_be_filtered_by_status(
    client: httpx.AsyncClient, source: LogSource, analyst_headers: dict[str, str]
) -> None:
    await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(VALID_CSV, "ok.csv", "text/csv"),
    )
    await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload("timestamp,message\nnope,one\n", "bad.csv", "text/csv"),
    )

    failed = await client.get(
        "/api/v1/ingestion-jobs", headers=analyst_headers, params={"status": "failed"}
    )

    assert failed.status_code == 200
    names = [job["filename"] for job in failed.json()]
    assert "bad.csv" in names
    assert "ok.csv" not in names


async def test_a_sources_ingestion_history_is_listed(
    client: httpx.AsyncClient, source: LogSource, analyst_headers: dict[str, str]
) -> None:
    for name in ("first.csv", "second.csv"):
        await client.post(
            f"/api/v1/log-sources/{source.id}/ingest",
            headers=analyst_headers,
            files=upload(VALID_CSV, name, "text/csv"),
        )

    response = await client.get(
        f"/api/v1/log-sources/{source.id}/ingestions", headers=analyst_headers
    )

    assert response.status_code == 200
    assert {job["filename"] for job in response.json()} == {"first.csv", "second.csv"}


async def test_the_upload_is_audited(
    client: httpx.AsyncClient,
    session: AsyncSession,
    source: LogSource,
    analyst_headers: dict[str, str],
) -> None:
    from app.models.audit_log import AuditLog

    await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(VALID_CSV, "firewall.csv", "text/csv"),
    )

    entries = (
        await session.execute(
            select(AuditLog).where(AuditLog.resource_type == "ingestion_job")
        )
    ).scalars()
    contexts = [entry.context for entry in entries]
    assert any(ctx.get("accepted") == 3 for ctx in contexts)


# --- The shipped sample files ----------------------------------------------


@pytest.mark.parametrize(
    ("filename", "content_type", "expected_accepted", "expected_rejected"),
    [
        ("firewall_logs.csv", "text/csv", 12, 0),
        ("auth_logs.json", "application/json", 8, 0),
        ("endpoint_logs.jsonl", "application/x-ndjson", 10, 0),
        ("malformed_logs.csv", "text/csv", 4, 3),
    ],
)
async def test_the_sample_files_ingest_as_documented(
    client: httpx.AsyncClient,
    source: LogSource,
    analyst_headers: dict[str, str],
    filename: str,
    content_type: str,
    expected_accepted: int,
    expected_rejected: int,
) -> None:
    """The README's table is a promise; this keeps it honest."""
    payload = (SAMPLE_DATA / filename).read_bytes()

    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files=upload(payload, filename, content_type),
    )

    body = response.json()
    assert body["accepted_records"] == expected_accepted, body["errors"]
    assert body["rejected_records"] == expected_rejected
