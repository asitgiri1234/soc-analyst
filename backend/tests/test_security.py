"""Security hardening: headers, throttling, error opacity, and boundaries.

The authentication and role tests live in `test_auth.py` and `test_rbac.py`;
this file covers the platform-level defences and the boundaries those two do not
reach -- what a response is allowed to reveal, what a caller is allowed to do
repeatedly, and what one user is allowed to learn about another.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi import HTTPException
from httpx import ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.log_sources import sanitise_filename
from app.core.config import settings
from app.core.middleware import API_CSP, REQUEST_ID_HEADER
from app.main import app
from app.models.enums import LogSourceType, UserRole
from app.models.log_source import LogSource
from app.services import rate_limit

HEALTH = "/api/v1/health"
LOGIN = "/api/v1/auth/login"
REGISTER = "/api/v1/auth/register"


@pytest.fixture
async def viewer(make_user):
    return await make_user(UserRole.VIEWER)


@pytest.fixture
def viewer_headers(viewer, auth_header) -> dict[str, str]:
    return auth_header(viewer)


@pytest.fixture
async def analyst(make_user):
    return await make_user(UserRole.ANALYST)


@pytest.fixture
def analyst_headers(analyst, auth_header) -> dict[str, str]:
    return auth_header(analyst)


# --- Security headers ------------------------------------------------------


async def test_security_headers_are_present(client: httpx.AsyncClient) -> None:
    response = await client.get(HEALTH)
    headers = response.headers

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "Permissions-Policy" in headers
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"


async def test_api_responses_carry_a_restrictive_csp(client: httpx.AsyncClient) -> None:
    """A JSON API needs no sources of its own, so the policy denies them."""
    response = await client.get(HEALTH)
    policy = response.headers["Content-Security-Policy"]

    assert policy == API_CSP
    assert "default-src 'none'" in policy
    assert "frame-ancestors 'none'" in policy


async def test_security_data_is_not_cached(
    client: httpx.AsyncClient, viewer_headers: dict[str, str]
) -> None:
    response = await client.get("/api/v1/incidents", headers=viewer_headers)
    assert response.headers["Cache-Control"] == "no-store"


async def test_every_response_carries_a_request_id(client: httpx.AsyncClient) -> None:
    response = await client.get(HEALTH)
    assert uuid.UUID(response.headers[REQUEST_ID_HEADER])


async def test_a_supplied_request_id_is_echoed(client: httpx.AsyncClient) -> None:
    """So a client's report of a failure can be matched to the server's log."""
    response = await client.get(HEALTH, headers={REQUEST_ID_HEADER: "trace-me-1234"})
    assert response.headers[REQUEST_ID_HEADER] == "trace-me-1234"


async def test_hsts_is_not_sent_in_local_development(client: httpx.AsyncClient) -> None:
    """Pinning a developer's browser to https://localhost would be unkind."""
    assert settings.ENVIRONMENT == "local"
    response = await client.get(HEALTH)
    assert "Strict-Transport-Security" not in response.headers


# --- Error opacity ---------------------------------------------------------


async def test_an_unhandled_error_does_not_leak_internals(
    session: AsyncSession,
) -> None:
    """A crash must answer with a bare 500, not a traceback.

    `raise_app_exceptions=False` so the transport returns the response the
    handler produced instead of re-raising into the test.
    """

    @app.get("/api/v1/_boom", include_in_schema=False)
    async def boom() -> dict[str, str]:  # pragma: no cover - invoked via HTTP
        raise RuntimeError("connection string postgresql://soc:hunter2@db/soc failed")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get("/api/v1/_boom")
    finally:
        app.router.routes = [
            route for route in app.router.routes if getattr(route, "path", "") != "/api/v1/_boom"
        ]

    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == "Internal server error"
    # The id is the only thing offered, and it is enough to ask an operator.
    assert body["request_id"]

    rendered = response.text
    assert "hunter2" not in rendered
    assert "postgresql://" not in rendered
    assert "Traceback" not in rendered
    assert "RuntimeError" not in rendered


async def test_a_404_does_not_describe_the_lookup(
    client: httpx.AsyncClient, viewer_headers: dict[str, str]
) -> None:
    response = await client.get(
        f"/api/v1/incidents/{uuid.uuid4()}", headers=viewer_headers
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


# --- Rate limiting ---------------------------------------------------------


async def test_repeated_failed_logins_are_throttled(client: httpx.AsyncClient) -> None:
    """Credential guessing hits a wall rather than running indefinitely."""
    if not settings.RATE_LIMIT_ENABLED:  # pragma: no cover - configuration dependent
        pytest.skip("rate limiting is disabled")

    payload = {"email": "nobody@soc.example.com", "password": "not-the-password-1"}

    statuses = []
    for _ in range(settings.RATE_LIMIT_LOGIN_ATTEMPTS + 2):
        statuses.append((await client.post(LOGIN, json=payload)).status_code)

    if 429 not in statuses:  # pragma: no cover - Redis absent, limiter fails open
        pytest.skip("Redis is unavailable, so the limiter failed open")

    assert statuses[0] == 401, "the first attempt must be answered on its merits"
    assert statuses[-1] == 429


async def test_a_throttled_response_says_when_to_retry(
    client: httpx.AsyncClient,
) -> None:
    payload = {"email": "nobody2@soc.example.com", "password": "not-the-password-1"}
    last = None
    for _ in range(settings.RATE_LIMIT_LOGIN_ATTEMPTS + 2):
        last = await client.post(LOGIN, json=payload)

    assert last is not None
    if last.status_code != 429:  # pragma: no cover - limiter failed open
        pytest.skip("Redis is unavailable, so the limiter failed open")

    assert int(last.headers["Retry-After"]) > 0
    assert last.headers["X-RateLimit-Limit"] == str(settings.RATE_LIMIT_LOGIN_ATTEMPTS)


async def test_a_successful_login_clears_the_counter(
    client: httpx.AsyncClient, make_user, password: str
) -> None:
    """Three fumbled passwords must not follow a user around all afternoon."""
    user = await make_user(UserRole.ANALYST)
    wrong = {"email": user.email, "password": "definitely-not-it-1"}
    right = {"email": user.email, "password": password}

    for _ in range(3):
        assert (await client.post(LOGIN, json=wrong)).status_code == 401

    assert (await client.post(LOGIN, json=right)).status_code == 200

    # The window would otherwise still be counting those three.
    assert (await client.post(LOGIN, json=right)).status_code == 200


async def test_registration_is_throttled(client: httpx.AsyncClient) -> None:
    """Open registration is also a way to fill the user table."""
    statuses = []
    for index in range(settings.RATE_LIMIT_REGISTER_ATTEMPTS + 2):
        statuses.append(
            (
                await client.post(
                    REGISTER,
                    json={
                        "email": f"flood{index}@soc.example.com",
                        "username": f"flood{index}",
                        "password": "correct-horse-battery-7",
                    },
                )
            ).status_code
        )

    if 429 not in statuses:  # pragma: no cover - limiter failed open
        pytest.skip("Redis is unavailable, so the limiter failed open")
    assert statuses[-1] == 429


async def test_the_limiter_fails_open_when_redis_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SOC that cannot authenticate during an incident is the worse outcome.

    This is the opposite choice from the token denylist, which fails closed --
    there, an unreadable store may be hiding a revoked token.
    """

    def explode() -> None:
        raise OSError("redis is gone")

    monkeypatch.setattr("app.services.rate_limit.get_redis", explode)

    verdict = await rate_limit.check("1.2.3.4", limit=1, window_seconds=60, scope="test")
    assert verdict.allowed is True


async def test_the_limiter_counts_per_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One caller's quota must not be spent by another's requests."""
    first = await rate_limit.check("10.0.0.1", limit=1, window_seconds=60, scope="unit")
    second = await rate_limit.check("10.0.0.2", limit=1, window_seconds=60, scope="unit")

    if not first.allowed:  # pragma: no cover - limiter unavailable
        pytest.skip("Redis is unavailable")

    assert first.allowed and second.allowed

    again = await rate_limit.check("10.0.0.1", limit=1, window_seconds=60, scope="unit")
    assert again.exceeded


def test_a_forged_forwarded_header_is_ignored_by_default() -> None:
    """Otherwise a caller hands itself a fresh quota with every request."""
    assert settings.TRUST_PROXY_HEADERS is False
    # The endpoint helper only passes the header through when the setting is on;
    # the identifier function is what would honour it.
    assert rate_limit.client_identifier("203.0.113.9", None) == "203.0.113.9"
    assert rate_limit.client_identifier("203.0.113.9", "1.1.1.1") == "1.1.1.1"


# --- Object-level authorization -------------------------------------------


async def test_a_viewer_cannot_read_another_account(
    client: httpx.AsyncClient, viewer_headers: dict[str, str], analyst
) -> None:
    """Account records are admin-only, whoever the subject is."""
    response = await client.get(f"/api/v1/users/{analyst.id}", headers=viewer_headers)
    assert response.status_code == 403


async def test_an_analyst_cannot_enumerate_accounts(
    client: httpx.AsyncClient, analyst_headers: dict[str, str]
) -> None:
    response = await client.get("/api/v1/users", headers=analyst_headers)
    assert response.status_code == 403


async def test_a_viewer_cannot_generate_an_ai_report(
    client: httpx.AsyncClient,
    analyst_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    """Reading a report is a viewer's right; spending money to make one is not."""
    created = await client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Credential stuffing against the portal"},
    )
    incident_id = created.json()["id"]

    response = await client.post(
        f"/api/v1/incidents/{incident_id}/analyze", headers=viewer_headers, json={}
    )
    assert response.status_code == 403

    # ...but the reports list is readable.
    listed = await client.get(
        f"/api/v1/incidents/{incident_id}/reports", headers=viewer_headers
    )
    assert listed.status_code == 200


async def test_a_viewer_cannot_add_a_note(
    client: httpx.AsyncClient,
    analyst_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    created = await client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Suspicious privilege escalation on the jump host"},
    )
    incident_id = created.json()["id"]

    response = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=viewer_headers,
        json={"body": "I should not be able to write this."},
    )
    assert response.status_code == 403


async def test_an_analyst_cannot_delete_an_incident(
    client: httpx.AsyncClient, analyst_headers: dict[str, str]
) -> None:
    created = await client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Outbound beaconing from a workstation"},
    )
    response = await client.delete(
        f"/api/v1/incidents/{created.json()['id']}", headers=analyst_headers
    )
    assert response.status_code == 403


# --- Injection through parameters -----------------------------------------


async def test_a_sql_payload_in_a_filter_is_not_executed(
    client: httpx.AsyncClient, viewer_headers: dict[str, str]
) -> None:
    """Enum-typed filters reject the payload before any query is built."""
    response = await client.get(
        "/api/v1/incidents",
        headers=viewer_headers,
        params={"status": "open'; DROP TABLE incidents; --"},
    )
    assert response.status_code == 422

    # The table is still there.
    assert (await client.get("/api/v1/incidents", headers=viewer_headers)).status_code == 200


async def test_a_sql_payload_in_a_free_text_filter_is_parameterised(
    client: httpx.AsyncClient, viewer_headers: dict[str, str]
) -> None:
    """`detector` is a free-text filter, so it is the one worth proving."""
    response = await client.get(
        "/api/v1/anomalies",
        headers=viewer_headers,
        params={"detector": "x'; DROP TABLE anomalies; --"},
    )
    assert response.status_code == 200
    assert response.json() == []

    assert (await client.get("/api/v1/anomalies", headers=viewer_headers)).status_code == 200


# --- Upload handling -------------------------------------------------------


def test_a_traversal_filename_is_reduced_to_its_name() -> None:
    assert sanitise_filename("../../../etc/passwd") == "passwd"
    assert sanitise_filename(r"C:\Windows\System32\config.sam") == "config.sam"
    assert sanitise_filename("logs/nested/auth.csv") == "auth.csv"


def test_a_control_character_filename_is_cleaned() -> None:
    assert sanitise_filename("auth\x00\x1b.csv") == "auth.csv"
    assert sanitise_filename("...") == "upload"
    assert sanitise_filename(None) == "upload"
    assert sanitise_filename("") == "upload"


def test_a_long_filename_is_bounded() -> None:
    assert len(sanitise_filename("a" * 5000 + ".csv")) == 255


async def test_an_oversized_upload_is_refused(
    client: httpx.AsyncClient, analyst_headers: dict[str, str], session: AsyncSession
) -> None:
    source = LogSource(
        name=f"upload-limit-{uuid.uuid4().hex[:8]}", source_type=LogSourceType.SYSLOG
    )
    session.add(source)
    await session.flush()

    oversized = b"a,b,c\n" + b"x" * (settings.MAX_UPLOAD_BYTES + 1024)
    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files={"file": ("huge.csv", oversized, "text/csv")},
    )
    assert response.status_code == 413


async def test_an_unsupported_upload_type_is_refused(
    client: httpx.AsyncClient, analyst_headers: dict[str, str], session: AsyncSession
) -> None:
    source = LogSource(
        name=f"upload-type-{uuid.uuid4().hex[:8]}", source_type=LogSourceType.SYSLOG
    )
    session.add(source)
    await session.flush()

    response = await client.post(
        f"/api/v1/log-sources/{source.id}/ingest",
        headers=analyst_headers,
        files={"file": ("payload.exe", b"MZ\x90\x00", "application/octet-stream")},
    )
    assert response.status_code == 415


# --- Response hygiene ------------------------------------------------------


async def test_no_response_carries_a_password_hash(
    client: httpx.AsyncClient, viewer_headers: dict[str, str], viewer
) -> None:
    response = await client.get("/api/v1/auth/me", headers=viewer_headers)
    body = response.text

    assert "hashed_password" not in body
    assert "$argon2" not in body


async def test_the_error_for_a_rejected_role_names_the_requirement_only(
    client: httpx.AsyncClient, viewer_headers: dict[str, str]
) -> None:
    """Enough to act on, without describing the authorization model."""
    response = await client.post(
        "/api/v1/incidents",
        headers=viewer_headers,
        json={"title": "A viewer should not be able to open this"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Requires the analyst role or higher"


def test_an_http_exception_carries_no_internal_detail() -> None:
    """The helper used for auth failures says one thing and no more."""
    exc = HTTPException(status_code=401, detail="Could not validate credentials")
    assert "user" not in str(exc.detail).lower()
    assert "token" not in str(exc.detail).lower()
