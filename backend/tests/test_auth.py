"""Registration, login, logout and token validation."""

from __future__ import annotations

import uuid
from datetime import timedelta

import httpx
import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models.audit_log import AuditLog
from app.models.enums import AuditAction, UserRole
from app.models.user import User

REGISTRATION = {
    "email": "New.Analyst@soc.example.com",
    "username": "new-analyst",
    "password": "correct-horse-battery-staple-7",
    "full_name": "New Analyst",
}


# --- Password hashing ------------------------------------------------------


def test_hashing_never_yields_the_plaintext() -> None:
    secret = "correct-horse-battery-staple-7"
    hashed = hash_password(secret)

    assert secret not in hashed
    assert hashed.startswith("$argon2id$")
    assert verify_password(secret, hashed)
    assert not verify_password("wrong-password-entirely-9", hashed)


def test_identical_passwords_hash_differently() -> None:
    """Per-hash salting: two accounts with the same password are not linkable."""
    secret = "correct-horse-battery-staple-7"
    assert hash_password(secret) != hash_password(secret)


def test_verifying_against_a_corrupt_hash_is_false_not_an_error() -> None:
    assert verify_password("anything-at-all-1", "not-a-hash") is False


# --- Registration ----------------------------------------------------------


async def test_registration_creates_a_viewer(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/v1/auth/register", json=REGISTRATION)

    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "new-analyst"
    # Least privilege: registering does not grant investigation rights.
    assert body["role"] == UserRole.VIEWER.value
    assert body["is_active"] is True
    assert uuid.UUID(body["id"])


async def test_registration_response_hides_the_password(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/v1/auth/register", json=REGISTRATION)

    body = response.json()
    assert "password" not in body
    assert "hashed_password" not in body
    assert REGISTRATION["password"] not in response.text


async def test_registration_stores_only_a_hash(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    await client.post("/api/v1/auth/register", json=REGISTRATION)

    user = (
        await session.execute(select(User).where(User.username == "new-analyst"))
    ).scalar_one()
    assert user.hashed_password != REGISTRATION["password"]
    assert user.hashed_password.startswith("$argon2id$")
    assert verify_password(REGISTRATION["password"], user.hashed_password)


async def test_registration_normalises_the_email(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    """Stored lower-cased, so a mixed-case login still finds the account."""
    await client.post("/api/v1/auth/register", json=REGISTRATION)

    user = (
        await session.execute(select(User).where(User.username == "new-analyst"))
    ).scalar_one()
    assert user.email == "new.analyst@soc.example.com"


async def test_registration_cannot_grant_a_role(client: httpx.AsyncClient) -> None:
    """An unexpected field is rejected outright rather than ignored."""
    response = await client.post(
        "/api/v1/auth/register", json={**REGISTRATION, "role": "admin"}
    )
    assert response.status_code == 422


async def test_duplicate_email_is_rejected(client: httpx.AsyncClient) -> None:
    await client.post("/api/v1/auth/register", json=REGISTRATION)
    response = await client.post(
        "/api/v1/auth/register", json={**REGISTRATION, "username": "someone-else"}
    )
    assert response.status_code == 409


async def test_duplicate_username_is_rejected(client: httpx.AsyncClient) -> None:
    await client.post("/api/v1/auth/register", json=REGISTRATION)
    response = await client.post(
        "/api/v1/auth/register", json={**REGISTRATION, "email": "other@soc.example.com"}
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", "not-an-email"),
        ("password", "short1"),  # below MIN_PASSWORD_LENGTH
        ("password", "alllettersnodigits"),  # no digits
        ("password", "12345678901234"),  # no letters
        ("username", "ab"),  # too short
        ("username", "has spaces"),
        ("username", "-starts-with-dash"),
    ],
)
async def test_invalid_registration_input_is_rejected(
    client: httpx.AsyncClient, field: str, value: str
) -> None:
    response = await client.post(
        "/api/v1/auth/register", json={**REGISTRATION, field: value}
    )
    assert response.status_code == 422


# --- Login -----------------------------------------------------------------


async def test_login_returns_a_usable_token(
    client: httpx.AsyncClient, make_user, password: str
) -> None:
    user = await make_user(UserRole.ANALYST)

    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": password}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert body["user"]["username"] == user.username
    assert "hashed_password" not in body["user"]

    claims = jwt.decode(
        body["access_token"],
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        issuer=settings.JWT_ISSUER,
    )
    assert claims["sub"] == str(user.id)
    assert claims["role"] == UserRole.ANALYST.value


async def test_login_is_case_insensitive_on_email(
    client: httpx.AsyncClient, make_user, password: str
) -> None:
    user = await make_user(UserRole.VIEWER)

    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email.upper(), "password": password}
    )
    assert response.status_code == 200


async def test_login_records_the_time(
    client: httpx.AsyncClient, session: AsyncSession, make_user, password: str
) -> None:
    user = await make_user(UserRole.VIEWER)
    assert user.last_login_at is None

    await client.post("/api/v1/auth/login", json={"email": user.email, "password": password})

    await session.refresh(user)
    assert user.last_login_at is not None


async def test_wrong_password_is_rejected(
    client: httpx.AsyncClient, make_user
) -> None:
    user = await make_user(UserRole.ANALYST)

    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": "wrong-password-99"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


async def test_unknown_email_is_rejected_identically(
    client: httpx.AsyncClient, make_user, password: str
) -> None:
    """The message must not reveal whether the account exists."""
    user = await make_user(UserRole.ANALYST)

    unknown = await client.post(
        "/api/v1/auth/login", json={"email": "nobody@soc.example.com", "password": password}
    )
    wrong_password = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": "wrong-password-99"}
    )

    assert unknown.status_code == wrong_password.status_code == 401
    assert unknown.json() == wrong_password.json()


async def test_deactivated_account_cannot_log_in(
    client: httpx.AsyncClient, make_user, password: str
) -> None:
    user = await make_user(UserRole.ANALYST, is_active=False)

    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": password}
    )
    assert response.status_code == 401


async def test_login_input_is_validated(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login", json={"email": "not-an-email", "password": "x"}
    )
    assert response.status_code == 422


# --- Token validation ------------------------------------------------------


async def test_missing_token_is_unauthorized(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_malformed_token_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer not.a.token"}
    )
    assert response.status_code == 401


async def test_expired_token_is_rejected(client: httpx.AsyncClient, make_user) -> None:
    user = await make_user(UserRole.ANALYST)
    token, _, _ = create_access_token(
        user_id=user.id, role=user.role, expires_delta=timedelta(seconds=-1)
    )

    response = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


async def test_token_signed_with_another_key_is_rejected(
    client: httpx.AsyncClient, make_user
) -> None:
    """A forged signature must not be accepted."""
    user = await make_user(UserRole.ADMIN)
    forged = jwt.encode(
        {
            "sub": str(user.id),
            "role": "admin",
            "typ": "access",
            "jti": str(uuid.uuid4()),
            "iat": 1,
            "nbf": 1,
            "exp": 99999999999,
            "iss": settings.JWT_ISSUER,
        },
        "an-attackers-own-signing-key-of-sufficient-length",
        algorithm="HS256",
    )

    response = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


async def test_unsigned_token_is_rejected(client: httpx.AsyncClient, make_user) -> None:
    """The ``none`` algorithm must never be honoured."""
    user = await make_user(UserRole.ADMIN)
    unsigned = jwt.encode(
        {"sub": str(user.id), "role": "admin", "typ": "access", "jti": "x", "exp": 99999999999},
        key="",
        algorithm="none",
    )

    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {unsigned}"}
    )
    assert response.status_code == 401


async def test_token_for_a_deleted_account_is_rejected(
    client: httpx.AsyncClient, session: AsyncSession, make_user, auth_header
) -> None:
    user = await make_user(UserRole.ANALYST)
    headers = auth_header(user)
    await session.delete(user)
    await session.flush()

    response = await client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 401


async def test_token_for_a_deactivated_account_is_refused(
    client: httpx.AsyncClient, session: AsyncSession, make_user, auth_header
) -> None:
    """A token issued before deactivation stops working at once."""
    user = await make_user(UserRole.ANALYST)
    headers = auth_header(user)
    user.is_active = False
    await session.flush()

    response = await client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 403


async def test_me_returns_the_authenticated_account(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    user = await make_user(UserRole.ANALYST)

    response = await client.get("/api/v1/auth/me", headers=auth_header(user))

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(user.id)
    assert body["role"] == UserRole.ANALYST.value
    assert "hashed_password" not in body


# --- Logout ----------------------------------------------------------------


async def test_logout_revokes_the_token(
    client: httpx.AsyncClient, make_user, password: str, redis_available: bool
) -> None:
    if not redis_available:
        pytest.skip("Redis is required for token revocation")

    user = await make_user(UserRole.ANALYST)
    login = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": password}
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200

    logout = await client.post("/api/v1/auth/logout", headers=headers)
    assert logout.status_code == 200
    assert logout.json()["token_revoked"] is True

    # The same token is no longer accepted.
    reused = await client.get("/api/v1/auth/me", headers=headers)
    assert reused.status_code == 401


async def test_logout_requires_authentication(client: httpx.AsyncClient) -> None:
    assert (await client.post("/api/v1/auth/logout")).status_code == 401


# --- Audit trail -----------------------------------------------------------


async def _actions(session: AsyncSession) -> list[AuditLog]:
    result = await session.execute(select(AuditLog).order_by(AuditLog.created_at))
    return list(result.scalars())


async def test_successful_login_is_audited(
    client: httpx.AsyncClient, session: AsyncSession, make_user, password: str
) -> None:
    user = await make_user(UserRole.ANALYST)

    await client.post("/api/v1/auth/login", json={"email": user.email, "password": password})

    entries = [e for e in await _actions(session) if e.action == AuditAction.LOGIN]
    assert len(entries) == 1
    assert entries[0].actor_id == user.id
    assert entries[0].success is True


async def test_failed_login_is_audited(
    client: httpx.AsyncClient, session: AsyncSession, make_user
) -> None:
    user = await make_user(UserRole.ANALYST)

    await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": "wrong-password-99"}
    )

    entries = [e for e in await _actions(session) if e.action == AuditAction.LOGIN_FAILED]
    assert len(entries) == 1
    assert entries[0].success is False
    assert entries[0].actor_email == user.email
    # The attempted password must never reach the audit trail.
    assert "wrong-password-99" not in str(entries[0].changes) + str(entries[0].context)


async def test_login_attempt_on_unknown_email_is_audited(
    client: httpx.AsyncClient, session: AsyncSession, password: str
) -> None:
    """Probing for accounts leaves a trail even though no account matched."""
    await client.post(
        "/api/v1/auth/login", json={"email": "ghost@soc.example.com", "password": password}
    )

    entries = [e for e in await _actions(session) if e.action == AuditAction.LOGIN_FAILED]
    assert len(entries) == 1
    assert entries[0].actor_id is None
    assert entries[0].actor_email == "ghost@soc.example.com"


async def test_logout_is_audited(
    client: httpx.AsyncClient, session: AsyncSession, make_user, auth_header
) -> None:
    user = await make_user(UserRole.ANALYST)

    await client.post("/api/v1/auth/logout", headers=auth_header(user))

    entries = [e for e in await _actions(session) if e.action == AuditAction.LOGOUT]
    assert len(entries) == 1
    assert entries[0].actor_id == user.id
