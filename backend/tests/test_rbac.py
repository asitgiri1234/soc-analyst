"""Role-based access control across the three tiers."""

from __future__ import annotations

import uuid

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.authz import (
    can_manage_users,
    can_read_security_data,
    can_write_security_data,
    has_at_least,
)
from app.models.enums import UserRole

ALL_ROLES = [UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN]


# --- The role model --------------------------------------------------------


def test_the_three_roles_are_the_only_roles() -> None:
    assert set(UserRole) == {UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER}


def test_roles_nest() -> None:
    assert has_at_least(UserRole.ADMIN, UserRole.VIEWER)
    assert has_at_least(UserRole.ADMIN, UserRole.ANALYST)
    assert has_at_least(UserRole.ANALYST, UserRole.VIEWER)
    assert not has_at_least(UserRole.VIEWER, UserRole.ANALYST)
    assert not has_at_least(UserRole.ANALYST, UserRole.ADMIN)


def test_every_role_satisfies_itself() -> None:
    for role in ALL_ROLES:
        assert has_at_least(role, role)


def test_capabilities_match_the_stated_tiers() -> None:
    assert [can_read_security_data(r) for r in ALL_ROLES] == [True, True, True]
    assert [can_write_security_data(r) for r in ALL_ROLES] == [False, True, True]
    assert [can_manage_users(r) for r in ALL_ROLES] == [False, False, True]


# --- Protected routes ------------------------------------------------------


@pytest.mark.parametrize("role", ALL_ROLES)
async def test_any_authenticated_role_reaches_whoami(
    client: httpx.AsyncClient, make_user, auth_header, role: UserRole
) -> None:
    user = await make_user(role)
    response = await client.get("/api/v1/protected/whoami", headers=auth_header(user))

    assert response.status_code == 200
    assert response.json()["role"] == role.value


@pytest.mark.parametrize("path", ["/api/v1/protected/whoami", "/api/v1/protected/security-data"])
async def test_protected_routes_reject_anonymous_callers(
    client: httpx.AsyncClient, path: str
) -> None:
    assert (await client.get(path)).status_code == 401


@pytest.mark.parametrize("role", ALL_ROLES)
async def test_every_role_can_read_security_data(
    client: httpx.AsyncClient, make_user, auth_header, role: UserRole
) -> None:
    user = await make_user(role)
    response = await client.get("/api/v1/protected/security-data", headers=auth_header(user))
    assert response.status_code == 200


@pytest.mark.parametrize(
    ("role", "expected"),
    [(UserRole.VIEWER, 403), (UserRole.ANALYST, 201), (UserRole.ADMIN, 201)],
)
async def test_writing_security_data_requires_analyst(
    client: httpx.AsyncClient, make_user, auth_header, role: UserRole, expected: int
) -> None:
    user = await make_user(role)
    response = await client.post("/api/v1/protected/security-data", headers=auth_header(user))
    assert response.status_code == expected


@pytest.mark.parametrize(
    ("role", "expected"),
    [(UserRole.VIEWER, 403), (UserRole.ANALYST, 403), (UserRole.ADMIN, 200)],
)
async def test_deleting_security_data_requires_admin(
    client: httpx.AsyncClient, make_user, auth_header, role: UserRole, expected: int
) -> None:
    user = await make_user(role)
    response = await client.request(
        "DELETE", "/api/v1/protected/security-data", headers=auth_header(user)
    )
    assert response.status_code == expected


# --- User administration ---------------------------------------------------


@pytest.mark.parametrize(
    ("role", "expected"),
    [(UserRole.VIEWER, 403), (UserRole.ANALYST, 403), (UserRole.ADMIN, 200)],
)
async def test_listing_users_requires_admin(
    client: httpx.AsyncClient, make_user, auth_header, role: UserRole, expected: int
) -> None:
    user = await make_user(role)
    response = await client.get("/api/v1/users", headers=auth_header(user))
    assert response.status_code == expected


async def test_the_user_list_never_includes_hashes(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    admin = await make_user(UserRole.ADMIN)
    await make_user(UserRole.VIEWER)

    response = await client.get("/api/v1/users", headers=auth_header(admin))

    assert response.status_code == 200
    assert "$argon2id$" not in response.text
    for entry in response.json():
        assert "hashed_password" not in entry
        assert "password" not in entry


async def test_an_admin_can_promote_a_viewer(
    client: httpx.AsyncClient, session: AsyncSession, make_user, auth_header
) -> None:
    admin = await make_user(UserRole.ADMIN)
    viewer = await make_user(UserRole.VIEWER)

    response = await client.patch(
        f"/api/v1/users/{viewer.id}",
        headers=auth_header(admin),
        json={"role": UserRole.ANALYST.value},
    )

    assert response.status_code == 200
    assert response.json()["role"] == UserRole.ANALYST.value
    await session.refresh(viewer)
    assert viewer.role == UserRole.ANALYST


async def test_a_promoted_user_gains_access_immediately(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    """Authorization reads the stored role, not the one frozen into the token."""
    admin = await make_user(UserRole.ADMIN)
    viewer = await make_user(UserRole.VIEWER)
    viewer_headers = auth_header(viewer)

    denied = await client.post("/api/v1/protected/security-data", headers=viewer_headers)
    assert denied.status_code == 403

    await client.patch(
        f"/api/v1/users/{viewer.id}",
        headers=auth_header(admin),
        json={"role": UserRole.ANALYST.value},
    )

    # Same token, now carrying a stale role claim.
    allowed = await client.post("/api/v1/protected/security-data", headers=viewer_headers)
    assert allowed.status_code == 201


async def test_a_demoted_user_loses_access_immediately(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    admin = await make_user(UserRole.ADMIN)
    analyst = await make_user(UserRole.ANALYST)
    analyst_headers = auth_header(analyst)

    assert (
        await client.post("/api/v1/protected/security-data", headers=analyst_headers)
    ).status_code == 201

    await client.patch(
        f"/api/v1/users/{analyst.id}",
        headers=auth_header(admin),
        json={"role": UserRole.VIEWER.value},
    )

    revoked = await client.post("/api/v1/protected/security-data", headers=analyst_headers)
    assert revoked.status_code == 403


async def test_a_non_admin_cannot_promote_themselves(
    client: httpx.AsyncClient, session: AsyncSession, make_user, auth_header
) -> None:
    viewer = await make_user(UserRole.VIEWER)

    response = await client.patch(
        f"/api/v1/users/{viewer.id}",
        headers=auth_header(viewer),
        json={"role": UserRole.ADMIN.value},
    )

    assert response.status_code == 403
    await session.refresh(viewer)
    assert viewer.role == UserRole.VIEWER


async def test_an_admin_cannot_demote_themselves(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    """Guards against locking the last administrator out."""
    admin = await make_user(UserRole.ADMIN)

    response = await client.patch(
        f"/api/v1/users/{admin.id}",
        headers=auth_header(admin),
        json={"role": UserRole.VIEWER.value},
    )
    assert response.status_code == 400


async def test_an_admin_cannot_deactivate_themselves(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    admin = await make_user(UserRole.ADMIN)

    response = await client.patch(
        f"/api/v1/users/{admin.id}",
        headers=auth_header(admin),
        json={"is_active": False},
    )
    assert response.status_code == 400


async def test_an_admin_can_deactivate_someone_else(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    admin = await make_user(UserRole.ADMIN)
    analyst = await make_user(UserRole.ANALYST)
    analyst_headers = auth_header(analyst)

    response = await client.patch(
        f"/api/v1/users/{analyst.id}", headers=auth_header(admin), json={"is_active": False}
    )
    assert response.status_code == 200

    # The deactivated account's existing token stops working.
    assert (await client.get("/api/v1/auth/me", headers=analyst_headers)).status_code == 403


async def test_role_changes_are_audited(
    client: httpx.AsyncClient, session: AsyncSession, make_user, auth_header
) -> None:
    from sqlalchemy import select

    from app.models.audit_log import AuditLog

    admin = await make_user(UserRole.ADMIN)
    viewer = await make_user(UserRole.VIEWER)

    await client.patch(
        f"/api/v1/users/{viewer.id}",
        headers=auth_header(admin),
        json={"role": UserRole.ANALYST.value},
    )

    entries = (
        await session.execute(select(AuditLog).where(AuditLog.resource_id == viewer.id))
    ).scalars()
    changes = [e.changes for e in entries if e.changes]
    assert {"from": "viewer", "to": "analyst"} in [c.get("role") for c in changes]


async def test_updating_an_unknown_user_is_not_found(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    admin = await make_user(UserRole.ADMIN)

    response = await client.patch(
        f"/api/v1/users/{uuid.uuid4()}",
        headers=auth_header(admin),
        json={"role": UserRole.ANALYST.value},
    )
    assert response.status_code == 404


async def test_an_unknown_role_is_rejected(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    admin = await make_user(UserRole.ADMIN)
    viewer = await make_user(UserRole.VIEWER)

    response = await client.patch(
        f"/api/v1/users/{viewer.id}",
        headers=auth_header(admin),
        json={"role": "superuser"},
    )
    assert response.status_code == 422


# --- Self-service password change ------------------------------------------


async def test_a_user_can_change_their_own_password(
    client: httpx.AsyncClient, make_user, auth_header, password: str
) -> None:
    user = await make_user(UserRole.VIEWER)
    new_password = "an-entirely-new-secret-42"

    response = await client.post(
        "/api/v1/users/me/password",
        headers=auth_header(user),
        json={"current_password": password, "new_password": new_password},
    )
    assert response.status_code == 204

    assert (
        await client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": new_password}
        )
    ).status_code == 200
    assert (
        await client.post("/api/v1/auth/login", json={"email": user.email, "password": password})
    ).status_code == 401


async def test_changing_a_password_requires_the_current_one(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    user = await make_user(UserRole.VIEWER)

    response = await client.post(
        "/api/v1/users/me/password",
        headers=auth_header(user),
        json={"current_password": "not-the-password-1", "new_password": "another-secret-42"},
    )
    assert response.status_code == 400


async def test_a_weak_new_password_is_rejected(
    client: httpx.AsyncClient, make_user, auth_header, password: str
) -> None:
    user = await make_user(UserRole.VIEWER)

    response = await client.post(
        "/api/v1/users/me/password",
        headers=auth_header(user),
        json={"current_password": password, "new_password": "short1"},
    )
    assert response.status_code == 422
