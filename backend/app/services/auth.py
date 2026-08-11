"""Registration and credential checking.

Kept out of the endpoint layer so the rules can be tested without HTTP, and so
the audit trail is written in the same transaction as the change it describes.
"""

from __future__ import annotations

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.security import dummy_verify, hash_password, needs_rehash, verify_password
from app.models.enums import AuditAction, UserRole
from app.models.user import User
from app.schemas.user import UserCreate
from app.services import audit

logger = get_logger(__name__)


class EmailAlreadyRegisteredError(Exception):
    """The email address already has an account."""


class UsernameTakenError(Exception):
    """The username already has an account."""


async def get_by_email(session: AsyncSession, email: str) -> User | None:
    """Look up an account by email, case-insensitively."""
    result = await session.execute(
        select(User).where(func.lower(User.email) == email.lower())
    )
    return result.scalar_one_or_none()


async def get_by_username(session: AsyncSession, username: str) -> User | None:
    result = await session.execute(
        select(User).where(func.lower(User.username) == username.lower())
    )
    return result.scalar_one_or_none()


async def register(
    session: AsyncSession,
    payload: UserCreate,
    *,
    request: Request | None = None,
) -> User:
    """Create an account.

    New accounts always start as VIEWER. Promotion is an administrative act, so
    that registering cannot be a route to privilege.
    """
    if await get_by_email(session, payload.email):
        raise EmailAlreadyRegisteredError(payload.email)
    if await get_by_username(session, payload.username):
        raise UsernameTakenError(payload.username)

    user = User(
        email=payload.email.lower(),
        username=payload.username,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=UserRole.VIEWER,
        is_active=True,
    )
    session.add(user)
    await session.flush()

    await audit.record(
        session,
        action=AuditAction.CREATE,
        resource_type="user",
        actor=user,
        resource_id=user.id,
        description="account registered",
        context={"role": user.role.value},
        request=request,
    )
    return user


async def authenticate(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    request: Request | None = None,
) -> User | None:
    """Verify credentials, recording the attempt either way.

    Returns None for an unknown address, a wrong password, or a deactivated
    account -- the caller must not tell them apart in its response.
    """
    user = await get_by_email(session, email)

    if user is None:
        # Spend the time a real verification would have taken, so response
        # latency does not reveal which addresses exist.
        dummy_verify()
        await _record_failure(session, email, "no such account", request)
        return None

    if not verify_password(password, user.hashed_password):
        await _record_failure(session, email, "incorrect password", request, user=user)
        return None

    if not user.is_active:
        await _record_failure(session, email, "account deactivated", request, user=user)
        return None

    # Transparently upgrade a hash left behind by older Argon2 parameters.
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(password)

    user.last_login_at = func.now()
    await session.flush()
    return user


async def _record_failure(
    session: AsyncSession,
    email: str,
    reason: str,
    request: Request | None,
    *,
    user: User | None = None,
) -> None:
    await audit.record(
        session,
        action=AuditAction.LOGIN_FAILED,
        resource_type="session",
        actor=user,
        # Retained even when no account matched, so repeated attempts against a
        # non-existent address are still visible.
        actor_email=email.lower(),
        description=reason,
        request=request,
        success=False,
    )
    logger.info("failed login for %s: %s", email, reason)
