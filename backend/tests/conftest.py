"""Shared fixtures for the API tests.

Each test runs against the real database inside a transaction that is rolled
back afterwards. The session handed to the application uses
``join_transaction_mode="create_savepoint"``, so endpoint calls to ``commit()``
release a savepoint instead of ending the test's outer transaction -- the data
is visible to the request that wrote it, and gone once the test finishes.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator

import httpx
import pytest
from httpx import ASGITransport
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.db import redis as redis_module
from app.db.session import get_session
from app.main import app
from app.models.enums import UserRole
from app.models.user import User


@pytest.fixture(autouse=True)
async def _reset_redis_client() -> AsyncGenerator[None, None]:
    """Drop the cached Redis client between tests.

    The client binds to the event loop that created it, and pytest-asyncio gives
    each test a fresh loop; a client carried over would fail on the next test.
    """
    yield
    try:
        await redis_module.close_redis()
    except (OSError, RedisError):  # pragma: no cover - best-effort cleanup
        redis_module._client = None


@pytest.fixture
async def redis_available() -> bool:
    """Whether Redis is reachable, for tests that need real revocation."""
    try:
        await redis_module.get_redis().ping()
    except (OSError, RedisError):
        return False
    return True


@pytest.fixture(autouse=True)
async def _denylist_off_without_redis(
    redis_available: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep authentication usable when Redis is not running.

    The denylist check fails closed, so without this every authenticated request
    in the suite would return 503 rather than exercising what it means to.
    """
    if not redis_available:
        monkeypatch.setattr(settings, "AUTH_TOKEN_DENYLIST_ENABLED", False)


@pytest.fixture
async def session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    try:
        connection = await engine.connect()
    except (OSError, SQLAlchemyError) as exc:  # pragma: no cover - environment dependent
        await engine.dispose()
        pytest.skip(f"PostgreSQL is not reachable: {exc}")

    transaction = await connection.begin()
    db = AsyncSession(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    try:
        yield db
    finally:
        await db.close()
        await transaction.rollback()
        await connection.close()
        await engine.dispose()


@pytest.fixture
async def client(session: AsyncSession) -> AsyncGenerator[httpx.AsyncClient, None]:
    """An HTTP client whose requests run in the test's transaction."""

    async def override_get_session() -> AsyncGenerator[AsyncSession, None]:
        yield session

    app.dependency_overrides[get_session] = override_get_session
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def password() -> str:
    """A password that satisfies the configured policy."""
    return "correct-horse-battery-staple-7"


@pytest.fixture
async def make_user(session: AsyncSession, password: str):
    """Factory creating an account directly, bypassing registration."""

    async def _make(
        role: UserRole = UserRole.VIEWER,
        *,
        is_active: bool = True,
        username: str | None = None,
    ) -> User:
        suffix = uuid.uuid4().hex[:8]
        name = username or f"{role.value}-{suffix}"
        user = User(
            email=f"{name}@soc.example.com",
            username=name,
            full_name=f"Test {role.value}",
            hashed_password=hash_password(password),
            role=role,
            is_active=is_active,
        )
        session.add(user)
        await session.flush()
        return user

    return _make


@pytest.fixture
def auth_header():
    """Build an Authorization header for a user."""

    def _header(user: User) -> dict[str, str]:
        token, _, _ = create_access_token(user_id=user.id, role=user.role)
        return {"Authorization": f"Bearer {token}"}

    return _header
