"""Async SQLAlchemy engine and session management."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    # Statement echo prints every query and its bound parameters, which for
    # this application means usernames, source addresses and log message bodies
    # landing in the application log. Useful while developing locally, and a
    # standing data-exposure risk anywhere else, so DEBUG alone does not enable
    # it -- the environment has to be `local` too.
    echo=settings.DEBUG and settings.ENVIRONMENT == "local",
    pool_pre_ping=True,
    future=True,
)

SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a request-scoped database session."""
    async with SessionLocal() as session:
        yield session


async def dispose_engine() -> None:
    """Close pooled connections during application shutdown."""
    await engine.dispose()
