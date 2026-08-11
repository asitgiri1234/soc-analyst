"""Liveness and readiness endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.core.config import settings
from app.core.logging import get_logger
from app.db.redis import get_redis
from app.db.session import get_session
from app.schemas.health import DependencyStatus, HealthResponse, ReadinessResponse

router = APIRouter()
logger = get_logger(__name__)

SessionDep = Annotated[AsyncSession, Depends(get_session)]


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
async def health() -> HealthResponse:
    """Report that the process is up. Does not touch external dependencies."""
    return HealthResponse(
        status="ok",
        service=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT,
        version=__version__,
    )


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness probe")
async def ready(session: SessionDep) -> ReadinessResponse:
    """Check that PostgreSQL and Redis are reachable."""
    postgres = DependencyStatus(connected=True)
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a status
        logger.warning("postgres readiness check failed: %s", exc)
        postgres = DependencyStatus(connected=False, detail=str(exc))

    redis_status = DependencyStatus(connected=True)
    try:
        await get_redis().ping()
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a status
        logger.warning("redis readiness check failed: %s", exc)
        redis_status = DependencyStatus(connected=False, detail=str(exc))

    overall = "ready" if postgres.connected and redis_status.connected else "degraded"
    return ReadinessResponse(status=overall, postgres=postgres, redis=redis_status)
