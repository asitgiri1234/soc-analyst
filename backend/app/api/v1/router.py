"""Aggregates all v1 routers.

Feature routers (alerts, investigations, detections, ...) are registered here
as they are introduced in later phases.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    dashboard,
    detection,
    health,
    incidents,
    ingestion_jobs,
    knowledge,
    log_sources,
    protected,
    users,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["system"])
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(log_sources.router)
api_router.include_router(ingestion_jobs.router)
api_router.include_router(detection.router)
api_router.include_router(incidents.router)
api_router.include_router(knowledge.router)
api_router.include_router(dashboard.router)
api_router.include_router(protected.router)
