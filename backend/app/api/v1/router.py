"""Aggregates all v1 routers.

Feature routers (alerts, investigations, detections, ...) are registered here
as they are introduced in later phases.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import health

api_router = APIRouter()
api_router.include_router(health.router, tags=["system"])
