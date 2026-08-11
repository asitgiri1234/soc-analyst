"""Worked example of the three authorization tiers.

These routes exist to demonstrate and test ``require_role``; they hold no real
data and are replaced by the genuine security-data endpoints in later phases.
They are the reference for how those endpoints should declare their access
level:

    GET     any authenticated caller
    GET     VIEWER and above     read security data
    POST    ANALYST and above    modify security data
    DELETE  ADMIN only
"""

from __future__ import annotations

from fastapi import APIRouter, status
from pydantic import BaseModel

from app.api.deps import CurrentUser, RequireAdmin, RequireAnalyst, RequireViewer
from app.models.enums import UserRole

router = APIRouter(prefix="/protected", tags=["protected example"])


class AccessCheck(BaseModel):
    """Echoes back which tier admitted the caller."""

    granted_to: str
    role: UserRole
    username: str


@router.get("/whoami", response_model=AccessCheck, summary="Any authenticated caller")
async def whoami(user: CurrentUser) -> AccessCheck:
    return AccessCheck(granted_to="any authenticated user", role=user.role, username=user.username)


@router.get("/security-data", response_model=AccessCheck, summary="Read (viewer and above)")
async def read_security_data(user: RequireViewer) -> AccessCheck:
    return AccessCheck(granted_to="viewer and above", role=user.role, username=user.username)


@router.post(
    "/security-data",
    response_model=AccessCheck,
    status_code=status.HTTP_201_CREATED,
    summary="Write (analyst and above)",
)
async def write_security_data(user: RequireAnalyst) -> AccessCheck:
    return AccessCheck(granted_to="analyst and above", role=user.role, username=user.username)


@router.delete("/security-data", response_model=AccessCheck, summary="Delete (admin only)")
async def delete_security_data(user: RequireAdmin) -> AccessCheck:
    return AccessCheck(granted_to="admin only", role=user.role, username=user.username)
