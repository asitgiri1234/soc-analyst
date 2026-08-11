"""Writing entries to the audit trail.

The actor's email is stored alongside the foreign key so the trail survives the
deletion of the account, and the client's address is captured from the request
where one is available.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.enums import AuditAction
from app.models.user import User


def client_ip(request: Request | None) -> str | None:
    """Best-effort client address.

    ``X-Forwarded-For`` is only consulted when the application sits behind a
    proxy that sets it; the left-most entry is the original client.
    """
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def record(
    session: AsyncSession,
    *,
    action: AuditAction,
    resource_type: str,
    actor: User | None = None,
    actor_email: str | None = None,
    resource_id: uuid.UUID | None = None,
    description: str | None = None,
    changes: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    request: Request | None = None,
    success: bool = True,
) -> AuditLog:
    """Append one entry. The caller controls the surrounding transaction."""
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_email=actor_email or (actor.email if actor else None),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        changes=changes or {},
        context=context or {},
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent") if request else None,
        success=success,
    )
    session.add(entry)
    await session.flush()
    return entry
