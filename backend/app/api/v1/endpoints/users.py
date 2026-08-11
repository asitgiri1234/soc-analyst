"""Account administration.

Everything here is ADMIN-only apart from the self-service password change.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select

from app.api.deps import CurrentUser, RequireAdmin, SessionDep
from app.core.security import hash_password, verify_password
from app.models.enums import AuditAction
from app.models.user import User
from app.schemas.user import PasswordChange, UserRead, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserRead], summary="List accounts (admin)")
async def list_users(
    session: SessionDep,
    _admin: RequireAdmin,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[UserRead]:
    """Page through accounts, newest first."""
    result = await session.execute(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    )
    return [UserRead.model_validate(user) for user in result.scalars()]


@router.get("/{user_id}", response_model=UserRead, summary="Fetch an account (admin)")
async def get_user(user_id: uuid.UUID, session: SessionDep, _admin: RequireAdmin) -> UserRead:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead, summary="Change a role (admin)")
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    session: SessionDep,
    request: Request,
    admin: RequireAdmin,
) -> UserRead:
    """Grant or revoke a role, or deactivate an account.

    An administrator may not demote or deactivate themselves: that is the usual
    way to lock every administrator out of a system by accident.
    """
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        return UserRead.model_validate(user)

    if user.id == admin.id:
        if "role" in updates and updates["role"] != user.role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot change your own role",
            )
        if updates.get("is_active") is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot deactivate your own account",
            )

    changes = {
        field: {"from": getattr(user, field), "to": value}
        for field, value in updates.items()
        if getattr(user, field) != value
    }
    for field, value in updates.items():
        setattr(user, field, value)
    await session.flush()

    await audit.record(
        session,
        action=AuditAction.UPDATE,
        resource_type="user",
        actor=admin,
        resource_id=user.id,
        description="account updated by administrator",
        # Enum members are not JSON-serialisable; store their values.
        changes={
            field: {key: getattr(val, "value", val) for key, val in delta.items()}
            for field, delta in changes.items()
        },
        request=request,
    )
    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user)


@router.post(
    "/me/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change your own password",
)
async def change_password(
    payload: PasswordChange,
    session: SessionDep,
    request: Request,
    user: CurrentUser,
) -> None:
    """Replace the caller's password, which requires the current one.

    Existing tokens keep working until they expire; revoking them all needs a
    per-user token generation counter, which the refresh-token work will add.
    """
    if not verify_password(payload.current_password, user.hashed_password):
        await audit.record(
            session,
            action=AuditAction.UPDATE,
            resource_type="user",
            actor=user,
            resource_id=user.id,
            description="password change rejected: current password incorrect",
            request=request,
            success=False,
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect"
        )

    user.hashed_password = hash_password(payload.new_password)
    await session.flush()

    await audit.record(
        session,
        action=AuditAction.UPDATE,
        resource_type="user",
        actor=user,
        resource_id=user.id,
        description="password changed",
        request=request,
    )
    await session.commit()
