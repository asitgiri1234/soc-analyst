"""User-facing representations of an account.

``UserRead`` is built field by field rather than from the ORM object wholesale,
so a column added to the model later cannot silently start appearing in API
responses. ``hashed_password`` in particular must never leave the server.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

from app.core.config import settings
from app.models.enums import UserRole

# Letters, digits, dot, dash and underscore; must start with a letter or digit.
Username = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
        strip_whitespace=True,
    ),
]

Password = Annotated[str, Field(min_length=8, max_length=1024)]


def _validate_password_strength(password: str) -> str:
    """Reject passwords that are trivially guessable.

    The maximum length is bounded in ``Password`` so that an enormous input
    cannot be used to tie up the hasher.
    """
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at least {settings.MIN_PASSWORD_LENGTH} characters"
        )
    if password.isdigit() or password.isalpha():
        raise ValueError("password must contain both letters and digits")
    return password


class UserCreate(BaseModel):
    """Registration payload.

    There is deliberately no ``role`` field: a caller must not be able to grant
    itself privileges at sign-up. New accounts start as VIEWER and are promoted
    by an administrator.
    """

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    username: Username
    password: Password
    full_name: str | None = Field(default=None, max_length=255)

    _check_password = field_validator("password")(_validate_password_strength)


class UserRead(BaseModel):
    """Everything the API is willing to disclose about an account."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    username: str
    full_name: str | None
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class UserUpdate(BaseModel):
    """Administrative changes to another account.

    Only fields an administrator may set are present; there is no password field
    here, so this route cannot be used to take over an account.
    """

    model_config = ConfigDict(extra="forbid")

    role: UserRole | None = None
    is_active: bool | None = None
    full_name: str | None = Field(default=None, max_length=255)


class PasswordChange(BaseModel):
    """Self-service password change, which requires the current password."""

    model_config = ConfigDict(extra="forbid")

    current_password: Password
    new_password: Password

    _check_password = field_validator("new_password")(_validate_password_strength)
