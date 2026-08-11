"""Login and token payloads."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.schemas.user import Password, UserRead


class LoginRequest(BaseModel):
    """Credentials presented at login.

    Identification is by email: it is the one identifier guaranteed unique and
    stable, and it keeps the failure message ("incorrect email or password")
    honest about what was checked.
    """

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: Password


class TokenResponse(BaseModel):
    """A freshly issued access token.

    ``expires_in`` is seconds from now, matching the OAuth 2.0 convention, so a
    client does not have to decode the token to schedule a refresh.
    """

    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(description="Seconds until the token expires")
    user: UserRead


class LogoutResponse(BaseModel):
    """Confirmation that a token was revoked."""

    detail: str
    token_revoked: bool
