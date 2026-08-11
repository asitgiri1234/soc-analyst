"""Shared FastAPI dependencies: who is calling, and may they do this.

Every rejection here returns as little as possible. A caller learns that its
token was not accepted, not why -- whether the account is missing, deactivated
or simply unknown is not something an unauthenticated client should be able to
probe.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.authz import has_at_least
from app.core.logging import get_logger
from app.core.security import InvalidTokenError, TokenClaims, decode_access_token
from app.db.session import get_session
from app.models.enums import UserRole
from app.models.user import User
from app.services import token_denylist

logger = get_logger(__name__)

# auto_error=False so a missing header produces our own 401 with a
# WWW-Authenticate challenge, rather than FastAPI's bare 403.
bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

SessionDep = Annotated[AsyncSession, Depends(get_session)]
CredentialsDep = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]

CREDENTIALS_HEADERS = {"WWW-Authenticate": "Bearer"}


def _unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers=CREDENTIALS_HEADERS,
    )


async def get_token_claims(credentials: CredentialsDep) -> TokenClaims:
    """Validate the bearer token and return its claims.

    Split out from ``get_current_user`` so that logout, which needs the token's
    ``jti`` to revoke it, does not have to decode the header a second time.
    """
    if credentials is None:
        raise _unauthorized("Not authenticated")

    try:
        claims = decode_access_token(credentials.credentials)
    except InvalidTokenError as exc:
        logger.debug("rejected token: %s", exc)
        raise _unauthorized() from exc
    return claims


TokenClaimsDep = Annotated[TokenClaims, Depends(get_token_claims)]


async def get_current_user(session: SessionDep, claims: TokenClaimsDep) -> User:
    """Resolve the caller from its validated token claims.

    Raises 401 unless the token is unrevoked and belongs to an account that
    still exists; 403 when that account has been deactivated.
    """
    try:
        if await token_denylist.is_revoked(claims.jti):
            raise _unauthorized("Token has been revoked")
    except token_denylist.DenylistUnavailableError as exc:
        # Fail closed: an unreadable denylist may be hiding a revoked token.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable",
        ) from exc

    user = await session.get(User, claims.user_id)
    if user is None:
        raise _unauthorized()

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated"
        )

    # The role in the token is a snapshot from login; the stored role wins, so a
    # demotion takes effect immediately rather than at token expiry.
    if user.role != claims.role:
        logger.info(
            "role changed since token was issued for %s: %s -> %s",
            user.id,
            claims.role,
            user.role,
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(minimum: UserRole) -> Callable[[User], Awaitable[User]]:
    """Dependency factory admitting ``minimum`` and every role above it.

    Used as ``Depends(require_role(UserRole.ANALYST))``.
    """

    async def dependency(user: CurrentUser) -> User:
        if not has_at_least(user.role, minimum):
            logger.info(
                "denied %s (role=%s) an endpoint requiring %s", user.id, user.role, minimum
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires the {minimum.value} role or higher",
            )
        return user

    return dependency


# The three tiers, named so endpoints read as their own documentation.
RequireViewer = Annotated[User, Depends(require_role(UserRole.VIEWER))]
RequireAnalyst = Annotated[User, Depends(require_role(UserRole.ANALYST))]
RequireAdmin = Annotated[User, Depends(require_role(UserRole.ADMIN))]
