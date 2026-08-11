"""Password hashing and access-token issuing.

Passwords are hashed with Argon2id, the algorithm OWASP recommends first for new
applications. Unlike bcrypt it has no 72-byte input truncation, so a long
passphrase is hashed in full.

Nothing here touches the database or FastAPI: it is pure crypto, which keeps it
straightforward to test.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import settings
from app.models.enums import UserRole

# argon2-cffi's defaults track the library's current recommendations.
_hasher = PasswordHasher()

TOKEN_TYPE = "access"  # noqa: S105 - a claim value, not a credential


class InvalidTokenError(Exception):
    """Raised when a token is malformed, expired, or fails signature checks."""


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """The claims this application relies on, already validated."""

    user_id: uuid.UUID
    role: UserRole
    jti: str
    expires_at: datetime


def hash_password(password: str) -> str:
    """Return an Argon2id hash. The plaintext is never stored or logged."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Check a password against a hash, returning False rather than raising."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when a stored hash predates the current Argon2 parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        # An unreadable hash cannot be upgraded in place; leave it to fail
        # verification instead.
        return False


@cache
def _placeholder_hash() -> str:
    """A hash to verify against when no account matched.

    Computed once on first use rather than at import, so starting the process
    does not pay for an Argon2 hash it may never need.
    """
    return _hasher.hash("placeholder-for-timing-equalisation")


def dummy_verify() -> None:
    """Burn roughly one hash verification's worth of time.

    Called when login is attempted for an address that has no account, so the
    response time does not reveal which addresses are registered.
    """
    verify_password("not-the-placeholder", _placeholder_hash())


def create_access_token(
    *,
    user_id: uuid.UUID,
    role: UserRole,
    expires_delta: timedelta | None = None,
) -> tuple[str, datetime, str]:
    """Mint a signed access token.

    Returns the encoded token, its expiry, and its ``jti`` so the caller can
    report the lifetime and revoke the token on logout.
    """
    issued_at = datetime.now(UTC)
    lifetime = expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = issued_at + lifetime
    jti = str(uuid.uuid4())

    payload = {
        "sub": str(user_id),
        "role": role.value,
        "typ": TOKEN_TYPE,
        "jti": jti,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "iss": settings.JWT_ISSUER,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, expires_at, jti


def decode_access_token(token: str) -> TokenClaims:
    """Validate a token's signature, expiry and issuer, then return its claims.

    ``algorithms`` is pinned to the configured algorithm so a token cannot ask to
    be verified with a weaker one -- or with ``none``.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            options={"require": ["exp", "iat", "nbf", "sub", "jti", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    # A refresh token, once those exist, must not be accepted as an access token.
    if payload.get("typ") != TOKEN_TYPE:
        raise InvalidTokenError("token is not an access token")

    try:
        user_id = uuid.UUID(payload["sub"])
        role = UserRole(payload["role"])
    except (KeyError, ValueError) as exc:
        raise InvalidTokenError("token claims are malformed") from exc

    return TokenClaims(
        user_id=user_id,
        role=role,
        jti=payload["jti"],
        expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
    )
