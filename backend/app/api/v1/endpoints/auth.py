"""Registration, login and logout."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from app.api.deps import CurrentUser, SessionDep, TokenClaimsDep
from app.core.config import settings
from app.core.security import create_access_token
from app.models.enums import AuditAction
from app.schemas.auth import LoginRequest, LogoutResponse, TokenResponse
from app.schemas.user import UserCreate, UserRead
from app.services import audit, auth, token_denylist

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account",
)
async def register(payload: UserCreate, session: SessionDep, request: Request) -> UserRead:
    """Register a new account.

    The account is created with the VIEWER role regardless of what is sent; an
    administrator grants anything beyond read access.
    """
    try:
        user = await auth.register(session, payload, request=request)
    except auth.EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists",
        ) from exc
    except auth.UsernameTakenError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="That username is taken"
        ) from exc

    await session.commit()
    return UserRead.model_validate(user)


@router.post("/login", response_model=TokenResponse, summary="Exchange credentials for a token")
async def login(payload: LoginRequest, session: SessionDep, request: Request) -> TokenResponse:
    """Authenticate and receive an access token.

    Every outcome is audited. A failure returns 401 with the same message
    whatever went wrong, so the response cannot be used to discover which
    addresses have accounts.
    """
    user = await auth.authenticate(
        session, email=payload.email, password=payload.password, request=request
    )
    if user is None:
        # Committed so that failed attempts are recorded, not rolled back.
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_at, jti = create_access_token(user_id=user.id, role=user.role)

    await audit.record(
        session,
        action=AuditAction.LOGIN,
        resource_type="session",
        actor=user,
        resource_id=user.id,
        description="login succeeded",
        context={"jti": jti, "role": user.role.value},
        request=request,
    )
    await session.commit()
    await session.refresh(user)

    return TokenResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserRead.model_validate(user),
    )


@router.post("/logout", response_model=LogoutResponse, summary="Revoke the current token")
async def logout(
    session: SessionDep,
    request: Request,
    user: CurrentUser,
    claims: TokenClaimsDep,
) -> LogoutResponse:
    """Revoke the presented token.

    The token's id goes on the denylist until it would have expired, so it stops
    working immediately rather than at expiry.
    """
    revoked = await token_denylist.revoke(claims.jti, claims.expires_at)

    await audit.record(
        session,
        action=AuditAction.LOGOUT,
        resource_type="session",
        actor=user,
        resource_id=user.id,
        description="logout" if revoked else "logout (token not revoked)",
        context={"jti": claims.jti, "revoked": revoked},
        request=request,
    )
    await session.commit()

    detail = (
        "Signed out and token revoked"
        if revoked
        else "Signed out; token remains valid until it expires"
    )
    return LogoutResponse(detail=detail, token_revoked=revoked)


@router.get("/me", response_model=UserRead, summary="The authenticated account")
async def me(user: CurrentUser) -> UserRead:
    """Return the caller's own account. Any authenticated role may call this."""
    return UserRead.model_validate(user)
