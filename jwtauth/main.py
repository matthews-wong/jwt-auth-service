"""FastAPI application and auth route handlers.

Endpoints:
    POST /auth/register  - create a user
    POST /auth/login     - verify credentials, issue access + refresh tokens
    POST /auth/refresh   - rotate the refresh token, detect reuse
    POST /auth/logout    - revoke a refresh token
    GET  /auth/me        - return the current user (protected)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status

from . import __version__
from .config import get_settings
from .deps import get_current_user
from .models import (
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserPublic,
    UserRecord,
)
from .refresh import (
    InvalidRefreshToken,
    RefreshTokenReuse,
    issue_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
)
from .security import create_access_token, hash_password, verify_password
from .store import Store, get_store

router = APIRouter(prefix="/auth", tags=["auth"])


def _token_pair(store: Store, user_id: str) -> TokenPair:
    """Mint a fresh access token plus a new refresh-token family."""
    settings = get_settings()
    access = create_access_token(user_id, settings)
    refresh = issue_refresh_token(store, user_id, settings)
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post(
    "/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: RegisterRequest,
    store: Store = Depends(get_store),
) -> UserPublic:
    if store.get_user_by_username(payload.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="username already registered",
        )
    user = UserRecord(
        id=uuid.uuid4().hex,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        created_at=datetime.now(timezone.utc),
    )
    store.add_user(user)
    return UserPublic(id=user.id, username=user.username, created_at=user.created_at)


@router.post("/login", response_model=TokenPair)
def login(
    payload: LoginRequest,
    store: Store = Depends(get_store),
) -> TokenPair:
    user = store.get_user_by_username(payload.username)
    # Return the same error whether the user is missing or the password is
    # wrong, so the response does not reveal which usernames exist.
    if user is None or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
        )
    return _token_pair(store, user.id)


@router.post("/refresh", response_model=TokenPair)
def refresh(
    payload: RefreshRequest,
    store: Store = Depends(get_store),
) -> TokenPair:
    settings = get_settings()
    try:
        user_id, new_refresh = rotate_refresh_token(
            store, payload.refresh_token, settings
        )
    except RefreshTokenReuse as exc:
        # The family is already revoked inside rotate_refresh_token; surface a
        # 401 so the client is forced to re-authenticate.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="refresh token reuse detected; session revoked",
        ) from exc
    except InvalidRefreshToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired refresh token",
        ) from exc

    access = create_access_token(user_id, settings)
    return TokenPair(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    payload: LogoutRequest,
    store: Store = Depends(get_store),
) -> MessageResponse:
    # Idempotent: logging out an unknown/already-revoked token still succeeds.
    revoke_refresh_token(store, payload.refresh_token)
    return MessageResponse(detail="logged out")


@router.get("/me", response_model=UserPublic)
def me(current_user: UserRecord = Depends(get_current_user)) -> UserPublic:
    return UserPublic(
        id=current_user.id,
        username=current_user.username,
        created_at=current_user.created_at,
    )


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="JWT Auth Service",
        version=__version__,
        description=(
            "JWT authentication microservice with short-lived access tokens "
            "and rotating, hashed refresh tokens (with reuse detection)."
        ),
    )

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(router)
    return app


app = create_app()
