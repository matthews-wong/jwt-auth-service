"""FastAPI dependencies: resolve the current user from a bearer access token."""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import UserRecord
from .security import TokenError, decode_access_token
from .store import Store, get_store

# auto_error=False so we can raise a consistent 401 with a WWW-Authenticate
# header rather than FastAPI's default 403 for a missing credential.
_bearer_scheme = HTTPBearer(auto_error=False)

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    store: Store = Depends(get_store),
) -> UserRecord:
    """Return the authenticated user or raise 401.

    Validates the JWT signature/expiry/type, then confirms the subject still
    maps to a known user.
    """
    if credentials is None or not credentials.credentials:
        raise _UNAUTHENTICATED

    try:
        claims = decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = store.get_user_by_id(claims["sub"])
    if user is None:
        raise _UNAUTHENTICATED
    return user
