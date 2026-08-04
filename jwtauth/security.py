"""Password hashing and access-token (JWT) minting/verification.

Passwords are hashed with bcrypt via passlib. Access tokens are signed JWTs
carrying a short expiry (``exp``), issued-at (``iat``), issuer (``iss``),
subject (``sub`` = user id) and a ``type`` claim so a refresh token can never
be accepted where an access token is expected.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from .config import Settings, get_settings

# bcrypt has a hard 72-byte password limit; passlib truncates and warns. We
# keep a single shared context so the (relatively expensive) backend is
# initialised once.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_TOKEN_TYPE = "access"


class TokenError(Exception):
    """Raised when an access token is missing, malformed, or expired."""


# --- passwords -------------------------------------------------------------


def hash_password(password: str) -> str:
    """Return a bcrypt hash of ``password``."""
    return _pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time-ish verification of ``password`` against ``hashed``."""
    return _pwd_context.verify(password, hashed)


# --- access tokens ---------------------------------------------------------


def create_access_token(
    user_id: str,
    settings: Settings | None = None,
    *,
    now: datetime | None = None,
) -> str:
    """Mint a signed, short-lived access token for ``user_id``."""
    settings = settings or get_settings()
    now = now or datetime.now(timezone.utc)
    expire = now + timedelta(seconds=settings.access_token_ttl_seconds)
    payload = {
        "sub": user_id,
        "type": ACCESS_TOKEN_TYPE,
        "iss": settings.jwt_issuer,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str, settings: Settings | None = None) -> dict:
    """Verify signature/expiry and return the claims of an access token.

    Raises ``TokenError`` on any validation failure, including a token whose
    ``type`` claim is not ``access`` (e.g. a refresh token presented here).
    """
    settings = settings or get_settings()
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("access token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid access token") from exc

    if claims.get("type") != ACCESS_TOKEN_TYPE:
        raise TokenError("not an access token")
    return claims
