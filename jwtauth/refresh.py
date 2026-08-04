"""Refresh-token issuing, rotation, revocation and reuse detection.

A refresh token is an opaque, high-entropy random string handed to the client.
Only a SHA-256 hash of it is ever stored, so a leaked store cannot be replayed
against this service. Tokens are grouped into a *family*: the chain of tokens
descended from a single login. Rotation revokes the presented token and issues
its successor in the same family; presenting an already-rotated (revoked) token
is treated as theft and revokes the entire family.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from .config import Settings, get_settings
from .models import RefreshRecord
from .store import Store

# Bytes of entropy for each opaque refresh token (token_urlsafe input).
_TOKEN_BYTES = 32


class RefreshError(Exception):
    """Base class for refresh-token failures."""


class InvalidRefreshToken(RefreshError):
    """Token is unknown, malformed, or expired."""


class RefreshTokenReuse(RefreshError):
    """A previously rotated/revoked token was presented again (possible theft)."""


def _hash_token(token: str) -> str:
    """Return a hex SHA-256 digest of the opaque token for storage/lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_record(
    user_id: str,
    family_id: str,
    settings: Settings,
    now: datetime,
) -> tuple[str, RefreshRecord]:
    """Create a fresh opaque token plus its (hashed) store record."""
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    record = RefreshRecord(
        id=uuid.uuid4().hex,
        user_id=user_id,
        family_id=family_id,
        token_hash=_hash_token(token),
        issued_at=now,
        expires_at=now + timedelta(seconds=settings.refresh_token_ttl_seconds),
    )
    return token, record


def issue_refresh_token(
    store: Store,
    user_id: str,
    settings: Settings | None = None,
    *,
    now: datetime | None = None,
) -> str:
    """Start a new token family for ``user_id`` and return the opaque token."""
    settings = settings or get_settings()
    now = now or datetime.now(timezone.utc)
    token, record = _new_record(user_id, uuid.uuid4().hex, settings, now)
    store.add_refresh(record)
    return token


def _revoke_family(store: Store, family_id: str) -> None:
    for record in store.refresh_records_in_family(family_id):
        record.revoked = True


def rotate_refresh_token(
    store: Store,
    presented_token: str,
    settings: Settings | None = None,
    *,
    now: datetime | None = None,
) -> tuple[str, str]:
    """Validate and rotate ``presented_token``.

    Returns ``(user_id, new_refresh_token)`` on success. Raises
    ``RefreshTokenReuse`` (after revoking the whole family) if the token was
    already rotated, or ``InvalidRefreshToken`` if it is unknown or expired.
    """
    settings = settings or get_settings()
    now = now or datetime.now(timezone.utc)

    record = store.get_refresh_by_hash(_hash_token(presented_token))
    if record is None:
        raise InvalidRefreshToken("unknown refresh token")

    # A revoked record that is presented again means the token was already
    # rotated (or the family was killed): classic refresh-token reuse.
    if record.revoked:
        _revoke_family(store, record.family_id)
        raise RefreshTokenReuse("refresh token reuse detected")

    if record.expires_at <= now:
        record.revoked = True
        raise InvalidRefreshToken("refresh token has expired")

    # Rotate: retire the presented token and mint its successor in the family.
    new_token, new_record = _new_record(record.user_id, record.family_id, settings, now)
    record.revoked = True
    record.replaced_by = new_record.id
    store.add_refresh(new_record)
    return record.user_id, new_token


def revoke_refresh_token(store: Store, presented_token: str) -> bool:
    """Revoke a single refresh token (logout). Returns True if one was found."""
    record = store.get_refresh_by_hash(_hash_token(presented_token))
    if record is None:
        return False
    record.revoked = True
    return True
