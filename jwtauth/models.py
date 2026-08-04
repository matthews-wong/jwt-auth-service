"""Pydantic request/response schemas and internal store records.

The Pydantic models define the public API contract; the dataclasses at the
bottom are the internal shapes persisted by the in-memory store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, Field


# --- API request models ---------------------------------------------------


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


# --- API response models ---------------------------------------------------


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # access-token lifetime in seconds


class UserPublic(BaseModel):
    id: str
    username: str
    created_at: datetime


class MessageResponse(BaseModel):
    detail: str


# --- Internal store records ------------------------------------------------


@dataclass
class UserRecord:
    """A registered user; ``hashed_password`` is never exposed via the API."""

    id: str
    username: str
    hashed_password: str
    created_at: datetime


@dataclass
class RefreshRecord:
    """One issued refresh token.

    Tokens are grouped into a ``family_id`` so that reuse of a rotated token
    can revoke every descendant in one go. ``token_hash`` stores only a hash of
    the opaque token, never the token itself.
    """

    id: str
    user_id: str
    family_id: str
    token_hash: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    # jti of the record that replaced this one when it was rotated.
    replaced_by: str | None = None
