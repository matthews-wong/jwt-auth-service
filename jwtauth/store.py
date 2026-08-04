"""In-memory persistence for users and refresh-token records.

This is a demo store: everything lives in process memory and is lost on
restart. It is deliberately behind a small class so it can be swapped for a
real database-backed implementation without touching the route handlers.
"""

from __future__ import annotations

from .models import RefreshRecord, UserRecord


class Store:
    """Process-local store for users and refresh tokens."""

    def __init__(self) -> None:
        self._users_by_username: dict[str, UserRecord] = {}
        self._users_by_id: dict[str, UserRecord] = {}
        self._refresh_by_id: dict[str, RefreshRecord] = {}
        self._refresh_by_hash: dict[str, RefreshRecord] = {}

    # --- users -------------------------------------------------------------

    def add_user(self, user: UserRecord) -> None:
        self._users_by_username[user.username] = user
        self._users_by_id[user.id] = user

    def get_user_by_username(self, username: str) -> UserRecord | None:
        return self._users_by_username.get(username)

    def get_user_by_id(self, user_id: str) -> UserRecord | None:
        return self._users_by_id.get(user_id)

    # --- refresh tokens ----------------------------------------------------

    def add_refresh(self, record: RefreshRecord) -> None:
        self._refresh_by_id[record.id] = record
        self._refresh_by_hash[record.token_hash] = record

    def get_refresh_by_hash(self, token_hash: str) -> RefreshRecord | None:
        return self._refresh_by_hash.get(token_hash)

    def get_refresh_by_id(self, record_id: str) -> RefreshRecord | None:
        return self._refresh_by_id.get(record_id)

    def refresh_records_in_family(self, family_id: str) -> list[RefreshRecord]:
        return [r for r in self._refresh_by_id.values() if r.family_id == family_id]

    # --- test / lifecycle helpers -----------------------------------------

    def clear(self) -> None:
        """Reset all state. Handy for isolated tests."""
        self._users_by_username.clear()
        self._users_by_id.clear()
        self._refresh_by_id.clear()
        self._refresh_by_hash.clear()


# A single module-level store instance backs the running app. Route handlers
# receive it via a FastAPI dependency so tests can swap or reset it.
_store = Store()


def get_store() -> Store:
    """FastAPI dependency returning the shared store instance."""
    return _store
