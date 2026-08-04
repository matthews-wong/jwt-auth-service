"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from jwtauth.main import app
from jwtauth.store import get_store


@pytest.fixture(autouse=True)
def clean_store():
    """Reset the in-memory store before and after every test for isolation."""
    store = get_store()
    store.clear()
    yield
    store.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def registered_user(client: TestClient) -> dict[str, str]:
    """Register a user and return its credentials."""
    creds = {"username": "alice", "password": "s3cret-passw0rd"}
    resp = client.post("/auth/register", json=creds)
    assert resp.status_code == 201, resp.text
    return creds
