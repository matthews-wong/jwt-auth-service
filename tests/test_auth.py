"""End-to-end tests for the auth flows via FastAPI's TestClient."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from jwtauth.config import get_settings
from jwtauth.security import create_access_token


def _login(client, creds) -> dict:
    resp = client.post("/auth/login", json=creds)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_register_login_and_access_protected_route(client, registered_user):
    tokens = _login(client, registered_user)
    assert tokens["token_type"] == "bearer"
    assert tokens["access_token"] and tokens["refresh_token"]

    resp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["username"] == registered_user["username"]


def test_protected_route_requires_a_token(client, registered_user):
    assert client.get("/auth/me").status_code == 401


def test_wrong_password_is_rejected(client, registered_user):
    resp = client.post(
        "/auth/login",
        json={"username": registered_user["username"], "password": "not-the-password"},
    )
    assert resp.status_code == 401


def test_unknown_user_is_rejected(client):
    resp = client.post(
        "/auth/login",
        json={"username": "nobody", "password": "whatever-12345"},
    )
    assert resp.status_code == 401


def test_duplicate_registration_conflicts(client, registered_user):
    resp = client.post("/auth/register", json=registered_user)
    assert resp.status_code == 409


def test_access_token_carries_expiry_and_subject(client, registered_user):
    tokens = _login(client, registered_user)
    settings = get_settings()
    claims = jwt.decode(
        tokens["access_token"],
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
    )
    assert claims["type"] == "access"
    assert claims["exp"] > claims["iat"]
    assert claims["sub"]


def test_refresh_rotates_and_issues_new_tokens(client, registered_user):
    tokens = _login(client, registered_user)
    old_refresh = tokens["refresh_token"]

    resp = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 200, resp.text
    new_tokens = resp.json()

    # Rotation must hand back a *different* refresh token.
    assert new_tokens["refresh_token"] != old_refresh

    # The freshly issued access token still works on the protected route.
    resp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {new_tokens['access_token']}"},
    )
    assert resp.status_code == 200


def test_reusing_old_refresh_token_is_detected_and_revokes_family(
    client, registered_user
):
    tokens = _login(client, registered_user)
    old_refresh = tokens["refresh_token"]

    # First rotation succeeds and yields a new refresh token.
    first = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert first.status_code == 200
    new_refresh = first.json()["refresh_token"]

    # Replaying the now-rotated old token is flagged as reuse.
    reuse = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert reuse.status_code == 401

    # Reuse detection revokes the whole family, so the legitimately rotated
    # token is invalidated too.
    followup = client.post("/auth/refresh", json={"refresh_token": new_refresh})
    assert followup.status_code == 401


def test_unknown_refresh_token_is_rejected(client):
    resp = client.post("/auth/refresh", json={"refresh_token": "not-a-real-token"})
    assert resp.status_code == 401


def test_logout_revokes_refresh_token(client, registered_user):
    tokens = _login(client, registered_user)
    refresh_token = tokens["refresh_token"]

    resp = client.post("/auth/logout", json={"refresh_token": refresh_token})
    assert resp.status_code == 200

    # A revoked token can no longer be rotated.
    resp = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 401


def test_refresh_token_is_not_accepted_as_access_token(client, registered_user):
    tokens = _login(client, registered_user)
    resp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {tokens['refresh_token']}"},
    )
    assert resp.status_code == 401


def _claims_for(tokens: dict) -> dict:
    """Decode a freshly issued access token to recover its real ``sub``."""
    settings = get_settings()
    return jwt.decode(
        tokens["access_token"],
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
    )


# --- access-token security: signature, algorithm and expiry enforcement -----


def test_expired_access_token_is_rejected(client, registered_user):
    """A correctly signed token whose ``exp`` has passed must be refused."""
    tokens = _login(client, registered_user)
    user_id = _claims_for(tokens)["sub"]
    # Mint a token that was already expired an hour ago for the *real* user, so
    # the only possible reason for a 401 is expiry (not an unknown subject).
    expired = create_access_token(
        user_id,
        get_settings(),
        now=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401


def test_tampered_access_token_signature_is_rejected(client, registered_user):
    """Flipping a byte of the signature must invalidate the token."""
    tokens = _login(client, registered_user)
    header, payload, sig = tokens["access_token"].split(".")
    tampered_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered = f"{header}.{payload}.{tampered_sig}"
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


def test_access_token_signed_with_wrong_secret_is_rejected(client, registered_user):
    """A token forged with an attacker-controlled secret must be refused."""
    tokens = _login(client, registered_user)
    settings = get_settings()
    claims = _claims_for(tokens)
    forged = jwt.encode(
        {**claims, "iss": settings.jwt_issuer},
        "attacker-controlled-secret",
        algorithm="HS256",
    )
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_alg_none_access_token_is_rejected(client, registered_user):
    """An unsigned ``alg=none`` token (algorithm-confusion attack) must fail."""
    tokens = _login(client, registered_user)
    forged = jwt.encode(_claims_for(tokens), key="", algorithm="none")
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
