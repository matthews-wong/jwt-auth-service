"""Application settings loaded from the environment (see .env.example).

Values fall back to development-safe defaults so the test suite and a local
`uvicorn` run work out of the box. Always set a strong ``JWT_SECRET`` in any
real deployment.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the auth service."""

    # NOTE: the default is intentionally obvious so it is never mistaken for a
    # production secret. Override it via the JWT_SECRET environment variable.
    jwt_secret: str = "dev-insecure-secret-change-me-before-deploying-anywhere"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "jwt-auth-service"

    # Access tokens are deliberately short-lived; refresh tokens live longer
    # and are rotated on every use.
    access_token_ttl_seconds: int = 900  # 15 minutes
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 7  # 7 days

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (single load per process)."""
    return Settings()
