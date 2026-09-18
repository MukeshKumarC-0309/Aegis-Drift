"""Application configuration, loaded from the environment with sane defaults.

Everything is resolved once at import time into a cached ``Settings`` singleton so
that config access is cheap from request handlers and background workers alike.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AnyHttpUrl, BeforeValidator, Field, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value: Any) -> Any:
    """Accept a comma-separated string or a JSON array for list-valued settings."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            import json

            return json.loads(text)
        return [item.strip() for item in text.split(",") if item.strip()]
    return value


#: ``NoDecode`` stops pydantic-settings from JSON-decoding the raw environment value
#: before validation runs. Without it, the natural `KEY=a,b,c` form that every
#: ``.env`` and Docker Compose file uses raises a JSON parse error at startup.
CSVList = Annotated[list[str], NoDecode, BeforeValidator(_split_csv)]


#: Where a generated development secret is cached. Git-ignored, and only ever used
#: when SECRET_KEY is not supplied by the environment.
_SECRET_CACHE = Path(__file__).resolve().parents[2] / ".aegisdrift" / "dev-secret.key"


def _local_secret_key() -> str:
    """Return a stable secret for local use, generating one on first run.

    Without persistence a fresh key is minted on every boot, which invalidates
    every issued token and signs the developer out on each restart — the single
    most irritating thing about running this locally. Caching it to a git-ignored
    file removes that, and removes any need to hand-write a `.env` just to get
    started.

    Production must still supply SECRET_KEY explicitly; ``validate_runtime``
    refuses to start without it.
    """
    try:
        if _SECRET_CACHE.exists():
            cached = _SECRET_CACHE.read_text().strip()
            if len(cached) >= 32:
                return cached

        generated = secrets.token_urlsafe(48)
        _SECRET_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _SECRET_CACHE.write_text(generated)
        _SECRET_CACHE.chmod(0o600)
        return generated
    except OSError:
        # Read-only filesystem (a hardened container, for instance). Fall back to an
        # ephemeral key so the process still starts; tokens simply will not survive
        # a restart, which is acceptable because production sets SECRET_KEY anyway.
        return secrets.token_urlsafe(48)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
    )

    # ------------------------------------------------------------------ core
    PROJECT_NAME: str = "Aegis Drift"
    PROJECT_DESCRIPTION: str = (
        "Identity Threat Detection & Response platform: behavioural baselines, "
        "temporal sequence correlation, context-aware damping and explainable AI."
    )
    VERSION: str = "2.0.0"
    ENVIRONMENT: Literal["local", "staging", "production", "test"] = "local"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1

    # --------------------------------------------------------------- security
    SECRET_KEY: str = Field(default_factory=lambda: _local_secret_key())
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    PASSWORD_MIN_LENGTH: int = 12

    # Bootstrap administrator, created on first start when absent.
    FIRST_SUPERUSER_EMAIL: str = "admin@aegisdrift.com"
    FIRST_SUPERUSER_PASSWORD: str = "ChangeMe_Aeg1sDrift!"
    AUTO_SEED: bool = True

    # The analyst/responder/viewer logins exist so the RBAC tiers can be tried out.
    # Their passwords are published in the README, which is fine on a laptop and a
    # complete compromise on anything public — the responder role can quarantine
    # accounts and execute playbooks. They are therefore off by default in
    # production, and refused outright if enabled while still using these values.
    SEED_DEMO_ACCOUNTS: bool | None = None
    DEMO_ANALYST_PASSWORD: str = "AnalystDemo_2026!"
    DEMO_RESPONDER_PASSWORD: str = "ResponderDemo_2026!"
    DEMO_VIEWER_PASSWORD: str = "ViewerDemo_2026!"

    CORS_ORIGINS: CSVList = [
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
    ]
    TRUSTED_HOSTS: CSVList = ["*"]

    # ------------------------------------------------------------- persistence
    POSTGRES_HOST: str | None = None
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "aegisdrift"
    POSTGRES_PASSWORD: str = "aegisdrift"
    POSTGRES_DB: str = "aegisdrift"
    SQLITE_PATH: str = "./aegisdrift.db"
    DATABASE_URL: str | None = None
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_ECHO: bool = False

    REDIS_URL: str | None = None
    CACHE_TTL_SECONDS: int = 30

    # -------------------------------------------------------------- observability
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "console"
    METRICS_ENABLED: bool = True
    SENTRY_DSN: AnyHttpUrl | None = None

    # ------------------------------------------------------------- rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 300
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_INGEST_REQUESTS: int = 2000

    # ----------------------------------------------------------- detection engine
    DECAY_HALFLIFE_HOURS: float = 48.0
    THRESHOLD_EARLY_DRIFT: float = 28.0
    THRESHOLD_ESCALATING: float = 50.0
    THRESHOLD_CRITICAL: float = 75.0
    RECOMPUTE_INTERVAL_SECONDS: int = 45
    RETENTION_DAYS: int = 90

    # ------------------------------------------------------------------ frontend
    SERVE_FRONTEND: bool = True
    FRONTEND_DIST_DIR: str = "../frontend/dist"

    @field_validator("SECRET_KEY")
    @classmethod
    def _reject_weak_secret(cls, v: str, info) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @model_validator(mode="after")
    def _production_requires_explicit_secrets(self) -> Settings:
        """A convenience default must never become a production credential.

        The generated dev key lives in a predictable, git-ignored file. That is
        fine on a laptop and unacceptable on a server, so production has to say
        the secret out loud.
        """
        if self.ENVIRONMENT != "production":
            return self

        problems: list[str] = []
        try:
            cached = _SECRET_CACHE.read_text().strip() if _SECRET_CACHE.exists() else None
        except OSError:
            cached = None

        if cached and cached == self.SECRET_KEY:
            problems.append(
                "SECRET_KEY is the auto-generated development key. Set it explicitly "
                '(python -c "import secrets; print(secrets.token_urlsafe(48))").'
            )
        if self.FIRST_SUPERUSER_PASSWORD == "ChangeMe_Aeg1sDrift!":
            problems.append("FIRST_SUPERUSER_PASSWORD is still the documented default.")
        if self.CORS_ORIGINS == ["*"]:
            problems.append("CORS_ORIGINS must not be '*' in production.")

        if self.seed_demo_accounts:
            published = {
                "DEMO_ANALYST_PASSWORD": "AnalystDemo_2026!",
                "DEMO_RESPONDER_PASSWORD": "ResponderDemo_2026!",
                "DEMO_VIEWER_PASSWORD": "ViewerDemo_2026!",
            }
            still_default = [name for name, default in published.items() if getattr(self, name) == default]
            if still_default:
                problems.append(
                    "SEED_DEMO_ACCOUNTS is enabled but these still use passwords published "
                    f"in the README: {', '.join(sorted(still_default))}. Set them to strong "
                    "values, or leave SEED_DEMO_ACCOUNTS unset to skip the demo logins."
                )

        if problems:
            raise ValueError(
                "Refusing to start in production with insecure defaults:\n  - " + "\n  - ".join(problems)
            )
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sqlalchemy_uri(self) -> str:
        """Async SQLAlchemy URI: explicit DATABASE_URL > Postgres > local SQLite."""
        if self.DATABASE_URL:
            url = self.DATABASE_URL
            if url.startswith("postgresql://"):
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
            elif url.startswith("sqlite://") and "+aiosqlite" not in url:
                url = url.replace("sqlite://", "sqlite+aiosqlite://", 1)
            return url
        if self.POSTGRES_HOST:
            return (
                f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        return f"sqlite+aiosqlite:///{self.SQLITE_PATH}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sync_sqlalchemy_uri(self) -> str:
        """Blocking URI used by Alembic."""
        return self.sqlalchemy_uri.replace("+asyncpg", "+psycopg2" if False else "").replace("+aiosqlite", "")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_sqlite(self) -> bool:
        return self.sqlalchemy_uri.startswith("sqlite")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seed_demo_accounts(self) -> bool:
        """Whether to create the analyst/responder/viewer logins.

        Defaults to on everywhere except production, where publishing working
        credentials for a containment-capable role would be indefensible.
        """
        if self.SEED_DEMO_ACCOUNTS is not None:
            return self.SEED_DEMO_ACCOUNTS
        return not self.is_production

    @computed_field  # type: ignore[prop-decorator]
    @property
    def docs_url(self) -> str | None:
        return None if self.is_production else "/docs"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
