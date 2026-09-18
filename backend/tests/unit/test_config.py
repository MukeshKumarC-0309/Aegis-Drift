"""Configuration loading.

These guard the deployment paths the README documents. A settings bug does not
fail a unit test somewhere subtle — it stops the process from booting at all.
"""

from __future__ import annotations

import pathlib

import pytest
from pydantic import ValidationError

from app.core.config import Settings

pytestmark = pytest.mark.unit

BASE = {"SECRET_KEY": "a-secret-key-that-is-comfortably-long-enough"}


class TestCsvLists:
    """Regression: `.env.example` and docker-compose both write `KEY=a,b,c`.

    pydantic-settings JSON-decodes complex types from the environment before
    validation, so without `NoDecode` this raised a JSON parse error and the
    application refused to start — breaking both `make env` and `make up`.
    """

    def test_comma_separated_origins_parse(self):
        settings = Settings(**BASE, CORS_ORIGINS="http://localhost:5173,http://localhost:8000")
        assert settings.CORS_ORIGINS == ["http://localhost:5173", "http://localhost:8000"]

    def test_whitespace_is_trimmed(self):
        settings = Settings(**BASE, CORS_ORIGINS="http://a.test , http://b.test")
        assert settings.CORS_ORIGINS == ["http://a.test", "http://b.test"]

    def test_single_value_parses(self):
        assert Settings(**BASE, TRUSTED_HOSTS="example.com").TRUSTED_HOSTS == ["example.com"]

    def test_json_array_form_still_works(self):
        settings = Settings(**BASE, CORS_ORIGINS='["http://a.test","http://b.test"]')
        assert settings.CORS_ORIGINS == ["http://a.test", "http://b.test"]

    def test_native_list_still_works(self):
        assert Settings(**BASE, TRUSTED_HOSTS=["a", "b"]).TRUSTED_HOSTS == ["a", "b"]

    def test_empty_entries_are_dropped(self):
        assert Settings(**BASE, TRUSTED_HOSTS="a,,b,").TRUSTED_HOSTS == ["a", "b"]


class TestSecretKey:
    def test_short_key_is_rejected(self):
        with pytest.raises(ValidationError, match="at least 32 characters"):
            Settings(SECRET_KEY="too-short")

    def test_a_key_is_generated_when_unset(self):
        """Development convenience — but it means a restart invalidates tokens,
        which is why every deployment path sets one explicitly."""
        assert len(Settings().SECRET_KEY) >= 32


class TestProductionGuard:
    """Local convenience must never silently become a production credential.

    The dev key is cached in a predictable, git-ignored file so developers stay
    logged in across restarts. That is exactly why production has to say its
    secret out loud.
    """

    def test_production_rejects_the_cached_dev_key(self, monkeypatch, tmp_path):
        from app.core import config as config_module

        cache = tmp_path / "dev-secret.key"
        cache.write_text("x" * 60)
        monkeypatch.setattr(config_module, "_SECRET_CACHE", cache)

        with pytest.raises(ValidationError, match="auto-generated development key"):
            Settings(
                SECRET_KEY="x" * 60,
                ENVIRONMENT="production",
                FIRST_SUPERUSER_PASSWORD="A-Real-Password-123!",
                CORS_ORIGINS="https://soc.example.com",
            )

    def test_production_rejects_the_default_superuser_password(self):
        with pytest.raises(ValidationError, match="FIRST_SUPERUSER_PASSWORD"):
            Settings(
                SECRET_KEY="a-genuinely-distinct-production-secret-value",
                ENVIRONMENT="production",
                CORS_ORIGINS="https://soc.example.com",
            )

    def test_production_rejects_wildcard_cors(self):
        with pytest.raises(ValidationError, match="CORS_ORIGINS"):
            Settings(
                SECRET_KEY="a-genuinely-distinct-production-secret-value",
                ENVIRONMENT="production",
                FIRST_SUPERUSER_PASSWORD="A-Real-Password-123!",
                CORS_ORIGINS="*",
            )

    def test_properly_configured_production_starts(self):
        settings = Settings(
            SECRET_KEY="a-genuinely-distinct-production-secret-value",
            ENVIRONMENT="production",
            FIRST_SUPERUSER_PASSWORD="A-Real-Password-123!",
            CORS_ORIGINS="https://soc.example.com",
        )
        assert settings.is_production is True

    def test_non_production_tolerates_every_default(self):
        """The whole point of `./start.sh`: no configuration required to run."""
        settings = Settings(_env_file=None, ENVIRONMENT="local")
        assert settings.is_production is False
        assert len(settings.SECRET_KEY) >= 32
        assert settings.FIRST_SUPERUSER_PASSWORD  # the documented default is fine here


class TestDemoAccountGating:
    """The analyst/responder/viewer logins have passwords published in the README.

    The responder role can quarantine identities and execute containment playbooks,
    so shipping those credentials on a public deployment would hand a stranger real
    authority. They are off by default in production and refused if enabled with the
    published values.
    """

    def test_demo_logins_are_skipped_in_production_by_default(self):
        assert Settings(**PRODUCTION).seed_demo_accounts is False

    def test_demo_logins_are_on_outside_production(self):
        assert Settings(_env_file=None, ENVIRONMENT="local").seed_demo_accounts is True

    def test_enabling_them_with_published_passwords_is_refused(self):
        with pytest.raises(ValidationError, match="published"):
            Settings(**PRODUCTION, SEED_DEMO_ACCOUNTS=True)

    def test_each_published_password_is_named_in_the_error(self):
        with pytest.raises(ValidationError) as exc:
            Settings(**PRODUCTION, SEED_DEMO_ACCOUNTS=True)
        message = str(exc.value)
        for field in ("DEMO_ANALYST_PASSWORD", "DEMO_RESPONDER_PASSWORD", "DEMO_VIEWER_PASSWORD"):
            assert field in message

    def test_enabling_them_with_strong_passwords_is_allowed(self):
        settings = Settings(
            **PRODUCTION,
            SEED_DEMO_ACCOUNTS=True,
            DEMO_ANALYST_PASSWORD="Str0ng-Analyst-Pw!",
            DEMO_RESPONDER_PASSWORD="Str0ng-Responder-Pw!",
            DEMO_VIEWER_PASSWORD="Str0ng-Viewer-Pw!",
        )
        assert settings.seed_demo_accounts is True

    def test_explicitly_disabling_them_is_honoured_locally(self):
        settings = Settings(_env_file=None, ENVIRONMENT="local", SEED_DEMO_ACCOUNTS=False)
        assert settings.seed_demo_accounts is False


class TestSecretPersistence:
    def test_the_key_is_reused_once_cached(self, monkeypatch, tmp_path):
        """Regression: a fresh key per boot signed the developer out on every restart."""
        from app.core import config as config_module

        cache = tmp_path / "nested" / "dev-secret.key"
        monkeypatch.setattr(config_module, "_SECRET_CACHE", cache)

        first = config_module._local_secret_key()
        second = config_module._local_secret_key()

        assert first == second
        assert cache.read_text().strip() == first
        assert len(first) >= 32

    def test_a_corrupt_cache_is_replaced(self, monkeypatch, tmp_path):
        from app.core import config as config_module

        cache = tmp_path / "dev-secret.key"
        cache.write_text("too-short")
        monkeypatch.setattr(config_module, "_SECRET_CACHE", cache)

        regenerated = config_module._local_secret_key()
        assert len(regenerated) >= 32
        assert regenerated != "too-short"

    def test_an_unwritable_location_still_yields_a_key(self, monkeypatch):
        """A read-only container filesystem must not stop the process from booting."""
        from app.core import config as config_module

        monkeypatch.setattr(config_module, "_SECRET_CACHE", pathlib.Path("/proc/nonexistent/dev-secret.key"))
        assert len(config_module._local_secret_key()) >= 32


class TestDatabaseUrl:
    def test_falls_back_to_sqlite(self):
        settings = Settings(**BASE, SQLITE_PATH="./test.db")
        assert settings.sqlalchemy_uri.startswith("sqlite+aiosqlite://")
        assert settings.is_sqlite is True

    def test_postgres_parts_build_an_async_uri(self):
        settings = Settings(
            **BASE,
            POSTGRES_HOST="db.internal",
            POSTGRES_USER="ss",
            POSTGRES_PASSWORD="pw",
            POSTGRES_DB="aegisdrift",
        )
        assert settings.sqlalchemy_uri == "postgresql+asyncpg://ss:pw@db.internal:5432/aegisdrift"
        assert settings.is_sqlite is False

    def test_explicit_url_wins_and_is_upgraded_to_async(self):
        settings = Settings(
            **BASE,
            POSTGRES_HOST="ignored.internal",
            DATABASE_URL="postgresql://u:p@other:5432/db",
        )
        assert settings.sqlalchemy_uri == "postgresql+asyncpg://u:p@other:5432/db"

    def test_sqlite_url_is_upgraded_to_async(self):
        settings = Settings(**BASE, DATABASE_URL="sqlite:///./local.db")
        assert settings.sqlalchemy_uri == "sqlite+aiosqlite:///./local.db"


PRODUCTION = {
    "SECRET_KEY": "a-genuinely-distinct-production-secret-value",
    "ENVIRONMENT": "production",
    "FIRST_SUPERUSER_PASSWORD": "A-Real-Password-123!",
    "CORS_ORIGINS": "https://soc.example.com",
}


class TestEnvironment:
    def test_production_hides_the_docs(self):
        """Not decoration: the schema describes every endpoint and its payloads."""
        settings = Settings(**PRODUCTION)
        assert settings.docs_url is None
        assert settings.is_production is True

    def test_local_exposes_the_docs(self):
        assert Settings(**BASE, ENVIRONMENT="local").docs_url == "/docs"
