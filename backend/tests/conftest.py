"""Shared pytest fixtures.

Each test gets an isolated in-memory SQLite database and an httpx client bound to
the app, so the suite exercises the real routing, dependency and serialisation
stack rather than calling service functions directly.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import pytest

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("AUTO_SEED", "false")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-definitely-long-enough-32")
os.environ.setdefault("LOG_LEVEL", "WARNING")

from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.core.security import Role, hash_password
from app.db.base import Base
from app.db.models import Identity, User
from app.engine.peer import cohort_key
from app.main import app

TEST_PASSWORD = "TestPassw0rd!Secure"


@pytest.fixture
async def engine():
    """In-memory SQLite shared across connections for the test's lifetime."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def session_factory(engine):
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def db(session_factory) -> AsyncGenerator[AsyncSession, None]:
    async with session_factory() as session:
        yield session
        await session.commit()


@pytest.fixture
async def client(session_factory) -> AsyncGenerator[AsyncClient, None]:
    """App-bound client with the database dependency overridden.

    The lifespan is deliberately not run: it would start the scheduler and seed
    the full estate, which no unit or integration test wants.
    """

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as async_client:
        yield async_client
    app.dependency_overrides.clear()


@pytest.fixture
async def admin_user(db: AsyncSession) -> User:
    user = User(
        email="admin@example.com",
        full_name="Test Admin",
        hashed_password=hash_password(TEST_PASSWORD),
        role=Role.ADMIN,
    )
    db.add(user)
    await db.commit()
    return user


@pytest.fixture
async def viewer_user(db: AsyncSession) -> User:
    user = User(
        email="viewer@example.com",
        full_name="Test Viewer",
        hashed_password=hash_password(TEST_PASSWORD),
        role=Role.VIEWER,
    )
    db.add(user)
    await db.commit()
    return user


async def _token_for(client: AsyncClient, email: str) -> str:
    response = await client.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture
async def admin_headers(client: AsyncClient, admin_user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {await _token_for(client, admin_user.email)}"}


@pytest.fixture
async def viewer_headers(client: AsyncClient, viewer_user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {await _token_for(client, viewer_user.email)}"}


@pytest.fixture
async def identity(db: AsyncSession) -> Identity:
    row = Identity(
        username="test.user",
        display_name="Test User",
        email="test.user@example.com",
        department="Engineering",
        role_title="Software Engineer",
        peer_group_id=cohort_key("Engineering", "Software Engineer"),
    )
    db.add(row)
    await db.commit()
    return row
