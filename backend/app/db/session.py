"""Async engine, session factory and FastAPI dependency."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import Column, MetaData, String, Table
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def _engine_kwargs() -> dict:
    if settings.is_sqlite:
        # SQLite has no meaningful server-side pool; NullPool avoids cross-loop reuse.
        return {"poolclass": NullPool, "connect_args": {"check_same_thread": False}}
    return {
        "pool_size": settings.DB_POOL_SIZE,
        "max_overflow": settings.DB_MAX_OVERFLOW,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }


engine = create_async_engine(
    settings.sqlalchemy_uri,
    echo=settings.DB_ECHO,
    future=True,
    **_engine_kwargs(),
)

SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Request-scoped session; commits on success, rolls back on any exception."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_scope() -> AsyncGenerator[AsyncSession, None]:
    """Session for background workers and CLI scripts."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_models() -> None:
    """Create tables directly for local, dev and test bootstrapping.

    Alembic owns the schema in production — the container entrypoint runs
    ``alembic upgrade head`` before the server starts. This path exists so that
    ``git clone && make dev`` works without a migration step, and it stamps the
    Alembic version table afterwards so the two mechanisms agree and
    ``alembic check`` stays meaningful on a development database.
    """
    from app.db import models  # noqa: F401  (import registers every mapper)
    from app.db.base import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_stamp_alembic_head)

    logger.info("database.schema_ready", dialect=engine.dialect.name)


def _stamp_alembic_head(connection) -> None:
    """Record the current head revision if the version table is empty.

    Without this, a database created by ``create_all`` has no Alembic version,
    so a later ``alembic upgrade`` would try to re-create existing tables.
    """
    from alembic.migration import MigrationContext
    from alembic.script import ScriptDirectory

    from app.db.base import Base

    try:
        script = ScriptDirectory(str(Path(__file__).resolve().parents[2] / "alembic"))
        head = script.get_current_head()
    except Exception as exc:  # pragma: no cover - only when alembic/ is absent
        logger.debug("database.stamp_skipped", reason=str(exc))
        return

    if head is None:
        return

    context = MigrationContext.configure(connection)
    if context.get_current_revision() is not None:
        return

    version_table = Table(
        "alembic_version",
        Base.metadata if "alembic_version" not in Base.metadata.tables else MetaData(),
        Column("version_num", String(32), primary_key=True),
        extend_existing=True,
    )
    version_table.create(connection, checkfirst=True)
    connection.execute(version_table.insert().values(version_num=head))
    logger.info("database.stamped", revision=head)


async def dispose_engine() -> None:
    await engine.dispose()
