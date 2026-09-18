"""Alembic environment, wired to the application's own settings and metadata."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from app.core.config import settings
from app.db import models  # noqa: F401  (registers every mapper)
from app.db.base import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# The application is the single source of truth for both URL and schema.
config.set_main_option("sqlalchemy.url", settings.sqlalchemy_uri)
target_metadata = Base.metadata


def _render_item(type_, obj, autogen_context) -> str | bool:
    """Render our custom column types as their underlying DDL types.

    ``StrEnumType`` carries a Python enum class that exists only to coerce values
    on read. Baking that class into a migration would couple frozen history to
    live application code, so migrations emit the plain VARCHAR the database
    actually sees.
    """
    if type_ != "type":
        return False

    from app.db.types import JSONType, StrEnumType

    if isinstance(obj, StrEnumType):
        autogen_context.imports.add("import sqlalchemy as sa")
        return f"sa.String(length={obj.impl.length})"
    if isinstance(obj, JSONType):
        autogen_context.imports.add("import app.db.types")
        return "app.db.types.JSONType()"
    return False


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        render_item=_render_item,
        # SQLite cannot ALTER most columns; batch mode rewrites the table instead.
        render_as_batch=settings.is_sqlite,
    )


def run_migrations_offline() -> None:
    context.configure(
        url=settings.sqlalchemy_uri,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_item=_render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with engine.connect() as connection:
        await connection.run_sync(lambda sync_conn: _configure(sync_conn) or context.run_migrations())
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
