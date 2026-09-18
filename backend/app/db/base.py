"""Declarative base plus column conventions shared by every table."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, String, event, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Explicit naming convention keeps Alembic autogenerate deterministic.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def to_dict(self, exclude: set[str] | None = None) -> dict[str, Any]:
        skip = exclude or set()
        return {c.name: getattr(self, c.name) for c in self.__table__.columns if c.name not in skip}


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, server_default=func.now(), nullable=False
    )


class IDMixin:
    """String primary keys prefixed by entity type — readable in logs and URLs."""

    __id_prefix__ = "obj"

    id: Mapped[str] = mapped_column(String(48), primary_key=True)


@event.listens_for(Base, "init", propagate=True)
def _assign_defaults(target: Any, _args: Any, kwargs: Any) -> None:
    """Materialise prefixed primary keys and Python-side column defaults eagerly.

    SQLAlchemy normally applies defaults at flush time, which means freshly
    constructed objects expose ``None`` for columns that have one. Reading such a
    column before the flush (``row.version += 1``) then fails. Applying them here
    makes a new instance behave like a fully initialised object straight away.
    """
    if isinstance(target, IDMixin) and not kwargs.get("id"):
        kwargs["id"] = new_id(type(target).__id_prefix__)

    for column in target.__table__.columns:
        name = column.name
        if name in kwargs or column.default is None:
            continue
        default = column.default
        if default.is_callable:
            # Zero-argument factories (dict, list, utcnow) — skip context-aware ones.
            try:
                kwargs[name] = default.arg(None)
            except TypeError:
                continue
        elif default.is_scalar:
            kwargs[name] = default.arg

    if "created_at" in target.__table__.columns and not kwargs.get("created_at"):
        kwargs["created_at"] = utcnow()
