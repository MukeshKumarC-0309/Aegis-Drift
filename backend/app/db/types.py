"""Portable column types that behave the same on SQLite and PostgreSQL."""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator


class JSONType(TypeDecorator):
    """``JSONB`` on PostgreSQL, plain ``JSON`` everywhere else."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class StrEnumType(TypeDecorator):
    """Persist a ``StrEnum`` as VARCHAR and rehydrate it as the enum on read.

    Without this, values come back as bare strings and behaviour that depends on the
    enum (``Role.rank``, identity comparisons with ``is``) silently breaks.
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_class: type, length: int = 32) -> None:
        self.enum_class = enum_class
        super().__init__(length)

    def process_bind_param(self, value: Any, _dialect: Any) -> Any:
        if value is None:
            return None
        return value.value if isinstance(value, self.enum_class) else str(value)

    def process_result_value(self, value: Any, _dialect: Any) -> Any:
        if value is None:
            return None
        try:
            return self.enum_class(value)
        except ValueError:
            # Tolerate rows written by an older schema rather than failing the query.
            return value
