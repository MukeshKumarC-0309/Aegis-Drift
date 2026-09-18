"""Query helpers shared by list endpoints."""

from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy import Select, asc, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.common import Page, PageMeta, PageParams

T = TypeVar("T")


def apply_sort(stmt: Select, model: Any, params: PageParams, default_column: str) -> Select:
    """Sort by a whitelisted column, falling back to the caller's default."""
    column_name = params.sort_by or default_column
    column = getattr(model, column_name, None)
    if column is None:
        column = getattr(model, default_column)
    return stmt.order_by(asc(column) if params.sort_dir == "asc" else desc(column))


async def paginate(
    db: AsyncSession,
    stmt: Select,
    params: PageParams,
    serializer,
) -> Page:
    """Run a count query and a windowed query, returning a ``Page`` envelope."""
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = int((await db.execute(count_stmt)).scalar_one())

    rows = (await db.execute(stmt.offset(params.offset).limit(params.page_size))).scalars().all()

    return Page(
        items=[serializer(r) for r in rows],
        meta=PageMeta.build(params.page, params.page_size, total),
    )
