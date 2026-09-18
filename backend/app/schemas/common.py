"""Shared response envelopes, pagination and filtering primitives."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    """Base for schemas read directly from SQLAlchemy rows."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class PageParams(BaseModel):
    """Query parameters for offset pagination."""

    page: Annotated[int, Field(ge=1)] = 1
    page_size: Annotated[int, Field(ge=1, le=200)] = 25
    sort_by: str | None = None
    sort_dir: Literal["asc", "desc"] = "desc"

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class PageMeta(BaseModel):
    page: int
    page_size: int
    total: int
    total_pages: int
    has_next: bool
    has_previous: bool

    @classmethod
    def build(cls, page: int, page_size: int, total: int) -> PageMeta:
        total_pages = max(1, -(-total // page_size))  # ceil division
        return cls(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_previous=page > 1,
        )


class Page(BaseModel, Generic[T]):
    """A paginated collection response."""

    items: list[T]
    meta: PageMeta


class Message(BaseModel):
    """Simple acknowledgement payload."""

    message: str
    detail: str | None = None


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class HealthStatus(BaseModel):
    status: Literal["healthy", "degraded", "unhealthy"]
    version: str
    environment: str
    uptime_seconds: float
    checks: dict[str, str]
    timestamp: datetime
