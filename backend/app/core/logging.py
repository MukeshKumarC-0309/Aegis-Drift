"""Structured logging with request-scoped correlation IDs."""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog

from app.core.config import settings

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
actor_ctx: ContextVar[str | None] = ContextVar("actor", default=None)


def _inject_context(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    if rid := request_id_ctx.get():
        event_dict["request_id"] = rid
    if actor := actor_ctx.get():
        event_dict["actor"] = actor
    return event_dict


def configure_logging() -> None:
    """Route stdlib logging through structlog and pick a renderer for the env."""
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _inject_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    renderer = (
        structlog.processors.JSONRenderer()
        if settings.LOG_FORMAT == "json"
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[settings.LOG_LEVEL]
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.getLevelNamesMapping()[settings.LOG_LEVEL],
        force=True,
    )
    # uvicorn duplicates access logs that our middleware already emits
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("uvicorn.error").propagate = False


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound logger tagged with its module name.

    ``add_logger_name`` is not used because the PrintLogger factory has no ``.name``;
    binding it explicitly here gives the same field without that coupling.
    """
    logger = structlog.get_logger()
    return logger.bind(logger=name) if name else logger  # type: ignore[return-value]
