"""Append-only audit logging for every state-changing operation."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger, request_id_ctx
from app.db.models import AuditLog, User

logger = get_logger(__name__)

#: Never write these through to the audit payload, whatever the caller passes.
REDACTED_KEYS = {"password", "new_password", "current_password", "token", "key", "secret"}


def _scrub(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: ("***redacted***" if k.lower() in REDACTED_KEYS else v) for k, v in payload.items()}


async def record(
    db: AsyncSession,
    *,
    action: str,
    target_type: str,
    target_id: str | None = None,
    actor: User | None = None,
    actor_email: str | None = None,
    outcome: str = "SUCCESS",
    payload: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLog:
    """Write one audit entry. Never raises — auditing must not break the request."""
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_email=actor_email or (actor.email if actor else "system"),
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255] or None,
        request_id=request_id_ctx.get(),
        payload=_scrub(payload or {}),
    )
    db.add(entry)
    logger.info("audit", action=action, target=f"{target_type}:{target_id}", outcome=outcome)
    return entry


async def recent(db: AsyncSession, limit: int = 50) -> list[AuditLog]:
    rows = (
        (await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit))).scalars().all()
    )
    return list(rows)
