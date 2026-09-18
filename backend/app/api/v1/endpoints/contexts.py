"""Business-context records — the authorisation registry that damps false positives."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession, Pagination, RequireAnalyst
from app.core.enums import ContextType
from app.core.exceptions import NotFoundError, ValidationError
from app.db.base import utcnow
from app.db.models import ContextRecord, Identity
from app.schemas.common import Message, Page
from app.schemas.domain import ContextCreate, ContextRead, ContextUpdate
from app.services import audit
from app.services.detection import detection_service
from app.utils.query import apply_sort, paginate

router = APIRouter()


@router.get("", response_model=Page[ContextRead], summary="Authorisation registry")
async def list_contexts(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    identity_id: str | None = None,
    context_type: ContextType | None = None,
    active_only: bool = False,
    currently_valid: bool = False,
) -> Page[ContextRead]:
    stmt = select(ContextRecord)
    if identity_id:
        stmt = stmt.where(ContextRecord.identity_id == identity_id)
    if context_type:
        stmt = stmt.where(ContextRecord.context_type == context_type)
    if active_only:
        stmt = stmt.where(ContextRecord.is_active.is_(True))
    if currently_valid:
        now = utcnow()
        stmt = stmt.where(
            ContextRecord.is_active.is_(True),
            ContextRecord.valid_from <= now,
            ContextRecord.valid_until >= now,
        )
    stmt = apply_sort(stmt, ContextRecord, params, "created_at")
    return await paginate(db, stmt, params, ContextRead.model_validate)


@router.post(
    "",
    response_model=ContextRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register an authorisation",
    description=(
        "Records an approved business reason that damps risk inside its validity window. "
        "Damping is bounded — it can never fully silence a signal, and evidence-destroying "
        "actions bypass it entirely."
    ),
)
async def create_context(payload: ContextCreate, user: RequireAnalyst, db: DbSession) -> ContextRecord:
    identity = (
        await db.execute(select(Identity).where(Identity.id == payload.identity_id))
    ).scalar_one_or_none()
    if identity is None:
        raise NotFoundError(f"No identity with id '{payload.identity_id}'.")

    valid_from = payload.valid_from or utcnow() - timedelta(hours=1)
    valid_until = payload.valid_until or valid_from + timedelta(days=payload.valid_days)
    if valid_until <= valid_from:
        raise ValidationError("'valid_until' must be later than 'valid_from'.")

    record = ContextRecord(
        identity_id=identity.id,
        context_type=payload.context_type,
        title=payload.title,
        description=payload.description,
        ticket_reference=payload.ticket_reference,
        source_system=payload.source_system,
        valid_from=valid_from,
        valid_until=valid_until,
        damping_factor=payload.damping_factor,
        target_resources=payload.target_resources,
        allowed_actions=payload.allowed_actions,
        approved_by=payload.approved_by,
        created_by_id=user.id,
    )
    db.add(record)
    await db.flush()

    # Re-score immediately so the analyst sees the effect of what they just approved.
    await detection_service.score_identity(db, identity)

    await audit.record(
        db,
        action="context.created",
        target_type="context",
        target_id=record.id,
        actor=user,
        payload={
            "identity": identity.username,
            "ticket": payload.ticket_reference,
            "damping_factor": payload.damping_factor,
        },
    )
    return record


@router.get("/{context_id}", response_model=ContextRead, summary="Fetch one context")
async def get_context(context_id: str, db: DbSession, _: CurrentUser) -> ContextRecord:
    return await _resolve(db, context_id)


@router.patch("/{context_id}", response_model=ContextRead, summary="Amend a context")
async def update_context(
    context_id: str, payload: ContextUpdate, user: RequireAnalyst, db: DbSession
) -> ContextRecord:
    record = await _resolve(db, context_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(record, field, value)

    identity = (
        await db.execute(select(Identity).where(Identity.id == record.identity_id))
    ).scalar_one_or_none()
    if identity:
        await detection_service.score_identity(db, identity)

    await audit.record(
        db,
        action="context.updated",
        target_type="context",
        target_id=record.id,
        actor=user,
        payload=changes,
    )
    return record


@router.delete("/{context_id}", response_model=Message, summary="Revoke a context")
async def revoke_context(context_id: str, user: RequireAnalyst, db: DbSession) -> Message:
    record = await _resolve(db, context_id)
    record.is_active = False

    identity = (
        await db.execute(select(Identity).where(Identity.id == record.identity_id))
    ).scalar_one_or_none()
    if identity:
        await detection_service.score_identity(db, identity)

    await audit.record(db, action="context.revoked", target_type="context", target_id=record.id, actor=user)
    return Message(
        message="Context revoked.",
        detail="The affected identity has been re-scored without its damping.",
    )


async def _resolve(db, context_id: str) -> ContextRecord:
    record = (
        await db.execute(select(ContextRecord).where(ContextRecord.id == context_id))
    ).scalar_one_or_none()
    if record is None:
        raise NotFoundError(f"No context record with id '{context_id}'.")
    return record
