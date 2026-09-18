"""Containment actions and SOAR playbooks."""

from __future__ import annotations

from fastapi import APIRouter, status
from sqlalchemy import or_, select

from app.api.deps import CurrentUser, DbSession, Pagination, RequireResponder
from app.core.exceptions import NotFoundError
from app.db.models import ActionRecord, Identity, Playbook
from app.schemas.common import Page
from app.schemas.domain import ActionRead, ActionRequest, PlaybookRead, PlaybookRunRequest
from app.services.response import response_service
from app.utils.query import apply_sort, paginate

router = APIRouter()


@router.post(
    "/identities/{identity_id}/actions",
    response_model=ActionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Execute a containment action",
    description=(
        "Applies a response action and re-scores the identity. Enforcing actions "
        "(quarantine, disable, revoke) also close the identity's open alerts as confirmed "
        "incidents. Every execution is written to the immutable audit log."
    ),
)
async def execute_action(
    identity_id: str, payload: ActionRequest, user: RequireResponder, db: DbSession
) -> ActionRecord:
    identity = await _resolve_identity(db, identity_id)
    return await response_service.execute(
        db,
        identity,
        payload.action,
        actor=user,
        notes=payload.notes,
        alert_id=payload.alert_id,
        case_id=payload.case_id,
        ticket_reference=payload.ticket_reference,
    )


@router.get("/actions", response_model=Page[ActionRead], summary="Response history")
async def list_actions(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    identity_id: str | None = None,
    case_id: str | None = None,
    automated_only: bool = False,
) -> Page[ActionRead]:
    stmt = select(ActionRecord)
    if identity_id:
        stmt = stmt.where(ActionRecord.identity_id == identity_id)
    if case_id:
        stmt = stmt.where(ActionRecord.case_id == case_id)
    if automated_only:
        stmt = stmt.where(ActionRecord.is_automated.is_(True))
    stmt = apply_sort(stmt, ActionRecord, params, "created_at")
    return await paginate(db, stmt, params, ActionRead.model_validate)


@router.get("/playbooks", response_model=list[PlaybookRead], summary="List playbooks")
async def list_playbooks(db: DbSession, _: CurrentUser, enabled_only: bool = False):
    stmt = select(Playbook).order_by(Playbook.name)
    if enabled_only:
        stmt = stmt.where(Playbook.enabled.is_(True))
    return list((await db.execute(stmt)).scalars().all())


@router.post(
    "/playbooks/{slug}/run",
    summary="Run a playbook",
    description=(
        "Defaults to a dry run that returns the plan without enforcing anything. Pass "
        "`dry_run: false` to execute — which requires the responder role."
    ),
)
async def run_playbook(slug: str, payload: PlaybookRunRequest, user: RequireResponder, db: DbSession) -> dict:
    playbook = (
        await db.execute(select(Playbook).where(or_(Playbook.slug == slug, Playbook.id == slug)))
    ).scalar_one_or_none()
    if playbook is None:
        raise NotFoundError(f"No playbook matches '{slug}'.")
    if not playbook.enabled:
        raise NotFoundError(f"Playbook '{playbook.slug}' is disabled.")

    identity = await _resolve_identity(db, payload.identity_id)
    return await response_service.run_playbook(
        db,
        playbook,
        identity,
        actor=user,
        case_id=payload.case_id,
        dry_run=payload.dry_run,
        notes=payload.notes,
    )


async def _resolve_identity(db, identity_id: str) -> Identity:
    identity = (
        await db.execute(
            select(Identity).where(or_(Identity.id == identity_id, Identity.username == identity_id))
        )
    ).scalar_one_or_none()
    if identity is None:
        raise NotFoundError(f"No identity matches '{identity_id}'.")
    return identity
