"""Monitored identities: the estate view and per-identity investigation."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, status
from sqlalchemy import or_, select

from app.api.deps import CurrentUser, DbSession, Pagination, RequireAnalyst
from app.core.enums import TransitionState
from app.core.exceptions import ConflictError, NotFoundError
from app.db.models import Identity
from app.engine.peer import cohort_key
from app.schemas.analytics import CopilotRequest, CopilotResponse, InvestigationResponse
from app.schemas.common import Message, Page
from app.schemas.domain import BaselineRead, IdentityCreate, IdentityRead, IdentityUpdate
from app.services import audit
from app.services.detection import detection_service
from app.services.investigation import investigation_service
from app.utils.query import apply_sort, paginate

router = APIRouter()


@router.get("", response_model=Page[IdentityRead], summary="List monitored identities")
async def list_identities(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    search: Annotated[str | None, Query(description="Match username, name, email or role.")] = None,
    department: str | None = None,
    state: TransitionState | None = None,
    min_risk: Annotated[float | None, Query(ge=0, le=100)] = None,
    privileged_only: bool = False,
    watchlist_only: bool = False,
    include_inactive: bool = False,
) -> Page[IdentityRead]:
    stmt = select(Identity)

    if not include_inactive:
        stmt = stmt.where(Identity.is_active.is_(True))
    if search:
        pattern = f"%{search.lower()}%"
        stmt = stmt.where(
            or_(
                Identity.username.ilike(pattern),
                Identity.display_name.ilike(pattern),
                Identity.email.ilike(pattern),
                Identity.role_title.ilike(pattern),
            )
        )
    if department:
        stmt = stmt.where(Identity.department == department)
    if state:
        stmt = stmt.where(Identity.transition_state == state)
    if min_risk is not None:
        stmt = stmt.where(Identity.risk_score >= min_risk)
    if privileged_only:
        stmt = stmt.where(Identity.is_privileged.is_(True))
    if watchlist_only:
        stmt = stmt.where(Identity.on_watchlist.is_(True))

    stmt = apply_sort(stmt, Identity, params, "risk_score")
    return await paginate(db, stmt, params, IdentityRead.model_validate)


@router.get("/departments", response_model=list[str], summary="Distinct departments")
async def list_departments(db: DbSession, _: CurrentUser) -> list[str]:
    rows = (await db.execute(select(Identity.department).distinct())).scalars().all()
    return sorted(rows)


@router.post(
    "",
    response_model=IdentityRead,
    status_code=status.HTTP_201_CREATED,
    summary="Onboard an identity",
)
async def create_identity(payload: IdentityCreate, user: RequireAnalyst, db: DbSession) -> Identity:
    exists = (
        await db.execute(select(Identity.id).where(Identity.username == payload.username))
    ).scalar_one_or_none()
    if exists:
        raise ConflictError(f"Identity '{payload.username}' is already monitored.")

    identity = Identity(
        **payload.model_dump(),
        peer_group_id=cohort_key(payload.department, payload.role_title),
    )
    db.add(identity)
    await db.flush()
    await audit.record(
        db,
        action="identity.created",
        target_type="identity",
        target_id=identity.id,
        actor=user,
        payload={"username": identity.username},
    )
    return identity


@router.get("/{identity_id}", response_model=IdentityRead, summary="Fetch one identity")
async def get_identity(identity_id: str, db: DbSession, _: CurrentUser) -> Identity:
    return await _resolve(db, identity_id)


@router.patch("/{identity_id}", response_model=IdentityRead, summary="Update an identity")
async def update_identity(
    identity_id: str, payload: IdentityUpdate, user: RequireAnalyst, db: DbSession
) -> Identity:
    identity = await _resolve(db, identity_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(identity, field, value)
    if "department" in changes or "role_title" in changes:
        identity.peer_group_id = cohort_key(identity.department, identity.role_title)
    await audit.record(
        db,
        action="identity.updated",
        target_type="identity",
        target_id=identity.id,
        actor=user,
        payload=changes,
    )
    return identity


@router.get(
    "/{identity_id}/investigation",
    response_model=InvestigationResponse,
    summary="Full investigation payload",
    description=(
        "Everything the Investigator Workbench needs in one round trip: scored timeline, "
        "explainability brief, blast radius, baseline comparison, contexts, alerts and "
        "response history."
    ),
)
async def investigate(identity_id: str, db: DbSession, _: CurrentUser) -> dict:
    return await investigation_service.build(db, identity_id)


@router.get("/{identity_id}/baseline", response_model=BaselineRead, summary="Learned baseline")
async def get_baseline(identity_id: str, db: DbSession, _: CurrentUser):
    identity = await _resolve(db, identity_id)
    baseline = await detection_service._get_baseline_row(db, identity.id)
    if baseline is None:
        raise NotFoundError(f"No baseline has been learned for '{identity.username}' yet.")
    return baseline


@router.post(
    "/{identity_id}/baseline/rebuild",
    response_model=BaselineRead,
    summary="Re-learn the baseline",
    description="Folds recent behaviour into the norm. Use after confirming a change is benign.",
)
async def rebuild_baseline(identity_id: str, user: RequireAnalyst, db: DbSession):
    identity = await _resolve(db, identity_id)
    baseline = await detection_service.rebuild_baseline(db, identity)
    await detection_service.score_identity(db, identity)
    await audit.record(
        db,
        action="identity.rebaselined",
        target_type="identity",
        target_id=identity.id,
        actor=user,
    )
    return baseline


@router.post("/{identity_id}/rescore", response_model=IdentityRead, summary="Force a re-score")
async def rescore(identity_id: str, user: RequireAnalyst, db: DbSession) -> Identity:
    identity = await _resolve(db, identity_id)
    await detection_service.score_identity(db, identity, persist=True, snapshot=True)
    return identity


@router.post(
    "/{identity_id}/copilot",
    response_model=CopilotResponse,
    summary="Ask the SOC Copilot",
    description=(
        "Answers investigation questions strictly from computed evidence. The copilot "
        "declines rather than speculating when a question falls outside what it can ground."
    ),
)
async def copilot(
    identity_id: str, payload: CopilotRequest, db: DbSession, user: CurrentUser
) -> CopilotResponse:
    from datetime import datetime

    answer = await investigation_service.copilot(db, identity_id, payload.question)
    return CopilotResponse(
        **answer,
        identity_id=identity_id,
        conversation_id=payload.conversation_id,
        answered_at=datetime.utcnow(),
    )


@router.delete("/{identity_id}", response_model=Message, summary="Offboard an identity")
async def offboard(identity_id: str, user: RequireAnalyst, db: DbSession) -> Message:
    identity = await _resolve(db, identity_id)
    identity.is_active = False
    await audit.record(
        db, action="identity.offboarded", target_type="identity", target_id=identity.id, actor=user
    )
    return Message(
        message=f"'{identity.username}' offboarded.",
        detail="Historical telemetry is retained for forensic and audit purposes.",
    )


async def _resolve(db, identity_id: str) -> Identity:
    identity = (
        await db.execute(
            select(Identity).where(or_(Identity.id == identity_id, Identity.username == identity_id))
        )
    ).scalar_one_or_none()
    if identity is None:
        raise NotFoundError(f"No identity matches '{identity_id}'.")
    return identity
