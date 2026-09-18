"""Case management: investigations, timelines and SLA tracking."""

from __future__ import annotations

from fastapi import APIRouter, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession, Pagination, RequireAnalyst
from app.core.enums import CasePriority, CaseStatus, Severity
from app.db.base import utcnow
from app.db.models import Case, CaseEntry
from app.schemas.common import Page
from app.schemas.domain import (
    CaseCreate,
    CaseDetail,
    CaseEntryCreate,
    CaseEntryRead,
    CaseRead,
    CaseUpdate,
)
from app.services import audit
from app.services.response import response_service
from app.utils.query import apply_sort, paginate

router = APIRouter()


@router.get("", response_model=Page[CaseRead], summary="List cases")
async def list_cases(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    status_filter: CaseStatus | None = None,
    priority: CasePriority | None = None,
    severity: Severity | None = None,
    assignee_id: str | None = None,
    mine: bool = False,
    open_only: bool = False,
    overdue: bool = False,
    user: CurrentUser = None,  # type: ignore[assignment]
) -> Page[CaseRead]:
    stmt = select(Case)
    if status_filter:
        stmt = stmt.where(Case.status == status_filter)
    if open_only:
        stmt = stmt.where(Case.status.notin_([CaseStatus.CLOSED, CaseStatus.RESOLVED]))
    if priority:
        stmt = stmt.where(Case.priority == priority)
    if severity:
        stmt = stmt.where(Case.severity == severity)
    if assignee_id:
        stmt = stmt.where(Case.assignee_id == assignee_id)
    if mine and user:
        stmt = stmt.where(Case.assignee_id == user.id)
    if overdue:
        stmt = stmt.where(
            Case.sla_due_at < utcnow(),
            Case.status.notin_([CaseStatus.CLOSED, CaseStatus.RESOLVED]),
        )
    stmt = apply_sort(stmt, Case, params, "created_at")
    return await paginate(db, stmt, params, CaseRead.model_validate)


@router.get("/stats", summary="Case board counters")
async def case_stats(db: DbSession, _: CurrentUser) -> dict:
    cases = (await db.execute(select(Case))).scalars().all()
    now = utcnow()
    open_cases = [c for c in cases if c.status not in {CaseStatus.CLOSED, CaseStatus.RESOLVED}]
    by_status: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    for case in cases:
        by_status[str(case.status)] = by_status.get(str(case.status), 0) + 1
        by_priority[str(case.priority)] = by_priority.get(str(case.priority), 0) + 1
    return {
        "total": len(cases),
        "open": len(open_cases),
        "overdue": sum(1 for c in open_cases if c.sla_due_at and c.sla_due_at < now),
        "unassigned": sum(1 for c in open_cases if c.assignee_id is None),
        "by_status": by_status,
        "by_priority": by_priority,
    }


@router.post("", response_model=CaseDetail, status_code=status.HTTP_201_CREATED, summary="Open a case")
async def create_case(payload: CaseCreate, user: RequireAnalyst, db: DbSession) -> Case:
    case = await response_service.create_case(
        db,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        severity=payload.severity,
        primary_identity_id=payload.primary_identity_id,
        assignee_id=payload.assignee_id or user.id,
        alert_ids=payload.alert_ids,
        tags=payload.tags,
        actor=user,
    )
    await db.flush()
    await db.refresh(case)
    return case


@router.get("/{case_id}", response_model=CaseDetail, summary="Fetch a case with its timeline")
async def get_case(case_id: str, db: DbSession, _: CurrentUser) -> Case:
    return await response_service.get_case(db, case_id)


@router.patch("/{case_id}", response_model=CaseDetail, summary="Update a case")
async def update_case(case_id: str, payload: CaseUpdate, user: RequireAnalyst, db: DbSession) -> Case:
    case = await response_service.get_case(db, case_id)
    changes = payload.model_dump(exclude_unset=True)

    if payload.status is not None and payload.status != case.status:
        await response_service.transition_case(db, case, payload.status, actor=user)
        changes.pop("status", None)

    for field, value in changes.items():
        setattr(case, field, value)

    await audit.record(
        db, action="case.updated", target_type="case", target_id=case.id, actor=user, payload=changes
    )
    await db.flush()
    await db.refresh(case)
    return case


@router.post(
    "/{case_id}/entries",
    response_model=CaseEntryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add a timeline entry",
)
async def add_entry(case_id: str, payload: CaseEntryCreate, user: RequireAnalyst, db: DbSession) -> CaseEntry:
    case = await response_service.get_case(db, case_id)
    entry = CaseEntry(
        case_id=case.id,
        entry_type=payload.entry_type,
        author_id=user.id,
        author_label=user.email,
        body=payload.body,
    )
    db.add(entry)
    await db.flush()
    return entry


@router.get("/{case_id}/entries", response_model=list[CaseEntryRead], summary="Case timeline")
async def list_entries(case_id: str, db: DbSession, _: CurrentUser) -> list[CaseEntry]:
    case = await response_service.get_case(db, case_id)
    rows = (
        (
            await db.execute(
                select(CaseEntry).where(CaseEntry.case_id == case.id).order_by(CaseEntry.created_at)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)
