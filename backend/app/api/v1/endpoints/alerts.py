"""Alert triage queue."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession, Pagination, RequireAnalyst
from app.core.enums import AlertStatus, Severity, TransitionState
from app.core.exceptions import NotFoundError
from app.db.base import utcnow
from app.db.models import Alert, Identity
from app.schemas.common import Message, Page
from app.schemas.domain import AlertRead, AlertUpdate, AlertWithIdentity
from app.services import audit
from app.utils.query import apply_sort, paginate

router = APIRouter()

OPEN_STATUSES = (AlertStatus.OPEN, AlertStatus.TRIAGED, AlertStatus.INVESTIGATING)


@router.get("", response_model=Page[AlertWithIdentity], summary="Triage queue")
async def list_alerts(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    state: TransitionState | None = None,
    department: str | None = None,
    min_risk: Annotated[float | None, Query(ge=0, le=100)] = None,
    damped: Annotated[bool | None, Query(description="Filter on context damping.")] = None,
    anti_tamper: bool | None = None,
    unassigned: bool = False,
    open_only: bool = False,
) -> Page[AlertWithIdentity]:
    stmt = select(Alert)

    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    if open_only:
        stmt = stmt.where(Alert.status.in_(OPEN_STATUSES))
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if state:
        stmt = stmt.where(Alert.transition_state == state)
    if min_risk is not None:
        stmt = stmt.where(Alert.risk_score >= min_risk)
    if damped is not None:
        stmt = stmt.where(Alert.context_damped.is_(damped))
    if anti_tamper is not None:
        stmt = stmt.where(Alert.anti_tamper_override.is_(anti_tamper))
    if unassigned:
        stmt = stmt.where(Alert.assigned_to_id.is_(None))
    if department:
        stmt = stmt.join(Identity, Identity.id == Alert.identity_id).where(Identity.department == department)

    stmt = apply_sort(stmt, Alert, params, "risk_score")
    page = await paginate(db, stmt, params, AlertRead.model_validate)

    # Decorate with identity context in one extra query rather than N.
    identity_ids = {a.identity_id for a in page.items}
    identities = {
        i.id: i
        for i in (await db.execute(select(Identity).where(Identity.id.in_(identity_ids)))).scalars().all()
    }
    items = []
    for alert in page.items:
        identity = identities.get(alert.identity_id)
        items.append(
            AlertWithIdentity(
                **alert.model_dump(),
                username=identity.username if identity else None,
                department=identity.department if identity else None,
                role_title=identity.role_title if identity else None,
            )
        )
    return Page[AlertWithIdentity](items=items, meta=page.meta)


@router.get("/stats", summary="Triage queue counters")
async def alert_stats(db: DbSession, _: CurrentUser) -> dict:
    alerts = (await db.execute(select(Alert))).scalars().all()
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for alert in alerts:
        by_status[str(alert.status)] = by_status.get(str(alert.status), 0) + 1
        by_severity[str(alert.severity)] = by_severity.get(str(alert.severity), 0) + 1
    return {
        "total": len(alerts),
        "open": sum(1 for a in alerts if a.status in OPEN_STATUSES),
        "unassigned": sum(1 for a in alerts if a.assigned_to_id is None and a.status in OPEN_STATUSES),
        "suppressed": sum(1 for a in alerts if a.context_damped),
        "anti_tamper": sum(1 for a in alerts if a.anti_tamper_override),
        "by_status": by_status,
        "by_severity": by_severity,
    }


@router.get("/{alert_id}", response_model=AlertRead, summary="Fetch one alert")
async def get_alert(alert_id: str, db: DbSession, _: CurrentUser) -> Alert:
    return await _resolve(db, alert_id)


@router.patch("/{alert_id}", response_model=AlertRead, summary="Update alert disposition")
async def update_alert(alert_id: str, payload: AlertUpdate, user: RequireAnalyst, db: DbSession) -> Alert:
    alert = await _resolve(db, alert_id)
    changes = payload.model_dump(exclude_unset=True)

    if payload.status is not None:
        if payload.status in {AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE, AlertStatus.CONFIRMED_INCIDENT}:
            alert.resolved_at = utcnow()
        if payload.status is AlertStatus.INVESTIGATING and alert.acknowledged_at is None:
            alert.acknowledged_at = utcnow()

    for field, value in changes.items():
        setattr(alert, field, value)

    await audit.record(
        db,
        action="alert.updated",
        target_type="alert",
        target_id=alert.id,
        actor=user,
        payload=changes,
    )
    return alert


@router.post("/{alert_id}/assign", response_model=AlertRead, summary="Assign to yourself")
async def assign_to_me(alert_id: str, user: RequireAnalyst, db: DbSession) -> Alert:
    alert = await _resolve(db, alert_id)
    alert.assigned_to_id = user.id
    if alert.status is AlertStatus.OPEN:
        alert.status = AlertStatus.TRIAGED
        alert.acknowledged_at = utcnow()
    await audit.record(db, action="alert.assigned", target_type="alert", target_id=alert.id, actor=user)
    return alert


@router.post(
    "/{alert_id}/false-positive",
    response_model=Message,
    summary="Mark as a false positive",
    description="Records analyst feedback and credits the matched rules, which feeds "
    "the precision statistics on the Detections page.",
)
async def mark_false_positive(
    alert_id: str, user: RequireAnalyst, db: DbSession, reason: str = ""
) -> Message:
    from app.db.models import DetectionRule

    alert = await _resolve(db, alert_id)
    alert.status = AlertStatus.FALSE_POSITIVE
    alert.resolved_at = utcnow()
    alert.resolution_note = reason or "Marked as a false positive by an analyst."

    if alert.matched_rule_ids:
        rules = (
            (await db.execute(select(DetectionRule).where(DetectionRule.id.in_(alert.matched_rule_ids))))
            .scalars()
            .all()
        )
        for rule in rules:
            rule.false_positive_count += 1

    await audit.record(
        db,
        action="alert.false_positive",
        target_type="alert",
        target_id=alert.id,
        actor=user,
        payload={"reason": reason},
    )
    return Message(
        message="Alert marked as a false positive.",
        detail="Rule precision statistics have been updated.",
    )


async def _resolve(db, alert_id: str) -> Alert:
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if alert is None:
        raise NotFoundError(f"No alert with id '{alert_id}'.")
    return alert
