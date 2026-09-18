"""Telemetry ingestion and the raw event stream."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession, Pagination, get_ingest_principal
from app.core.enums import EventType
from app.db.base import utcnow
from app.db.models import Identity, SecurityEvent
from app.schemas.common import Page
from app.schemas.domain import EventBatchIngest, EventIngest, EventRead, IngestResult
from app.services.ingest import ingest_service
from app.utils.query import apply_sort, paginate

router = APIRouter()


@router.post(
    "/ingest",
    response_model=IngestResult,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a telemetry batch",
    description=(
        "Accepts up to 1,000 events per call. Authenticate with an `X-API-Key` header "
        "(machine clients) or a bearer token. Each event is validated independently: one "
        "bad record does not reject the batch, and the response itemises every rejection."
    ),
)
async def ingest_batch(
    payload: EventBatchIngest,
    db: DbSession,
    _principal: Annotated[object, Depends(get_ingest_principal)],
) -> IngestResult:
    return await ingest_service.ingest(db, payload.events, recompute=payload.recompute)


@router.post(
    "/ingest/single",
    response_model=IngestResult,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest one event",
    description="Convenience wrapper over the batch endpoint for interactive injection.",
)
async def ingest_single(
    payload: EventIngest,
    db: DbSession,
    _principal: Annotated[object, Depends(get_ingest_principal)],
) -> IngestResult:
    return await ingest_service.ingest(db, [payload], recompute=True)


@router.get("", response_model=Page[EventRead], summary="Query the event stream")
async def list_events(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    identity_id: str | None = None,
    resource: str | None = None,
    action: str | None = None,
    event_type: EventType | None = None,
    min_score: Annotated[float | None, Query(ge=0, le=100)] = None,
    min_sensitivity: Annotated[int | None, Query(ge=1, le=5)] = None,
    off_hours_only: bool = False,
    damped: bool | None = None,
    since_hours: Annotated[int | None, Query(ge=1, le=8760)] = None,
) -> Page[EventRead]:
    stmt = select(SecurityEvent)

    if identity_id:
        stmt = stmt.where(SecurityEvent.identity_id == identity_id)
    if resource:
        stmt = stmt.where(SecurityEvent.resource.ilike(f"%{resource}%"))
    if action:
        stmt = stmt.where(SecurityEvent.action == action)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    if min_score is not None:
        stmt = stmt.where(SecurityEvent.anomaly_score >= min_score)
    if min_sensitivity is not None:
        stmt = stmt.where(SecurityEvent.sensitivity_level >= min_sensitivity)
    if off_hours_only:
        stmt = stmt.where(SecurityEvent.is_off_hours.is_(True))
    if damped is not None:
        stmt = stmt.where(SecurityEvent.is_damped.is_(damped))
    if since_hours:
        stmt = stmt.where(SecurityEvent.occurred_at >= utcnow() - timedelta(hours=since_hours))

    stmt = apply_sort(stmt, SecurityEvent, params, "occurred_at")
    return await paginate(db, stmt, params, EventRead.model_validate)


@router.get("/recent", response_model=list[dict], summary="Live feed backfill")
async def recent_events(
    db: DbSession,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict]:
    """The last N events with identity names attached — used to prime the live feed
    before the WebSocket takes over."""
    rows = (
        (await db.execute(select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(limit)))
        .scalars()
        .all()
    )
    identities = {
        i.id: i
        for i in (await db.execute(select(Identity).where(Identity.id.in_({r.identity_id for r in rows}))))
        .scalars()
        .all()
    }
    return [
        {
            "id": r.id,
            "identity_id": r.identity_id,
            "username": identities[r.identity_id].username if r.identity_id in identities else "?",
            "department": identities[r.identity_id].department if r.identity_id in identities else "?",
            "occurred_at": r.occurred_at.isoformat(),
            "event_type": str(r.event_type),
            "resource": r.resource,
            "action": r.action,
            "sensitivity_level": r.sensitivity_level,
            "anomaly_score": r.anomaly_score,
            "is_damped": r.is_damped,
            "is_off_hours": r.is_off_hours,
            "country": r.country,
            "matched_rules": r.matched_rules,
        }
        for r in rows
    ]


@router.get("/stats", summary="Ingestion statistics")
async def event_stats(db: DbSession, _: CurrentUser) -> dict:
    now = utcnow()
    windows = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
    counts: dict[str, int] = {}
    for label, hours in windows.items():
        rows = (
            (
                await db.execute(
                    select(SecurityEvent.id).where(SecurityEvent.occurred_at >= now - timedelta(hours=hours))
                )
            )
            .scalars()
            .all()
        )
        counts[label] = len(rows)

    anomalous = (
        (
            await db.execute(
                select(SecurityEvent.id).where(
                    SecurityEvent.occurred_at >= now - timedelta(hours=24),
                    SecurityEvent.anomaly_score >= 45,
                )
            )
        )
        .scalars()
        .all()
    )

    by_source = {}
    for (source,) in (await db.execute(select(SecurityEvent.source))).all():
        by_source[source] = by_source.get(source, 0) + 1

    return {
        "counts": counts,
        "anomalous_24h": len(anomalous),
        "anomaly_rate_24h": round(len(anomalous) / max(counts["24h"], 1) * 100, 2),
        "by_source": by_source,
        "generated_at": datetime.utcnow(),
    }
