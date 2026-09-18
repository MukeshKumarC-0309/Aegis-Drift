"""Dashboards, executive metrics, ATT&CK coverage and engine tuning."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from fastapi import APIRouter
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession, Pagination, RequireAdmin, RequireAnalyst
from app.core.exceptions import ValidationError
from app.db.base import utcnow
from app.db.models import Alert, AuditLog, Integration, RiskSnapshot, Watchlist
from app.engine.mitre import CATALOG, coverage_matrix
from app.schemas.analytics import (
    EnterpriseMetrics,
    HyperparameterSet,
    HyperparameterUpdate,
    OverviewResponse,
)
from app.schemas.common import Page
from app.schemas.domain import AuditLogRead, IntegrationRead, WatchlistCreate, WatchlistRead
from app.services import audit
from app.services.analytics import analytics_service
from app.services.detection import detection_service
from app.utils.query import apply_sort, paginate

router = APIRouter()


@router.get("/overview", response_model=OverviewResponse, summary="Command Center dashboard")
async def overview(db: DbSession, _: CurrentUser) -> dict:
    return await analytics_service.overview(db)


@router.get("/metrics", response_model=EnterpriseMetrics, summary="Executive effectiveness metrics")
async def enterprise_metrics(db: DbSession, _: CurrentUser) -> dict:
    return await analytics_service.enterprise_metrics(db)


@router.get("/mitre/coverage", summary="ATT&CK coverage matrix")
async def mitre_coverage(db: DbSession, _: CurrentUser) -> dict:
    alerts = (await db.execute(select(Alert))).scalars().all()
    observed = {t for a in alerts for t in (a.mitre_techniques or [])}
    matrix = coverage_matrix(observed)
    return {
        "matrix": matrix,
        "observed_count": len(observed),
        "catalog_size": len(CATALOG),
        "coverage_percentage": round(len(observed) / max(len(CATALOG), 1) * 100, 1),
        "observed_techniques": sorted(observed),
    }


@router.get("/trends/risk", summary="Fleet risk trend")
async def risk_trend(db: DbSession, _: CurrentUser, days: int = 14) -> list[dict]:
    since = utcnow() - timedelta(days=min(days, 90))
    rows = (
        (
            await db.execute(
                select(RiskSnapshot)
                .where(RiskSnapshot.captured_at >= since)
                .order_by(RiskSnapshot.captured_at)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "identity_id": r.identity_id,
            "captured_at": r.captured_at,
            "risk_score": r.risk_score,
            "raw_risk_score": r.raw_risk_score,
            "transition_state": str(r.transition_state),
        }
        for r in rows
    ]


@router.get("/peer-outliers", summary="Identities outside their cohort norm")
async def peer_outliers(db: DbSession, _: CurrentUser, z_threshold: float = 1.8) -> list[dict]:
    return await detection_service.peer_outliers(db, z_threshold)


@router.get("/integrations", response_model=list[IntegrationRead], summary="Connected systems")
async def list_integrations(db: DbSession, _: CurrentUser):
    return list(
        (await db.execute(select(Integration).order_by(Integration.kind, Integration.name))).scalars().all()
    )


@router.get("/audit", response_model=Page[AuditLogRead], summary="Audit trail")
async def audit_trail(
    db: DbSession,
    _: RequireAnalyst,
    params: Pagination,
    action: str | None = None,
    target_type: str | None = None,
    actor_email: str | None = None,
) -> Page[AuditLogRead]:
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action.ilike(f"%{action}%"))
    if target_type:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if actor_email:
        stmt = stmt.where(AuditLog.actor_email == actor_email)
    stmt = apply_sort(stmt, AuditLog, params, "created_at")
    return await paginate(db, stmt, params, AuditLogRead.model_validate)


# -------------------------------------------------------------------- tuning
@router.get(
    "/hyperparameters",
    response_model=HyperparameterSet,
    summary="Current engine tuning",
)
async def get_hyperparameters(_: CurrentUser) -> HyperparameterSet:
    return _hyperparameter_response(detection_service.config)


@router.put(
    "/hyperparameters",
    response_model=HyperparameterSet,
    summary="Retune the engine",
    description=(
        "Adjusts the live detection engine. Thresholds must remain strictly ordered, and "
        "vector weights are renormalised to sum to 1 so a partial edit cannot silently "
        "rescale every score. Optionally re-scores the whole fleet."
    ),
)
async def update_hyperparameters(
    payload: HyperparameterUpdate, user: RequireAdmin, db: DbSession
) -> HyperparameterSet:
    live = detection_service.config

    # Validate against a candidate copy and only commit once every check passes.
    # Mutating the live config first would leave the running detector configured
    # with values this endpoint just rejected — silently raising the alerting
    # threshold while telling the operator nothing changed.
    candidate = replace(live, vector_weights=dict(live.vector_weights))
    changes = payload.model_dump(exclude_unset=True, exclude={"recompute"})

    if payload.vector_weights is not None:
        unknown = set(payload.vector_weights) - set(candidate.vector_weights)
        if unknown:
            raise ValidationError(
                f"Unknown vector(s): {', '.join(sorted(unknown))}.",
                details={"valid": sorted(candidate.vector_weights)},
            )
        if any(v < 0 for v in payload.vector_weights.values()):
            raise ValidationError("Vector weights must be non-negative.")
        candidate.vector_weights.update(payload.vector_weights)
        if sum(candidate.vector_weights.values()) <= 0:
            raise ValidationError("At least one vector weight must be greater than zero.")
        changes.pop("vector_weights", None)

    for field, value in changes.items():
        setattr(candidate, field, value)

    if not (candidate.threshold_early_drift < candidate.threshold_escalating < candidate.threshold_critical):
        raise ValidationError(
            "Thresholds must satisfy early_drift < escalating < critical.",
            details={
                "early_drift": candidate.threshold_early_drift,
                "escalating": candidate.threshold_escalating,
                "critical": candidate.threshold_critical,
            },
        )

    # Every check passed — commit the candidate onto the live engine.
    detection_service.apply_config(candidate)

    await audit.record(
        db,
        action="engine.retuned",
        target_type="engine",
        target_id="config",
        actor=user,
        payload=payload.model_dump(exclude_unset=True),
    )

    if payload.recompute:
        await detection_service.score_all(db, snapshot=False)

    return _hyperparameter_response(detection_service.config)


def _hyperparameter_response(cfg) -> HyperparameterSet:
    return HyperparameterSet(
        decay_halflife_hours=cfg.decay_halflife_hours,
        normal_threshold=cfg.normal_threshold,
        threshold_early_drift=cfg.threshold_early_drift,
        threshold_escalating=cfg.threshold_escalating,
        threshold_critical=cfg.threshold_critical,
        vector_weights=cfg.vector_weights,
        synergy_elevated_at=cfg.synergy_elevated_at,
    )


# ----------------------------------------------------------------- watchlists
@router.get("/watchlists", response_model=list[WatchlistRead], summary="List watchlists")
async def list_watchlists(db: DbSession, _: CurrentUser):
    return list((await db.execute(select(Watchlist).order_by(Watchlist.created_at.desc()))).scalars().all())


@router.post("/watchlists", response_model=WatchlistRead, summary="Create a watchlist")
async def create_watchlist(payload: WatchlistCreate, user: RequireAnalyst, db: DbSession) -> Watchlist:
    from app.db.models import Identity

    watchlist = Watchlist(
        name=payload.name,
        description=payload.description,
        reason=payload.reason,
        risk_multiplier=payload.risk_multiplier,
        member_ids=payload.member_ids,
        created_by_id=user.id,
        expires_at=(utcnow() + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None),
    )
    db.add(watchlist)

    if payload.member_ids:
        members = (
            (await db.execute(select(Identity).where(Identity.id.in_(payload.member_ids)))).scalars().all()
        )
        for member in members:
            member.on_watchlist = True
            await detection_service.score_identity(db, member)

    await db.flush()
    await audit.record(
        db,
        action="watchlist.created",
        target_type="watchlist",
        target_id=watchlist.id,
        actor=user,
        payload={"name": watchlist.name, "members": len(payload.member_ids)},
    )
    return watchlist


@router.get("/system", summary="Runtime and configuration snapshot")
async def system_info(_: RequireAdmin, db: DbSession) -> dict:
    from app.core.config import settings
    from app.services.events import event_bus

    return {
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database_dialect": "sqlite" if settings.is_sqlite else "postgresql",
        "redis_enabled": bool(settings.REDIS_URL),
        "metrics_enabled": settings.METRICS_ENABLED,
        "rate_limiting": {
            "enabled": settings.RATE_LIMIT_ENABLED,
            "requests_per_window": settings.RATE_LIMIT_REQUESTS,
            "window_seconds": settings.RATE_LIMIT_WINDOW_SECONDS,
        },
        "websocket_clients": event_bus.subscriber_count,
        "retention_days": settings.RETENTION_DAYS,
        "recompute_interval_seconds": settings.RECOMPUTE_INTERVAL_SECONDS,
        "generated_at": datetime.utcnow(),
    }
