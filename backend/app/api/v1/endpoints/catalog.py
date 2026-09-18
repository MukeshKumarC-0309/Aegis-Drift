"""Asset catalogue and threat-intelligence indicators."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, status
from sqlalchemy import or_, select

from app.api.deps import CurrentUser, DbSession, Pagination, RequireAnalyst
from app.core.enums import IndicatorType
from app.core.exceptions import ConflictError, NotFoundError
from app.db.base import utcnow
from app.db.models import Asset, ThreatIndicator
from app.schemas.common import Message, Page
from app.schemas.domain import AssetRead, IndicatorCreate, IndicatorRead
from app.services import audit
from app.utils.query import apply_sort, paginate

router = APIRouter()


@router.get("/assets", response_model=Page[AssetRead], summary="Asset catalogue")
async def list_assets(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    category: str | None = None,
    min_sensitivity: int | None = None,
    crown_jewels_only: bool = False,
    pii_only: bool = False,
    search: str | None = None,
) -> Page[AssetRead]:
    stmt = select(Asset)
    if category:
        stmt = stmt.where(Asset.category == category)
    if min_sensitivity is not None:
        stmt = stmt.where(Asset.sensitivity_level >= min_sensitivity)
    if crown_jewels_only:
        stmt = stmt.where(Asset.is_crown_jewel.is_(True))
    if pii_only:
        stmt = stmt.where(Asset.contains_pii.is_(True))
    if search:
        pattern = f"%{search.lower()}%"
        stmt = stmt.where(or_(Asset.key.ilike(pattern), Asset.display_name.ilike(pattern)))
    stmt = apply_sort(stmt, Asset, params, "sensitivity_level")
    return await paginate(db, stmt, params, AssetRead.model_validate)


@router.get("/assets/summary", summary="Catalogue composition")
async def asset_summary(db: DbSession, _: CurrentUser) -> dict:
    assets = (await db.execute(select(Asset))).scalars().all()
    by_category: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    for asset in assets:
        by_category[asset.category] = by_category.get(asset.category, 0) + 1
        by_tier[str(asset.sensitivity_level)] = by_tier.get(str(asset.sensitivity_level), 0) + 1
    return {
        "total": len(assets),
        "crown_jewels": sum(1 for a in assets if a.is_crown_jewel),
        "pii_assets": sum(1 for a in assets if a.contains_pii),
        "cardholder_assets": sum(1 for a in assets if a.contains_cardholder_data),
        "phi_assets": sum(1 for a in assets if a.contains_phi),
        "total_records": sum(a.record_estimate for a in assets),
        "by_category": by_category,
        "by_sensitivity_tier": by_tier,
    }


@router.get("/indicators", response_model=Page[IndicatorRead], summary="Threat intel feed")
async def list_indicators(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    indicator_type: IndicatorType | None = None,
    active_only: bool = True,
    min_confidence: int | None = None,
) -> Page[IndicatorRead]:
    stmt = select(ThreatIndicator)
    if indicator_type:
        stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)
    if active_only:
        stmt = stmt.where(ThreatIndicator.is_active.is_(True))
    if min_confidence is not None:
        stmt = stmt.where(ThreatIndicator.confidence >= min_confidence)
    stmt = apply_sort(stmt, ThreatIndicator, params, "confidence")
    return await paginate(db, stmt, params, IndicatorRead.model_validate)


@router.post(
    "/indicators",
    response_model=IndicatorRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add an indicator",
)
async def create_indicator(payload: IndicatorCreate, user: RequireAnalyst, db: DbSession) -> ThreatIndicator:
    exists = (
        await db.execute(
            select(ThreatIndicator.id).where(
                ThreatIndicator.indicator_type == payload.indicator_type,
                ThreatIndicator.value == payload.value,
            )
        )
    ).scalar_one_or_none()
    if exists:
        raise ConflictError(f"Indicator '{payload.value}' is already tracked.")

    now = utcnow()
    indicator = ThreatIndicator(
        indicator_type=payload.indicator_type,
        value=payload.value,
        confidence=payload.confidence,
        severity=payload.severity,
        source_feed=payload.source_feed,
        description=payload.description,
        first_seen=now,
        last_seen=now,
        expires_at=(now + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None),
    )
    db.add(indicator)
    await db.flush()
    await audit.record(
        db,
        action="indicator.created",
        target_type="indicator",
        target_id=indicator.id,
        actor=user,
        payload={"type": str(payload.indicator_type), "value": payload.value},
    )
    return indicator


@router.delete("/indicators/{indicator_id}", response_model=Message, summary="Retire an indicator")
async def retire_indicator(indicator_id: str, user: RequireAnalyst, db: DbSession) -> Message:
    indicator = (
        await db.execute(select(ThreatIndicator).where(ThreatIndicator.id == indicator_id))
    ).scalar_one_or_none()
    if indicator is None:
        raise NotFoundError(f"No indicator with id '{indicator_id}'.")
    indicator.is_active = False
    await audit.record(
        db, action="indicator.retired", target_type="indicator", target_id=indicator.id, actor=user
    )
    return Message(message=f"Indicator '{indicator.value}' retired.")
