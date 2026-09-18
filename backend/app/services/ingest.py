"""Telemetry ingestion: validate, normalise, persist and trigger re-scoring."""

from __future__ import annotations

import time
from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models import Identity, SecurityEvent
from app.schemas.domain import EventIngest, IngestResult
from app.services.detection import detection_service
from app.services.events import event_bus

logger = get_logger(__name__)

#: Outside this band an event is treated as clock skew or a replay and rejected.
MAX_FUTURE_SKEW = timedelta(minutes=10)
MAX_AGE = timedelta(days=365)

#: Hours considered "off hours" when the caller does not say.
WORK_START_HOUR = 7
WORK_END_HOUR = 20


class IngestService:
    """Batch-oriented ingestion with per-event error isolation."""

    async def ingest(
        self,
        db: AsyncSession,
        events: list[EventIngest],
        *,
        recompute: bool = True,
        source_override: str | None = None,
    ) -> IngestResult:
        started = time.perf_counter()
        now = utcnow()

        identities = await self._resolve_identities(db, events)
        accepted: list[SecurityEvent] = []
        errors: list[dict] = []

        for index, payload in enumerate(events):
            identity = identities.get(payload.identity.lower())
            if identity is None:
                errors.append({"index": index, "identity": payload.identity, "error": "Unknown identity"})
                continue

            occurred_at = payload.occurred_at or now
            if occurred_at.tzinfo is not None:
                occurred_at = occurred_at.replace(tzinfo=None)
            if occurred_at > now + MAX_FUTURE_SKEW:
                errors.append(
                    {"index": index, "identity": payload.identity, "error": "Timestamp is in the future"}
                )
                continue
            if occurred_at < now - MAX_AGE:
                errors.append(
                    {
                        "index": index,
                        "identity": payload.identity,
                        "error": "Timestamp exceeds retention window",
                    }
                )
                continue

            off_hours = payload.is_off_hours
            if off_hours is None:
                off_hours = not (WORK_START_HOUR <= occurred_at.hour <= WORK_END_HOUR) or (
                    occurred_at.weekday() >= 5
                )

            row = SecurityEvent(
                identity_id=identity.id,
                occurred_at=occurred_at,
                ingested_at=now,
                event_type=payload.event_type,
                resource=payload.resource,
                action=payload.action,
                outcome=payload.outcome,
                sensitivity_level=payload.sensitivity_level,
                ip_address=payload.ip_address,
                country=payload.country,
                city=payload.city,
                latitude=payload.latitude,
                longitude=payload.longitude,
                asn=payload.asn,
                device_id=payload.device_id,
                user_agent=payload.user_agent,
                bytes_transferred=payload.bytes_transferred,
                record_count=payload.record_count,
                is_off_hours=off_hours,
                context_tags=payload.context_tags,
                source=source_override or payload.source,
                event_metadata=payload.metadata,
            )
            db.add(row)
            accepted.append(row)
            identity.event_count += 1
            if identity.last_event_at is None or occurred_at > identity.last_event_at:
                identity.last_event_at = occurred_at

        await db.flush()

        rescored: list[str] = []
        alerts_raised: list[str] = []
        if recompute and accepted:
            affected = {row.identity_id for row in accepted}
            for identity_id in affected:
                identity = next(i for i in identities.values() if i.id == identity_id)
                result = await detection_service.score_identity(db, identity)
                rescored.append(identity_id)
                await event_bus.publish(
                    "identity.rescored",
                    {
                        "identity_id": identity.id,
                        "username": identity.username,
                        "risk_score": result.cumulative_risk,
                        "transition_state": result.transition_state.value,
                        "drift_velocity": result.drift_velocity,
                        "dominant_vectors": result.dominant_vectors,
                    },
                )
                if result.cumulative_risk >= detection_service.config.threshold_escalating:
                    alerts_raised.append(identity.id)

        for row in accepted[-25:]:
            await event_bus.publish(
                "event.ingested",
                {
                    "event_id": row.id,
                    "identity_id": row.identity_id,
                    "resource": row.resource,
                    "action": row.action,
                    "sensitivity_level": row.sensitivity_level,
                    "occurred_at": row.occurred_at.isoformat(),
                    "anomaly_score": row.anomaly_score,
                },
            )

        duration_ms = int((time.perf_counter() - started) * 1000)
        logger.info(
            "ingest.batch",
            accepted=len(accepted),
            rejected=len(errors),
            rescored=len(rescored),
            duration_ms=duration_ms,
        )
        return IngestResult(
            accepted=len(accepted),
            rejected=len(errors),
            identities_rescored=rescored,
            alerts_raised=alerts_raised,
            errors=errors[:50],
            duration_ms=duration_ms,
        )

    @staticmethod
    async def _resolve_identities(db: AsyncSession, events: list[EventIngest]) -> dict[str, Identity]:
        """Look identities up by id *or* username in a single query."""
        keys = {e.identity for e in events}
        if not keys:
            return {}
        rows = (
            (
                await db.execute(
                    select(Identity).where(or_(Identity.id.in_(keys), Identity.username.in_(keys)))
                )
            )
            .scalars()
            .all()
        )
        lookup: dict[str, Identity] = {}
        for row in rows:
            lookup[row.id.lower()] = row
            lookup[row.username.lower()] = row
        return lookup


ingest_service = IngestService()
