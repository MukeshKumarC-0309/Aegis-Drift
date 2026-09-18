"""Background maintenance loop.

Runs inside the API process: periodically re-scores the fleet, snapshots risk for
trend charts, expires stale context records and prunes telemetry past retention.
A dedicated worker process would be the next step at real volume; at this scale an
asyncio task with a lock is the honest, simpler answer.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import timedelta

from sqlalchemy import delete, select, update

from app.core.config import settings
from app.core.logging import get_logger
from app.core.metrics import FLEET_RISK, IDENTITIES_BY_STATE
from app.db.base import utcnow
from app.db.models import ContextRecord, Identity, RiskSnapshot, SecurityEvent, Watchlist
from app.db.session import session_scope
from app.services.detection import detection_service
from app.services.events import event_bus

logger = get_logger(__name__)

#: Snapshot risk roughly every 10 minutes regardless of the scoring cadence.
SNAPSHOT_INTERVAL_SECONDS = 600

#: Housekeeping (expiry, retention) runs hourly.
MAINTENANCE_INTERVAL_SECONDS = 3600


class BackgroundScheduler:
    """Owns the periodic task; started and stopped by the application lifespan."""

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._last_snapshot = 0.0
        self._last_maintenance = 0.0

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="silentshift-scheduler")
        logger.info("scheduler.started", interval=settings.RECOMPUTE_INTERVAL_SECONDS)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        logger.info("scheduler.stopped")

    async def _run(self) -> None:
        # Let the application finish starting before the first pass.
        await asyncio.sleep(5)
        while not self._stopping.is_set():
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A failed cycle must never kill the loop.
                logger.exception("scheduler.tick_failed", error=str(exc))
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=settings.RECOMPUTE_INTERVAL_SECONDS)
            except TimeoutError:
                continue

    async def _tick(self) -> None:
        now = asyncio.get_running_loop().time()
        snapshot = now - self._last_snapshot >= SNAPSHOT_INTERVAL_SECONDS

        async with session_scope() as db:
            results = await detection_service.score_all(db, snapshot=snapshot)
            await self._publish_gauges(db)

        if snapshot:
            self._last_snapshot = now

        if now - self._last_maintenance >= MAINTENANCE_INTERVAL_SECONDS:
            async with session_scope() as db:
                await self._maintenance(db)
            self._last_maintenance = now

        escalated = [
            identity_id
            for identity_id, result in results.items()
            if result.cumulative_risk >= detection_service.config.threshold_escalating
        ]
        if escalated:
            await event_bus.publish(
                "fleet.rescored",
                {"scored": len(results), "escalated": len(escalated)},
            )

    @staticmethod
    async def _publish_gauges(db) -> None:
        identities = (await db.execute(select(Identity).where(Identity.is_active.is_(True)))).scalars().all()
        if not identities:
            return
        counts: dict[str, int] = {}
        for identity in identities:
            key = str(identity.transition_state)
            counts[key] = counts.get(key, 0) + 1
        for state, count in counts.items():
            IDENTITIES_BY_STATE.labels(state=state).set(count)
        FLEET_RISK.set(sum(i.risk_score for i in identities) / len(identities))

    @staticmethod
    async def _maintenance(db) -> None:
        now = utcnow()

        expired_contexts = await db.execute(
            update(ContextRecord)
            .where(ContextRecord.is_active.is_(True), ContextRecord.valid_until < now)
            .values(is_active=False)
        )

        expired_watchlists = (
            (
                await db.execute(
                    select(Watchlist).where(
                        Watchlist.is_active.is_(True),
                        Watchlist.expires_at.is_not(None),
                        Watchlist.expires_at < now,
                    )
                )
            )
            .scalars()
            .all()
        )
        for watchlist in expired_watchlists:
            watchlist.is_active = False
            if watchlist.member_ids:
                await db.execute(
                    update(Identity).where(Identity.id.in_(watchlist.member_ids)).values(on_watchlist=False)
                )

        cutoff = now - timedelta(days=settings.RETENTION_DAYS)
        pruned_events = await db.execute(delete(SecurityEvent).where(SecurityEvent.occurred_at < cutoff))
        pruned_snapshots = await db.execute(delete(RiskSnapshot).where(RiskSnapshot.captured_at < cutoff))

        logger.info(
            "scheduler.maintenance",
            contexts_expired=expired_contexts.rowcount or 0,
            watchlists_expired=len(expired_watchlists),
            events_pruned=pruned_events.rowcount or 0,
            snapshots_pruned=pruned_snapshots.rowcount or 0,
            retention_days=settings.RETENTION_DAYS,
        )


scheduler = BackgroundScheduler()
