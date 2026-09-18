"""The detection orchestration service.

Owns the full scoring cycle for an identity: load telemetry, run the engine,
persist the results, and raise or resolve alerts. This is the only place that
knows both the database and the engine.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.enums import AlertStatus, Severity, TransitionState
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models import (
    Alert,
    Asset,
    Baseline,
    ContextRecord,
    DetectionRule,
    Identity,
    RiskSnapshot,
    SecurityEvent,
    ThreatIndicator,
    Watchlist,
)
from app.engine import (
    BaselineEngine,
    BlastRadiusEngine,
    ContextEngine,
    CopilotEngine,
    EngineConfig,
    ExplainabilityEngine,
    PeerEngine,
    RuleEngine,
    SequenceEngine,
)
from app.engine.peer import CohortMember, cohort_key
from app.engine.types import CorrelationResult, PeerStats
from app.services import adapters

logger = get_logger(__name__)

#: How far back the correlator looks. Older events are already reflected in the
#: baseline and would be decayed to irrelevance anyway.
CORRELATION_WINDOW_DAYS = 14

#: Baselines are learned from this window, ending before the correlation window.
BASELINE_WINDOW_DAYS = 45


class DetectionService:
    """Stateless orchestrator — one instance is shared across requests."""

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or EngineConfig(
            decay_halflife_hours=settings.DECAY_HALFLIFE_HOURS,
            threshold_early_drift=settings.THRESHOLD_EARLY_DRIFT,
            threshold_escalating=settings.THRESHOLD_ESCALATING,
            threshold_critical=settings.THRESHOLD_CRITICAL,
        )
        self.baseline_engine = BaselineEngine()
        self.context_engine = ContextEngine()
        self.sequence_engine = SequenceEngine(self.baseline_engine, self.context_engine, self.config)
        self.explain_engine = ExplainabilityEngine()
        self.blast_engine = BlastRadiusEngine()
        self.peer_engine = PeerEngine()
        self.copilot_engine = CopilotEngine()

        self._peer_cache: dict[str, PeerStats] = {}
        self._peer_cache_at: datetime | None = None

    def apply_config(self, config: EngineConfig) -> None:
        """Swap in a validated configuration.

        The sequence engine holds its own reference, so both must be updated
        together or scoring would silently keep using the previous settings.
        """
        self.config = config
        self.sequence_engine.config = config

    # ------------------------------------------------------------------ scoring
    async def score_identity(
        self,
        db: AsyncSession,
        identity: Identity,
        *,
        persist: bool = True,
        snapshot: bool = False,
    ) -> CorrelationResult:
        """Run the full pipeline for one identity and optionally persist results."""
        window_start = utcnow() - timedelta(days=CORRELATION_WINDOW_DAYS)

        events = await self._load_events(db, identity.id, since=window_start)
        baseline_row = await self._get_baseline_row(db, identity.id)
        baseline = adapters.to_baseline_view(identity, baseline_row)

        contexts = await self._load_contexts(db, identity.id)
        rules = await self._load_rules(db)
        indicators = await self._load_indicators(db)
        peer = await self.peer_stats_for(db, identity)
        multiplier = await self._watchlist_multiplier(db, identity.id)

        result = self.sequence_engine.correlate(
            identity.id,
            events,
            baseline,
            contexts=contexts,
            peer=peer,
            rules=RuleEngine(rules),
            indicators=indicators,
            risk_multiplier=multiplier,
        )

        if persist:
            await self._persist_scores(db, identity, result)
            if snapshot:
                db.add(
                    RiskSnapshot(
                        identity_id=identity.id,
                        captured_at=utcnow(),
                        risk_score=result.cumulative_risk,
                        raw_risk_score=result.raw_cumulative_risk,
                        transition_state=result.transition_state,
                        vector_scores=result.vector_scores,
                        event_count=result.event_count,
                    )
                )
            await self.reconcile_alert(db, identity, result)
        return result

    async def score_all(self, db: AsyncSession, *, snapshot: bool = False) -> dict[str, CorrelationResult]:
        """Re-score every active identity. Used by the background worker."""
        identities = (await db.execute(select(Identity).where(Identity.is_active.is_(True)))).scalars().all()

        await self.refresh_peer_cache(db, force=True)
        results: dict[str, CorrelationResult] = {}
        for identity in identities:
            results[identity.id] = await self.score_identity(db, identity, persist=True, snapshot=snapshot)
        logger.info("detection.fleet_scored", identities=len(results))
        return results

    # ----------------------------------------------------------------- baseline
    async def rebuild_baseline(self, db: AsyncSession, identity: Identity) -> Baseline:
        """Learn (or re-learn) an identity's behavioural norm from recent history."""
        since = utcnow() - timedelta(days=BASELINE_WINDOW_DAYS)
        events = await self._load_events(db, identity.id, since=since)

        view = self.baseline_engine.build(
            identity.id,
            identity.username,
            identity.department,
            identity.role_title,
            identity.peer_group_id,
            events,
        )
        row = await self._get_baseline_row(db, identity.id)
        if row is None:
            row = Baseline(identity_id=identity.id)
            db.add(row)
        adapters.apply_baseline_view(row, view)
        row.window_start = min((e.occurred_at for e in events), default=None)
        row.window_end = max((e.occurred_at for e in events), default=None)
        await db.flush()
        return row

    # -------------------------------------------------------------------- peers
    async def refresh_peer_cache(self, db: AsyncSession, *, force: bool = False) -> None:
        """Recompute cohort statistics; cheap enough to do on a short TTL."""
        fresh = (
            self._peer_cache_at
            and (datetime.now(UTC).replace(tzinfo=None) - self._peer_cache_at).total_seconds() < 120
        )
        if fresh and not force:
            return

        rows = (
            (
                await db.execute(
                    select(Identity)
                    .options(selectinload(Identity.baseline))
                    .where(Identity.is_active.is_(True))
                )
            )
            .scalars()
            .all()
        )

        members = [
            CohortMember(
                identity_id=i.id,
                username=i.username,
                department=i.department,
                role_title=i.role_title,
                risk_score=i.risk_score,
                daily_events=i.baseline.avg_daily_events if i.baseline else 20.0,
                max_sensitivity=i.baseline.typical_max_sensitivity if i.baseline else 2,
                resources=list(i.baseline.common_resources or []) if i.baseline else [],
            )
            for i in rows
        ]
        self._peer_cache = self.peer_engine.build_cohorts(members)
        self._peer_cache_at = utcnow()

    async def peer_stats_for(self, db: AsyncSession, identity: Identity) -> PeerStats | None:
        await self.refresh_peer_cache(db)
        return self._peer_cache.get(cohort_key(identity.department, identity.role_title))

    async def peer_outliers(self, db: AsyncSession, z_threshold: float = 1.8) -> list[dict]:
        await self.refresh_peer_cache(db, force=True)
        rows = (
            (
                await db.execute(
                    select(Identity)
                    .options(selectinload(Identity.baseline))
                    .where(Identity.is_active.is_(True))
                )
            )
            .scalars()
            .all()
        )
        members = [
            CohortMember(
                identity_id=i.id,
                username=i.username,
                department=i.department,
                role_title=i.role_title,
                risk_score=i.risk_score,
                daily_events=i.baseline.avg_daily_events if i.baseline else 20.0,
                max_sensitivity=i.baseline.typical_max_sensitivity if i.baseline else 2,
                resources=[],
            )
            for i in rows
        ]
        return self.peer_engine.outliers(members, self._peer_cache, z_threshold)

    # ------------------------------------------------------------------- alerts
    async def reconcile_alert(
        self, db: AsyncSession, identity: Identity, result: CorrelationResult
    ) -> Alert | None:
        """Create, update or resolve the identity's open alert to match its state.

        Deliberately keeps at most one *open* alert per identity: a drifting account
        is one story, not one alert per event. Occurrence count carries the volume.
        """
        existing = (
            await db.execute(
                select(Alert)
                .where(
                    Alert.identity_id == identity.id,
                    Alert.status.notin_(
                        [AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE, AlertStatus.CONFIRMED_INCIDENT]
                    ),
                )
                .order_by(Alert.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        should_alert = (
            result.cumulative_risk >= self.config.threshold_early_drift or result.anti_tamper_triggered
        )

        if not should_alert:
            if existing and existing.status in {AlertStatus.OPEN, AlertStatus.TRIAGED}:
                existing.status = AlertStatus.CLOSED
                existing.resolved_at = utcnow()
                existing.resolution_note = "Auto-closed: risk decayed below the drift threshold."
            return existing

        baseline_row = await self._get_baseline_row(db, identity.id)
        baseline = adapters.to_baseline_view(identity, baseline_row)
        contexts = await self._load_contexts(db, identity.id)
        peer = await self.peer_stats_for(db, identity)
        explanation = self.explain_engine.explain(result, baseline, contexts=contexts, peer=peer)

        severity = self._severity_for(result)
        triggering = [s.event.id for s in sorted(result.scored_events, key=lambda s: -s.raw_score)[:8]]
        techniques = [t["id"] for t in explanation.mitre_techniques]
        first_anomaly = next(
            (s.event.occurred_at for s in result.scored_events if s.raw_score >= 45),
            utcnow(),
        )

        if existing:
            existing.risk_score = result.cumulative_risk
            existing.raw_risk_score = result.raw_cumulative_risk
            existing.transition_state = result.transition_state
            existing.drift_velocity = result.drift_velocity
            existing.severity = severity
            existing.confidence = explanation.confidence
            existing.summary = explanation.headline
            existing.title = self._alert_title(identity, result)
            existing.context_damped = result.damping_applied
            existing.damping_reason = result.damping_reasons[-1] if result.damping_reasons else None
            existing.anti_tamper_override = result.anti_tamper_triggered
            existing.dominant_vectors = result.dominant_vectors
            existing.vector_scores = result.vector_scores
            existing.mitre_techniques = techniques
            existing.triggering_event_ids = triggering
            existing.matched_rule_ids = result.matched_rule_ids
            existing.last_seen_at = utcnow()
            existing.occurrence_count += 1
            if result.damping_applied and result.cumulative_risk < 30:
                existing.status = AlertStatus.SUPPRESSED
            return existing

        alert = Alert(
            identity_id=identity.id,
            title=self._alert_title(identity, result),
            summary=explanation.headline,
            severity=severity,
            status=(
                AlertStatus.SUPPRESSED
                if result.damping_applied and result.cumulative_risk < 30
                else AlertStatus.OPEN
            ),
            confidence=explanation.confidence,
            risk_score=result.cumulative_risk,
            raw_risk_score=result.raw_cumulative_risk,
            transition_state=result.transition_state,
            drift_velocity=result.drift_velocity,
            context_damped=result.damping_applied,
            damping_reason=result.damping_reasons[-1] if result.damping_reasons else None,
            anti_tamper_override=result.anti_tamper_triggered,
            dominant_vectors=result.dominant_vectors,
            vector_scores=result.vector_scores,
            mitre_techniques=techniques,
            triggering_event_ids=triggering,
            matched_rule_ids=result.matched_rule_ids,
            first_seen_at=first_anomaly,
            last_seen_at=utcnow(),
        )
        db.add(alert)
        await db.flush()
        logger.info(
            "detection.alert_raised",
            alert_id=alert.id,
            identity=identity.username,
            risk=result.cumulative_risk,
            state=result.transition_state.value,
        )
        return alert

    def _severity_for(self, result: CorrelationResult) -> Severity:
        if result.anti_tamper_triggered:
            return Severity.CRITICAL
        return {
            TransitionState.CRITICAL_TRANSITION: Severity.CRITICAL,
            TransitionState.ESCALATING: Severity.HIGH,
            TransitionState.EARLY_DRIFT: Severity.MEDIUM,
            TransitionState.STABLE: Severity.LOW,
        }[result.transition_state]

    @staticmethod
    def _alert_title(identity: Identity, result: CorrelationResult) -> str:
        if result.anti_tamper_triggered:
            return f"Audit tampering by {identity.username}"
        vectors = ", ".join(v.replace("_", " ") for v in result.dominant_vectors[:2])
        label = result.transition_state.value.replace("_", " ").title()
        return f"{label}: {identity.username} — {vectors}"

    # -------------------------------------------------------------- persistence
    async def _persist_scores(self, db: AsyncSession, identity: Identity, result: CorrelationResult) -> None:
        identity.risk_score = result.cumulative_risk
        identity.raw_risk_score = result.raw_cumulative_risk
        identity.transition_state = result.transition_state
        identity.drift_velocity = result.drift_velocity
        identity.dominant_vector = result.dominant_vectors[0] if result.dominant_vectors else "nominal"
        identity.vector_scores = result.vector_scores
        identity.last_scored_at = utcnow()
        if result.scored_events:
            identity.last_event_at = result.scored_events[-1].event.occurred_at

        # Write per-event scores back so the event table is queryable by score.
        by_id = {s.event.id: s for s in result.scored_events}
        if not by_id:
            return
        rows = (
            (await db.execute(select(SecurityEvent).where(SecurityEvent.id.in_(list(by_id))))).scalars().all()
        )
        # Count each (event, rule) pair exactly once, ever. The scheduler re-scores
        # the fleet every cycle, so a naive increment here would inflate match counts
        # without bound; diffing against what the row already records makes this
        # idempotent under repeated scoring of the same events.
        newly_matched: Counter[str] = Counter()

        for row in rows:
            scored = by_id[row.id]
            already_recorded = set(row.matched_rules or [])
            for slug in scored.matched_rules:
                if slug not in already_recorded:
                    newly_matched[slug] += 1

            row.anomaly_score = scored.raw_score
            row.damped_score = scored.damped_score
            row.vector_scores = scored.vector_scores
            row.is_damped = scored.is_damped
            row.damping_reason = scored.damping_reason
            row.matched_rules = scored.matched_rules

        if newly_matched:
            await self._record_rule_matches(db, newly_matched)

    @staticmethod
    async def _record_rule_matches(db: AsyncSession, counts: Counter[str]) -> None:
        """Update per-rule match statistics, which feed the tuning view."""
        rules = (
            (await db.execute(select(DetectionRule).where(DetectionRule.slug.in_(list(counts)))))
            .scalars()
            .all()
        )
        now = utcnow()
        for rule in rules:
            rule.match_count += counts[rule.slug]
            rule.last_matched_at = now

    # ------------------------------------------------------------------ loaders
    @staticmethod
    async def _load_events(db: AsyncSession, identity_id: str, *, since: datetime):
        rows = (
            (
                await db.execute(
                    select(SecurityEvent)
                    .where(SecurityEvent.identity_id == identity_id, SecurityEvent.occurred_at >= since)
                    .order_by(SecurityEvent.occurred_at)
                )
            )
            .scalars()
            .all()
        )
        return [adapters.to_event_view(r) for r in rows]

    @staticmethod
    async def _get_baseline_row(db: AsyncSession, identity_id: str) -> Baseline | None:
        return (
            await db.execute(select(Baseline).where(Baseline.identity_id == identity_id))
        ).scalar_one_or_none()

    @staticmethod
    async def _load_contexts(db: AsyncSession, identity_id: str):
        rows = (
            (
                await db.execute(
                    select(ContextRecord).where(
                        ContextRecord.identity_id == identity_id,
                        ContextRecord.is_active.is_(True),
                    )
                )
            )
            .scalars()
            .all()
        )
        return [adapters.to_context_view(r) for r in rows]

    @staticmethod
    async def _load_rules(db: AsyncSession):
        rows = (
            (await db.execute(select(DetectionRule).where(DetectionRule.enabled.is_(True)))).scalars().all()
        )
        return [adapters.to_rule_view(r) for r in rows]

    @staticmethod
    async def _load_indicators(db: AsyncSession):
        rows = (
            (await db.execute(select(ThreatIndicator).where(ThreatIndicator.is_active.is_(True))))
            .scalars()
            .all()
        )
        return {r.value: adapters.to_indicator_view(r) for r in rows}

    @staticmethod
    async def load_assets(db: AsyncSession):
        rows = (await db.execute(select(Asset))).scalars().all()
        return {r.key: adapters.to_asset_view(r) for r in rows}

    @staticmethod
    async def _watchlist_multiplier(db: AsyncSession, identity_id: str) -> float:
        """Watchlisted identities are scored more aggressively, multiplicatively."""
        rows = (await db.execute(select(Watchlist).where(Watchlist.is_active.is_(True)))).scalars().all()
        multiplier = 1.0
        for row in rows:
            if identity_id in (row.member_ids or []):
                multiplier *= row.risk_multiplier
        return min(multiplier, 2.0)

    @staticmethod
    async def events_in_last(db: AsyncSession, hours: int) -> int:
        since = utcnow() - timedelta(hours=hours)
        return int(
            (
                await db.execute(
                    select(func.count()).select_from(SecurityEvent).where(SecurityEvent.occurred_at >= since)
                )
            ).scalar_one()
        )


#: Process-wide singleton. The service holds no per-request state beyond the
#: peer cache, which is intentionally shared.
detection_service = DetectionService()
