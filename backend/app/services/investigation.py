"""Assembles the complete investigation payload for one identity.

Built as a single service call so the Investigator Workbench loads in one round
trip rather than a waterfall of six.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.base import utcnow
from app.db.models import ActionRecord, Alert, DetectionRule, Identity
from app.services import adapters
from app.services.detection import detection_service


class InvestigationService:
    """Read-only aggregation across the detection, response and catalogue tables."""

    async def build(self, db: AsyncSession, identity_id: str) -> dict:
        identity = await self._get_identity(db, identity_id)

        result = await detection_service.score_identity(db, identity, persist=False)
        baseline_row = await detection_service._get_baseline_row(db, identity.id)
        baseline = adapters.to_baseline_view(identity, baseline_row)
        contexts = await detection_service._load_contexts(db, identity.id)
        peer = await detection_service.peer_stats_for(db, identity)
        assets = await detection_service.load_assets(db)

        explanation = detection_service.explain_engine.explain(result, baseline, contexts=contexts, peer=peer)
        blast = detection_service.blast_engine.compute(
            identity.id,
            identity.username,
            identity.department,
            identity.role_title,
            [s.event for s in result.scored_events],
            assets,
            result.cumulative_risk,
            is_privileged=identity.is_privileged,
        )

        alerts = (
            (
                await db.execute(
                    select(Alert)
                    .where(Alert.identity_id == identity.id)
                    .order_by(Alert.created_at.desc())
                    .limit(10)
                )
            )
            .scalars()
            .all()
        )

        actions = (
            (
                await db.execute(
                    select(ActionRecord)
                    .where(ActionRecord.identity_id == identity.id)
                    .order_by(ActionRecord.created_at.desc())
                    .limit(20)
                )
            )
            .scalars()
            .all()
        )

        matched_rules = []
        if result.matched_rule_ids:
            rows = (
                (await db.execute(select(DetectionRule).where(DetectionRule.id.in_(result.matched_rule_ids))))
                .scalars()
                .all()
            )
            matched_rules = [
                {
                    "id": r.id,
                    "slug": r.slug,
                    "name": r.name,
                    "severity": str(r.severity),
                    "risk_boost": r.risk_boost,
                    "mitre_techniques": r.mitre_techniques,
                }
                for r in rows
            ]

        return {
            "identity": {
                "id": identity.id,
                "username": identity.username,
                "display_name": identity.display_name,
                "email": identity.email,
                "department": identity.department,
                "role_title": identity.role_title,
                "manager": identity.manager,
                "location": identity.location,
                "employment_type": identity.employment_type,
                "peer_group_id": identity.peer_group_id,
                "is_privileged": identity.is_privileged,
                "is_service_account": identity.is_service_account,
                "is_quarantined": identity.is_quarantined,
                "on_watchlist": identity.on_watchlist,
                "event_count": identity.event_count,
                "last_event_at": identity.last_event_at,
            },
            "risk_score": result.cumulative_risk,
            "raw_risk_score": result.raw_cumulative_risk,
            "transition_state": result.transition_state,
            "drift_velocity": result.drift_velocity,
            "peak_risk": result.peak_risk,
            "vector_scores": result.vector_scores,
            "dominant_vectors": result.dominant_vectors,
            "explanation": explanation.as_dict(),
            "blast_radius": blast,
            "timeline": result.timeline[-120:],
            "baseline": self._baseline_payload(baseline_row, baseline),
            "contexts": [
                {
                    "id": c.id,
                    "context_type": c.context_type,
                    "title": c.title,
                    "description": c.description,
                    "ticket_reference": c.ticket_reference,
                    "valid_from": c.valid_from,
                    "valid_until": c.valid_until,
                    "damping_factor": c.damping_factor,
                    "target_resources": c.target_resources,
                    "approved_by": c.approved_by,
                    "is_active": c.is_active,
                    "currently_covering": c.covers(utcnow()),
                }
                for c in contexts
            ],
            "alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": str(a.severity),
                    "status": str(a.status),
                    "risk_score": a.risk_score,
                    "created_at": a.created_at,
                    "occurrence_count": a.occurrence_count,
                    "case_id": a.case_id,
                }
                for a in alerts
            ],
            "actions": [
                {
                    "id": a.id,
                    "action": str(a.action),
                    "outcome": str(a.outcome),
                    "performed_by": a.performed_by_label,
                    "is_automated": a.is_automated,
                    "notes": a.notes,
                    "created_at": a.created_at,
                }
                for a in actions
            ],
            "matched_rules": matched_rules,
            "event_count": result.event_count,
            "generated_at": datetime.utcnow(),
        }

    async def copilot(self, db: AsyncSession, identity_id: str, question: str) -> dict:
        """Answer a question against a freshly assembled evidence bundle."""
        bundle = await self.build(db, identity_id)
        answer = detection_service.copilot_engine.answer(
            question, {"explanation": bundle["explanation"], "blast_radius": bundle["blast_radius"]}
        )
        return answer.as_dict()

    @staticmethod
    def _baseline_payload(row, view) -> dict | None:
        if row is None:
            return None
        return {
            "id": row.id,
            "hourly_distribution": view.hourly_distribution,
            "dow_distribution": view.dow_distribution,
            "common_resources": view.common_resources[:20],
            "known_countries": view.known_countries,
            "known_devices": view.known_devices,
            "resource_entropy": view.resource_entropy,
            "avg_daily_events": view.avg_daily_events,
            "stddev_daily_events": view.stddev_daily_events,
            "typical_max_sensitivity": view.typical_max_sensitivity,
            "off_hours_ratio": view.off_hours_ratio,
            "sample_event_count": view.sample_event_count,
            "maturity": view.maturity,
            "version": row.version,
            "window_start": row.window_start,
            "window_end": row.window_end,
            "updated_at": row.updated_at,
        }

    @staticmethod
    async def _get_identity(db: AsyncSession, identity_id: str) -> Identity:
        identity = (
            await db.execute(
                select(Identity).where((Identity.id == identity_id) | (Identity.username == identity_id))
            )
        ).scalar_one_or_none()
        if identity is None:
            raise NotFoundError(f"No identity matches '{identity_id}'.")
        return identity


investigation_service = InvestigationService()
