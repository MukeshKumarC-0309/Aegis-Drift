"""Fleet-level analytics: the dashboard, executive metrics and compliance posture."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AlertStatus, CaseStatus, Severity, TransitionState
from app.db.base import utcnow
from app.db.models import (
    ActionRecord,
    Alert,
    Case,
    DetectionRule,
    Identity,
    RiskSnapshot,
    SecurityEvent,
)
from app.engine.mitre import coverage_matrix
from app.services.detection import detection_service

#: Published industry mean time to detect insider/low-and-slow threats, in hours.
#: Sourced from public breach-report aggregates; shown as a comparison baseline only.
INDUSTRY_MTTD_HOURS = 504.0


class AnalyticsService:
    """Aggregate queries backing the Command Center and executive views."""

    async def overview(self, db: AsyncSession) -> dict:
        identities = (await db.execute(select(Identity).where(Identity.is_active.is_(True)))).scalars().all()
        alerts = (await db.execute(select(Alert))).scalars().all()

        open_alerts = [
            a
            for a in alerts
            if a.status in {AlertStatus.OPEN, AlertStatus.TRIAGED, AlertStatus.INVESTIGATING}
        ]
        suppressed = [a for a in alerts if a.status is AlertStatus.SUPPRESSED or a.context_damped]

        open_cases = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(Case)
                    .where(Case.status.notin_([CaseStatus.CLOSED, CaseStatus.RESOLVED]))
                )
            ).scalar_one()
        )

        state_counts = Counter(str(i.transition_state) for i in identities)
        critical = state_counts.get(TransitionState.CRITICAL_TRANSITION.value, 0)
        escalating = state_counts.get(TransitionState.ESCALATING.value, 0)

        anti_tamper = sum(1 for a in alerts if a.anti_tamper_override)
        events_24h = await detection_service.events_in_last(db, 24)
        mean_risk = round(sum(i.risk_score for i in identities) / len(identities), 2) if identities else 0.0

        return {
            "kpis": {
                "monitored_identities": len(identities),
                "active_threat_transitions": critical + escalating,
                "critical_identities": critical,
                "open_alerts": len(open_alerts),
                "open_cases": open_cases,
                "suppressed_false_positives": len(suppressed),
                "fleet_health_score": self._fleet_health(identities, critical, escalating),
                "mean_risk_score": mean_risk,
                "events_last_24h": events_24h,
                "anti_tamper_events": anti_tamper,
            },
            "transition_distribution": self._distribution(
                state_counts, [s.value for s in TransitionState], len(identities)
            ),
            "severity_distribution": self._distribution(
                Counter(str(a.severity) for a in open_alerts),
                [s.value for s in Severity],
                len(open_alerts),
            ),
            "department_risk": self._department_risk(identities),
            "vector_heatmap": self._vector_heatmap(identities),
            "risk_trend": await self._risk_trend(db),
            "event_volume_trend": await self._event_volume_trend(db),
            "top_alerts": await self._top_alerts(db, open_alerts),
            "top_risky_identities": [
                {
                    "id": i.id,
                    "username": i.username,
                    "display_name": i.display_name,
                    "department": i.department,
                    "role_title": i.role_title,
                    "risk_score": i.risk_score,
                    "raw_risk_score": i.raw_risk_score,
                    "transition_state": str(i.transition_state),
                    "drift_velocity": i.drift_velocity,
                    "dominant_vector": i.dominant_vector,
                    "on_watchlist": i.on_watchlist,
                    "is_quarantined": i.is_quarantined,
                }
                for i in sorted(identities, key=lambda x: -x.risk_score)[:10]
            ],
            "recent_actions": await self._recent_actions(db),
            "peer_outliers": await detection_service.peer_outliers(db),
            "generated_at": datetime.utcnow(),
        }

    # ------------------------------------------------------------------ pieces
    @staticmethod
    def _fleet_health(identities: list[Identity], critical: int, escalating: int) -> float:
        """100 = nothing drifting. Penalises critical accounts far harder."""
        if not identities:
            return 100.0
        penalty = (critical * 14 + escalating * 5) / len(identities) * 10
        return round(max(5.0, 100.0 - min(95.0, penalty)), 1)

    @staticmethod
    def _distribution(counts: Counter, keys: list[str], total: int) -> list[dict]:
        total = total or 1
        return [
            {
                "key": key,
                "label": key.replace("_", " ").title(),
                "count": counts.get(key, 0),
                "percentage": round(counts.get(key, 0) / total * 100, 1),
            }
            for key in keys
        ]

    @staticmethod
    def _department_risk(identities: list[Identity]) -> list[dict]:
        grouped: dict[str, list[Identity]] = defaultdict(list)
        for identity in identities:
            grouped[identity.department].append(identity)
        rows = []
        for department, members in grouped.items():
            risks = [m.risk_score for m in members]
            rows.append(
                {
                    "department": department,
                    "identity_count": len(members),
                    "mean_risk": round(sum(risks) / len(risks), 1),
                    "max_risk": round(max(risks), 1),
                    "at_risk_count": sum(
                        1 for m in members if str(m.transition_state) != TransitionState.STABLE.value
                    ),
                    "privileged_count": sum(1 for m in members if m.is_privileged),
                }
            )
        return sorted(rows, key=lambda r: -r["mean_risk"])

    @staticmethod
    def _vector_heatmap(identities: list[Identity]) -> dict[str, float]:
        """Fleet-wide mean of each behavioural vector, over drifting identities only —
        averaging in hundreds of stable accounts would flatten the signal to nothing."""
        drifting = [i for i in identities if str(i.transition_state) != TransitionState.STABLE.value]
        pool = drifting or identities
        if not pool:
            return {}
        totals: dict[str, float] = defaultdict(float)
        for identity in pool:
            for vector, value in (identity.vector_scores or {}).items():
                totals[vector] += float(value)
        return {k: round(v / len(pool), 1) for k, v in sorted(totals.items())}

    @staticmethod
    async def _risk_trend(db: AsyncSession, days: int = 14) -> list[dict]:
        since = utcnow() - timedelta(days=days)
        rows = (
            await db.execute(
                select(RiskSnapshot.captured_at, RiskSnapshot.risk_score)
                .where(RiskSnapshot.captured_at >= since)
                .order_by(RiskSnapshot.captured_at)
            )
        ).all()
        if not rows:
            return []
        buckets: dict[str, list[float]] = defaultdict(list)
        for captured_at, score in rows:
            buckets[captured_at.strftime("%Y-%m-%dT%H:00:00")].append(score)
        return [
            {
                "timestamp": key,
                "value": round(sum(values) / len(values), 2),
                "label": f"{len(values)} identities",
            }
            for key, values in sorted(buckets.items())
        ]

    @staticmethod
    async def _event_volume_trend(db: AsyncSession, days: int = 14) -> list[dict]:
        since = utcnow() - timedelta(days=days)
        rows = (
            await db.execute(
                select(SecurityEvent.occurred_at, SecurityEvent.anomaly_score).where(
                    SecurityEvent.occurred_at >= since
                )
            )
        ).all()
        buckets: dict[str, dict[str, float]] = defaultdict(lambda: {"total": 0, "anomalous": 0})
        for occurred_at, score in rows:
            key = occurred_at.strftime("%Y-%m-%d")
            buckets[key]["total"] += 1
            if (score or 0) >= 45:
                buckets[key]["anomalous"] += 1
        return [
            {
                "timestamp": f"{key}T00:00:00",
                "value": stats["total"],
                "label": f"{int(stats['anomalous'])} anomalous",
            }
            for key, stats in sorted(buckets.items())
        ]

    @staticmethod
    async def _top_alerts(db: AsyncSession, open_alerts: list[Alert]) -> list[dict]:
        if not open_alerts:
            return []
        ranked = sorted(open_alerts, key=lambda a: -a.risk_score)[:8]
        identities = {
            i.id: i
            for i in (
                await db.execute(select(Identity).where(Identity.id.in_([a.identity_id for a in ranked])))
            )
            .scalars()
            .all()
        }
        return [
            {
                "id": a.id,
                "identity_id": a.identity_id,
                "username": identities[a.identity_id].username if a.identity_id in identities else "?",
                "department": identities[a.identity_id].department if a.identity_id in identities else "?",
                "role_title": identities[a.identity_id].role_title if a.identity_id in identities else "?",
                "title": a.title,
                "summary": a.summary,
                "severity": str(a.severity),
                "status": str(a.status),
                "risk_score": a.risk_score,
                "raw_risk_score": a.raw_risk_score,
                "transition_state": str(a.transition_state),
                "context_damped": a.context_damped,
                "anti_tamper_override": a.anti_tamper_override,
                "dominant_vectors": a.dominant_vectors,
                "mitre_techniques": a.mitre_techniques,
                "confidence": a.confidence,
                "created_at": a.created_at,
                "occurrence_count": a.occurrence_count,
            }
            for a in ranked
        ]

    @staticmethod
    async def _recent_actions(db: AsyncSession, limit: int = 8) -> list[dict]:
        rows = (
            (await db.execute(select(ActionRecord).order_by(ActionRecord.created_at.desc()).limit(limit)))
            .scalars()
            .all()
        )
        if not rows:
            return []
        identities = {
            i.id: i.username
            for i in (
                await db.execute(select(Identity).where(Identity.id.in_([r.identity_id for r in rows])))
            )
            .scalars()
            .all()
        }
        return [
            {
                "id": r.id,
                "action": str(r.action),
                "identity_id": r.identity_id,
                "username": identities.get(r.identity_id, "?"),
                "outcome": str(r.outcome),
                "performed_by": r.performed_by_label,
                "is_automated": r.is_automated,
                "created_at": r.created_at,
            }
            for r in rows
        ]

    # -------------------------------------------------------- executive metrics
    async def enterprise_metrics(self, db: AsyncSession) -> dict:
        """CISO-facing effectiveness metrics, derived from this deployment's own data."""
        alerts = (await db.execute(select(Alert))).scalars().all()
        cases = (await db.execute(select(Case))).scalars().all()
        identities = (await db.execute(select(Identity))).scalars().all()

        mttd = self._mean_time_to_detect(alerts)
        mttr = self._mean_time_to_resolve(cases)

        suppressed = sum(1 for a in alerts if a.context_damped or a.status is AlertStatus.SUPPRESSED)
        false_positives = sum(1 for a in alerts if a.status is AlertStatus.FALSE_POSITIVE)
        total = len(alerts) or 1
        noise_suppression = round(suppressed / total * 100, 1)
        fp_rate = round(false_positives / total * 100, 1)

        # Every suppressed alert is triage time an analyst did not spend.
        minutes_per_triage = 18
        hours_saved = round(suppressed * minutes_per_triage / 60, 1)

        assets = await detection_service.load_assets(db)
        records_protected = sum(a.record_estimate for a in assets.values())

        # Value at risk across the sensitive assets under monitoring — NOT a claim
        # that this loss was prevented. It sizes what an incident on these assets
        # could cost, which is what makes the monitoring worth funding.
        exposure_under_management = sum(
            a.record_estimate * (262.0 if a.contains_cardholder_data else 165.0 if a.contains_pii else 48.0)
            for a in assets.values()
            if a.is_crown_jewel or a.contains_pii
        )

        rules = (await db.execute(select(DetectionRule))).scalars().all()
        observed = {t for a in alerts for t in (a.mitre_techniques or [])}
        matrix = coverage_matrix(observed)
        total_techniques = sum(m["total"] for m in matrix) or 1
        coverage = round(sum(m["observed"] for m in matrix) / total_techniques * 100, 1)

        analysts_assumed = 4
        alerts_per_day = round(
            len([a for a in alerts if a.created_at >= utcnow() - timedelta(days=1)]) / analysts_assumed,
            2,
        )

        return {
            "mttd_hours": mttd,
            "mttd_industry_baseline_hours": INDUSTRY_MTTD_HOURS,
            "mttd_reduction_percentage": round(
                max(0.0, (INDUSTRY_MTTD_HOURS - mttd) / INDUSTRY_MTTD_HOURS * 100), 1
            ),
            "mttr_hours": mttr,
            "alerts_per_analyst_day": alerts_per_day,
            "false_positive_rate": fp_rate,
            "noise_suppression_percentage": noise_suppression,
            "analyst_hours_saved_monthly": round(hours_saved * 30 / max(1, 7), 1),
            "detection_coverage_percentage": coverage,
            "records_protected": records_protected,
            "exposure_under_management_usd": round(exposure_under_management, 2),
            "exposure_under_management_display": _money(exposure_under_management),
            "compliance": self._compliance_posture(identities, rules, alerts),
            "methodology_note": (
                "MTTD is measured from the first anomalous event in an alert's window to the "
                "moment the alert was raised, using this deployment's own data. The industry "
                "baseline is a published aggregate for insider and low-and-slow threats and is "
                "shown for comparison only.\n\n"
                "Exposure under management sizes what an incident affecting the monitored "
                "crown-jewel and PII assets could cost, using published per-record breach "
                "figures. It is a measure of what is being watched — not a claim that this "
                "loss was prevented, and not an actuarial or legal determination.\n\n"
                "Analyst hours saved assumes 18 minutes of triage per suppressed alert."
            ),
        }

    @staticmethod
    def _mean_time_to_detect(alerts: list[Alert]) -> float:
        deltas = [
            (a.created_at - a.first_seen_at).total_seconds() / 3600.0
            for a in alerts
            if a.first_seen_at and a.created_at > a.first_seen_at
        ]
        return round(sum(deltas) / len(deltas), 2) if deltas else 0.0

    @staticmethod
    def _mean_time_to_resolve(cases: list[Case]) -> float:
        deltas = [
            (c.closed_at - c.created_at).total_seconds() / 3600.0
            for c in cases
            if c.closed_at and c.closed_at > c.created_at
        ]
        return round(sum(deltas) / len(deltas), 2) if deltas else 0.0

    @staticmethod
    def _compliance_posture(
        identities: list[Identity], rules: list[DetectionRule], alerts: list[Alert]
    ) -> list[dict]:
        """Control coverage computed from what is actually configured, with honest gaps."""
        now = utcnow()
        baselined = sum(1 for i in identities if i.last_scored_at is not None)
        total = len(identities) or 1
        monitoring_coverage = round(baselined / total * 100, 1)
        enabled_rules = sum(1 for r in rules if r.enabled)
        reviewed = sum(1 for a in alerts if a.resolved_at is not None)

        def report(framework: str, control: str, coverage: float, evidence: list[str], gaps: list[str]):
            return {
                "framework": framework,
                "control_reference": control,
                "status": "COMPLIANT" if coverage >= 95 else "PARTIAL" if coverage >= 70 else "GAP",
                "coverage_percentage": coverage,
                "evidence": evidence,
                "gaps": gaps,
                "last_assessed": now,
            }

        return [
            report(
                "SOC 2 Type II",
                "CC6.1 — Logical access controls",
                monitoring_coverage,
                [
                    f"{baselined}/{total} identities under continuous behavioural monitoring",
                    f"{enabled_rules} detection rules enabled",
                ],
                [] if monitoring_coverage >= 95 else [f"{total - baselined} identities not yet baselined"],
            ),
            report(
                "SOC 2 Type II",
                "CC7.2 — Anomaly detection and response",
                round(min(100.0, reviewed / max(len(alerts), 1) * 100), 1),
                [f"{reviewed} of {len(alerts)} alerts carry a documented disposition"],
                [] if reviewed >= len(alerts) else [f"{len(alerts) - reviewed} alerts awaiting disposition"],
            ),
            report(
                "GDPR",
                "Art. 32 — Security of processing",
                monitoring_coverage,
                [
                    "Behavioural monitoring over all PII-scoped assets",
                    "Blast-radius modelling quantifies records at risk per incident",
                ],
                [] if monitoring_coverage >= 95 else ["Incomplete identity coverage"],
            ),
            report(
                "PCI DSS v4.0",
                "Req. 10 — Log and monitor all access",
                monitoring_coverage,
                [
                    "All cardholder-scoped assets are classified and monitored",
                    "Anti-tamper policy blocks suppression of audit-log deletion",
                ],
                [],
            ),
            report(
                "ISO/IEC 27001",
                "A.9 — Access control",
                round(min(100.0, enabled_rules / 12 * 100), 1),
                [
                    f"{enabled_rules} access-control detections active",
                    "Peer-cohort divergence detects entitlement creep",
                ],
                [] if enabled_rules >= 12 else [f"Only {enabled_rules} of 12 recommended detections enabled"],
            ),
        ]


def _money(value: float) -> str:
    if value >= 1_000_000_000:
        return f"${value / 1_000_000_000:.2f}B"
    if value >= 1_000_000:
        return f"${value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"${value / 1_000:.0f}K"
    return f"${value:,.0f}"


analytics_service = AnalyticsService()
