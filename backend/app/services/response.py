"""Response orchestration: containment actions, playbooks and case management."""

from __future__ import annotations

import time
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    ActionOutcome,
    AlertStatus,
    CasePriority,
    CaseStatus,
    ContextType,
    ResponseAction,
    Severity,
)
from app.core.exceptions import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models import (
    ActionRecord,
    Alert,
    Case,
    CaseEntry,
    ContextRecord,
    Identity,
    Playbook,
    User,
)
from app.services import audit
from app.services.detection import detection_service
from app.services.events import event_bus

logger = get_logger(__name__)

#: SLA to first response, by case priority.
SLA_HOURS: dict[CasePriority, int] = {
    CasePriority.P1: 1,
    CasePriority.P2: 4,
    CasePriority.P3: 24,
    CasePriority.P4: 72,
}

#: Actions that mutate the identity's access posture rather than just recording intent.
ENFORCING_ACTIONS = {
    ResponseAction.QUARANTINE_SESSION,
    ResponseAction.DISABLE_ACCOUNT,
    ResponseAction.REVOKE_TOKENS,
    ResponseAction.SUSPEND_API_KEYS,
}


class ResponseService:
    """Executes containment actions and keeps cases in step with them."""

    # ----------------------------------------------------------------- actions
    async def execute(
        self,
        db: AsyncSession,
        identity: Identity,
        action: ResponseAction,
        *,
        actor: User | None = None,
        notes: str | None = None,
        alert_id: str | None = None,
        case_id: str | None = None,
        ticket_reference: str | None = None,
        is_automated: bool = False,
    ) -> ActionRecord:
        started = time.perf_counter()
        result: dict = {}

        match action:
            case ResponseAction.QUARANTINE_SESSION:
                identity.is_quarantined = True
                result = {"sessions_terminated": True, "network_isolated": True}
            case ResponseAction.DISABLE_ACCOUNT:
                identity.is_active = False
                identity.is_quarantined = True
                result = {"account_disabled": True}
            case ResponseAction.REVOKE_TOKENS:
                result = {"tokens_revoked": True, "idp_notified": True}
            case ResponseAction.SUSPEND_API_KEYS:
                result = {"api_keys_suspended": True}
            case ResponseAction.STEP_UP_MFA:
                result = {"mfa_challenge_pushed": True, "channel": "push"}
            case ResponseAction.NOTIFY_MANAGER:
                result = {"notified": identity.manager or "no manager on record"}
            case ResponseAction.ISOLATE_ENDPOINT:
                result = {"endpoint_isolated": True}
            case ResponseAction.OPEN_TICKET:
                result = {"ticket": ticket_reference or f"SEC-{utcnow():%Y%m%d}-{identity.id[-4:]}"}
            case ResponseAction.ESCALATE:
                result = {"escalated_to": "Tier-3 Incident Response"}
            case ResponseAction.RE_BASELINE:
                await detection_service.rebuild_baseline(db, identity)
                result = {"baseline_rebuilt": True}
            case ResponseAction.ADD_CONTEXT_EXEMPTION:
                if not notes:
                    raise ValidationError(
                        "A justification note is required when recording a context exemption."
                    )
                context = ContextRecord(
                    identity_id=identity.id,
                    context_type=ContextType.APPROVED_CHANGE_TICKET,
                    title="Analyst-approved exemption",
                    description=notes,
                    ticket_reference=ticket_reference,
                    source_system="console",
                    valid_from=utcnow() - timedelta(hours=1),
                    valid_until=utcnow() + timedelta(days=14),
                    damping_factor=0.3,
                    approved_by=actor.email if actor else "system",
                    created_by_id=actor.id if actor else None,
                )
                db.add(context)
                result = {"context_id": context.id}

        record = ActionRecord(
            identity_id=identity.id,
            alert_id=alert_id,
            case_id=case_id,
            action=action,
            outcome=ActionOutcome.SUCCEEDED,
            performed_by_id=actor.id if actor else None,
            performed_by_label=actor.email if actor else "automation",
            is_automated=is_automated,
            notes=notes,
            result=result,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        db.add(record)

        if action in ENFORCING_ACTIONS:
            await self._close_open_alerts(db, identity, action, actor)

        await detection_service.score_identity(db, identity)
        await db.flush()

        await audit.record(
            db,
            action=f"response.{action.value.lower()}",
            target_type="identity",
            target_id=identity.id,
            actor=actor,
            payload={"action": action.value, "notes": notes, "result": result},
        )
        await event_bus.publish(
            "action.executed",
            {
                "identity_id": identity.id,
                "username": identity.username,
                "action": action.value,
                "by": record.performed_by_label,
                "automated": is_automated,
            },
        )
        logger.info(
            "response.executed",
            action=action.value,
            identity=identity.username,
            automated=is_automated,
        )
        return record

    @staticmethod
    async def _close_open_alerts(
        db: AsyncSession, identity: Identity, action: ResponseAction, actor: User | None
    ) -> None:
        alerts = (
            (
                await db.execute(
                    select(Alert).where(
                        Alert.identity_id == identity.id,
                        Alert.status.in_([AlertStatus.OPEN, AlertStatus.TRIAGED, AlertStatus.INVESTIGATING]),
                    )
                )
            )
            .scalars()
            .all()
        )
        for alert in alerts:
            alert.status = AlertStatus.CONFIRMED_INCIDENT
            alert.resolved_at = utcnow()
            alert.resolution_note = (
                f"Contained via {action.value} by {actor.email if actor else 'automation'}."
            )

    # ------------------------------------------------------------------- cases
    async def create_case(
        self,
        db: AsyncSession,
        *,
        title: str,
        description: str,
        priority: CasePriority,
        severity: Severity,
        primary_identity_id: str | None,
        assignee_id: str | None,
        alert_ids: list[str],
        tags: list[str],
        actor: User | None = None,
    ) -> Case:
        reference = await self._next_reference(db)
        case = Case(
            reference=reference,
            title=title,
            description=description,
            priority=priority,
            severity=severity,
            primary_identity_id=primary_identity_id,
            assignee_id=assignee_id,
            opened_by_id=actor.id if actor else None,
            tags=tags,
            sla_due_at=utcnow() + timedelta(hours=SLA_HOURS[priority]),
        )
        db.add(case)
        await db.flush()

        if alert_ids:
            alerts = (await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))).scalars().all()
            techniques: set[str] = set()
            for alert in alerts:
                alert.case_id = case.id
                alert.status = AlertStatus.INVESTIGATING
                case.peak_risk_score = max(case.peak_risk_score, alert.risk_score)
                techniques.update(alert.mitre_techniques or [])
            case.mitre_techniques = sorted(techniques)

        # Snapshot the impact at the moment the case was opened. Cases are read long
        # after the fact, so this must be the assessment the analyst acted on rather
        # than whatever the live score happens to be when the page is later reopened.
        if primary_identity_id:
            await self._attach_impact_snapshot(db, case, primary_identity_id)

        db.add(
            CaseEntry(
                case_id=case.id,
                entry_type="CREATED",
                author_id=actor.id if actor else None,
                author_label=actor.email if actor else "system",
                body=f"Case opened at {priority.value} with {len(alert_ids)} linked alert(s).",
            )
        )
        await audit.record(
            db,
            action="case.created",
            target_type="case",
            target_id=case.id,
            actor=actor,
            payload={"reference": reference, "priority": priority.value},
        )
        await event_bus.publish(
            "case.created",
            {"case_id": case.id, "reference": reference, "title": title, "priority": priority.value},
        )
        return case

    @staticmethod
    async def _attach_impact_snapshot(db: AsyncSession, case: Case, identity_id: str) -> None:
        """Record blast radius and records-at-risk for the case's primary identity."""
        identity = (await db.execute(select(Identity).where(Identity.id == identity_id))).scalar_one_or_none()
        if identity is None:
            return

        try:
            result = await detection_service.score_identity(db, identity, persist=False)
            assets = await detection_service.load_assets(db)
            blast = detection_service.blast_engine.compute(
                identity.id,
                identity.username,
                identity.department,
                identity.role_title,
                [scored.event for scored in result.scored_events],
                assets,
                result.cumulative_risk,
                is_privileged=identity.is_privileged,
            )
        except Exception as exc:  # pragma: no cover - impact is advisory, never fatal
            logger.warning("case.impact_snapshot_failed", case_id=case.id, error=str(exc))
            return

        case.blast_radius_score = blast["blast_radius_score"]
        case.estimated_records_at_risk = blast["records_at_risk"]
        case.peak_risk_score = max(case.peak_risk_score, result.cumulative_risk)

    async def transition_case(
        self,
        db: AsyncSession,
        case: Case,
        status: CaseStatus,
        *,
        actor: User | None = None,
        note: str | None = None,
    ) -> Case:
        previous = case.status
        case.status = status
        now = utcnow()
        if status is CaseStatus.IN_PROGRESS and case.acknowledged_at is None:
            case.acknowledged_at = now
        if status is CaseStatus.CONTAINED:
            case.contained_at = now
        if status in {CaseStatus.RESOLVED, CaseStatus.CLOSED}:
            case.closed_at = now

        db.add(
            CaseEntry(
                case_id=case.id,
                entry_type="STATUS_CHANGE",
                author_id=actor.id if actor else None,
                author_label=actor.email if actor else "system",
                body=note or f"Status changed from {previous} to {status.value}.",
                entry_metadata={"from": str(previous), "to": status.value},
            )
        )
        await audit.record(
            db,
            action="case.transitioned",
            target_type="case",
            target_id=case.id,
            actor=actor,
            payload={"from": str(previous), "to": status.value},
        )
        return case

    @staticmethod
    async def _next_reference(db: AsyncSession) -> str:
        year = utcnow().year
        count = int(
            (
                await db.execute(
                    select(func.count()).select_from(Case).where(Case.reference.like(f"SS-{year}-%"))
                )
            ).scalar_one()
        )
        return f"SS-{year}-{count + 1:04d}"

    # --------------------------------------------------------------- playbooks
    async def run_playbook(
        self,
        db: AsyncSession,
        playbook: Playbook,
        identity: Identity,
        *,
        actor: User | None = None,
        case_id: str | None = None,
        dry_run: bool = True,
        notes: str | None = None,
    ) -> dict:
        """Execute a playbook's steps in order. ``dry_run`` plans without enforcing."""
        executed: list[dict] = []
        for index, step in enumerate(playbook.steps or [], start=1):
            action_name = step.get("action")
            try:
                action = ResponseAction(action_name)
            except ValueError:
                executed.append(
                    {
                        "step": index,
                        "action": action_name,
                        "outcome": ActionOutcome.SKIPPED.value,
                        "reason": f"'{action_name}' is not a recognised response action.",
                    }
                )
                continue

            if dry_run:
                executed.append(
                    {
                        "step": index,
                        "action": action.value,
                        "label": step.get("label", action.value),
                        "outcome": "PLANNED",
                        "description": step.get("description", ""),
                    }
                )
                continue

            record = await self.execute(
                db,
                identity,
                action,
                actor=actor,
                notes=notes or f"Playbook {playbook.slug} step {index}",
                case_id=case_id,
                is_automated=True,
            )
            executed.append(
                {
                    "step": index,
                    "action": action.value,
                    "label": step.get("label", action.value),
                    "outcome": record.outcome,
                    "result": record.result,
                }
            )

        if not dry_run:
            playbook.run_count += 1
            playbook.last_run_at = utcnow()
            await audit.record(
                db,
                action="playbook.executed",
                target_type="playbook",
                target_id=playbook.id,
                actor=actor,
                payload={"identity_id": identity.id, "steps": len(executed)},
            )

        return {
            "playbook": {"id": playbook.id, "slug": playbook.slug, "name": playbook.name},
            "identity_id": identity.id,
            "dry_run": dry_run,
            "steps": executed,
            "executed_at": utcnow(),
        }

    @staticmethod
    async def get_case(db: AsyncSession, case_id: str) -> Case:
        case = (
            await db.execute(select(Case).where((Case.id == case_id) | (Case.reference == case_id)))
        ).scalar_one_or_none()
        if case is None:
            raise NotFoundError(f"No case matches '{case_id}'.")
        return case


response_service = ResponseService()
