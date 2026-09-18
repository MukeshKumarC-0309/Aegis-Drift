"""Threat scenario simulator and synthetic telemetry generator.

Provides the demonstrable, reproducible attack narratives the platform is evaluated
against. Each scenario declares the outcome it *expects*, and the runner reports
whether the engine actually produced it — so the simulator doubles as a live
regression harness rather than a scripted demo.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import EventType, TransitionState
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models import Identity
from app.schemas.domain import EventIngest
from app.services.detection import detection_service
from app.services.ingest import ingest_service

logger = get_logger(__name__)


@dataclass(slots=True)
class ScenarioStep:
    """One event in a scenario, positioned relative to "now"."""

    hours_ago: float
    event_type: EventType
    resource: str
    action: str
    sensitivity: int = 1
    off_hours: bool = False
    ip: str = "192.168.1.105"
    country: str = "US"
    latitude: float | None = 37.77
    longitude: float | None = -122.42
    device: str | None = "dev-laptop-01"
    bytes_transferred: int = 0
    records: int = 0
    outcome: str = "SUCCESS"
    tags: list[str] = field(default_factory=list)


#: Transition states in ascending severity, for ordinal comparison.
STATE_ORDER: tuple[TransitionState, ...] = (
    TransitionState.STABLE,
    TransitionState.EARLY_DRIFT,
    TransitionState.ESCALATING,
    TransitionState.CRITICAL_TRANSITION,
)


@dataclass(slots=True)
class Scenario:
    id: str
    title: str
    subtitle: str
    narrative: str
    username: str
    expected_state: TransitionState
    expected_outcome: str
    teaches: str
    steps: list[ScenarioStep]
    #: Suppression scenarios must land on exactly ``expected_state``. Threat scenarios
    #: assert a *minimum* severity, so tightening the engine never fails the harness.
    expect_exact: bool = False

    def matches(self, actual: TransitionState) -> bool:
        if self.expect_exact:
            return actual is self.expected_state
        return STATE_ORDER.index(actual) >= STATE_ORDER.index(self.expected_state)

    @property
    def duration_days(self) -> int:
        if not self.steps:
            return 0
        return max(1, int(max(s.hours_ago for s in self.steps) / 24))

    def summary(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "subtitle": self.subtitle,
            "narrative": self.narrative,
            "target_username": self.username,
            "expected_outcome": self.expected_outcome,
            "expected_state": self.expected_state,
            "expect_exact": self.expect_exact,
            "teaches": self.teaches,
            "event_count": len(self.steps),
            "duration_days": self.duration_days,
        }


SCENARIOS: dict[str, Scenario] = {
    "slow_poisoner": Scenario(
        id="slow_poisoner",
        title="The Slow Poisoner",
        subtitle="Low-and-slow insider exfiltration over five days",
        narrative=(
            "A senior frontend engineer with no history of touching data systems begins "
            "logging in after midnight, reads the customer PII schema, works outward to the "
            "production replica, and finally bulk-exports a crown-jewel dataset. No single "
            "step would clear a per-event threshold. The sequence is unmistakable."
        ),
        username="alex.mercer",
        expected_state=TransitionState.CRITICAL_TRANSITION,
        expected_outcome="Cumulative risk crosses the critical threshold; containment recommended.",
        teaches="Sequence correlation catches drift that per-event rules structurally cannot.",
        steps=[
            ScenarioStep(96, EventType.AUTHENTICATION, "sso_okta_gateway", "login", 2, True),
            ScenarioStep(94, EventType.FILE_ACCESS, "internal_schema_docs_customer_pii", "read", 3, True),
            ScenarioStep(72, EventType.FILE_ACCESS, "internal_schema_docs_customer_pii", "read", 3),
            ScenarioStep(70, EventType.API_CALL, "prod_customer_sql_replica", "query", 4, True),
            ScenarioStep(
                48, EventType.API_CALL, "prod_customer_sql_replica", "query_bulk", 4, True, records=48_000
            ),
            ScenarioStep(
                26, EventType.API_CALL, "prod_payment_vault_metadata", "query_bulk", 4, True, records=12_000
            ),
            ScenarioStep(
                6,
                EventType.NETWORK_EGRESS,
                "crown_jewel_customer_pii_export",
                "export_all",
                5,
                True,
                bytes_transferred=890_000_000,
                records=2_400_000,
            ),
        ],
    ),
    "compromised_admin": Scenario(
        id="compromised_admin",
        title="The Compromised Admin",
        subtitle="Credential takeover, privilege escalation and audit tampering",
        narrative=(
            "A DevOps lead's credentials authenticate from Bucharest four hours after a "
            "San Francisco session — a physically impossible journey. The session assumes an "
            "auditor role, attaches an admin policy, and deletes the CloudTrail stream. An "
            "active on-call approval covers her production access; it does not, and cannot, "
            "cover destroying the audit trail."
        ),
        username="sarah.connor",
        expected_state=TransitionState.CRITICAL_TRANSITION,
        expected_outcome="Anti-tamper override fires despite an active on-call context.",
        teaches="Approved context must never be able to suppress evidence destruction.",
        steps=[
            ScenarioStep(
                8,
                EventType.AUTHENTICATION,
                "aws_management_console",
                "login",
                3,
                False,
                ip="10.20.4.11",
                country="US",
                latitude=37.77,
                longitude=-122.42,
            ),
            ScenarioStep(
                4,
                EventType.AUTHENTICATION,
                "aws_management_console",
                "login",
                3,
                True,
                ip="185.220.101.5",
                country="RO",
                latitude=44.43,
                longitude=26.10,
                device="unknown-device",
            ),
            ScenarioStep(
                3.2,
                EventType.PRIVILEGE_ACTION,
                "iam_role_security_auditor",
                "assume_role",
                4,
                True,
                ip="185.220.101.5",
                country="RO",
                latitude=44.43,
                longitude=26.10,
                device="unknown-device",
            ),
            ScenarioStep(
                2.1,
                EventType.ROLE_MODIFICATION,
                "aws_iam_policy_admin_attach",
                "iam_modify",
                5,
                True,
                ip="185.220.101.5",
                country="RO",
                latitude=44.43,
                longitude=26.10,
                device="unknown-device",
            ),
            ScenarioStep(
                0.8,
                EventType.API_CALL,
                "cloudtrail_audit_log_stream",
                "delete_audit_logs",
                5,
                True,
                ip="185.220.101.5",
                country="RO",
                latitude=44.43,
                longitude=26.10,
                device="unknown-device",
            ),
        ],
    ),
    "project_switcher": Scenario(
        id="project_switcher",
        title="The Legitimate Project Switcher",
        subtitle="Context-aware false-positive suppression",
        narrative=(
            "A cloud architect is assigned to lead a data-lake migration and starts touching "
            "Tier-4 warehouses she has never accessed. Statistically this is indistinguishable "
            "from staged exfiltration. An approved change ticket scoped to exactly those "
            "resources damps the score, and the analyst is never paged."
        ),
        username="priya.patel",
        expected_state=TransitionState.STABLE,
        expected_outcome="Raw risk is high; damped risk stays below the alerting threshold.",
        teaches="Suppressing known-good change is what makes the remaining alerts worth reading.",
        expect_exact=True,
        steps=[
            ScenarioStep(
                54, EventType.FILE_ACCESS, "prod_datalake_s3", "read", 4, tags=["ticket:CHG-2024-9182"]
            ),
            ScenarioStep(
                50,
                EventType.API_CALL,
                "snowflake_titan_lake",
                "query",
                4,
                tags=["ticket:CHG-2024-9182"],
                records=20_000,
            ),
            ScenarioStep(
                28,
                EventType.API_CALL,
                "customer_analytics_warehouse",
                "read",
                4,
                tags=["ticket:CHG-2024-9182"],
            ),
            ScenarioStep(
                22,
                EventType.API_CALL,
                "snowflake_titan_lake",
                "query_bulk",
                4,
                tags=["ticket:CHG-2024-9182"],
                records=90_000,
            ),
            ScenarioStep(
                5, EventType.FILE_ACCESS, "prod_datalake_s3", "write", 4, tags=["ticket:CHG-2024-9182"]
            ),
        ],
    ),
    "privilege_creep": Scenario(
        id="privilege_creep",
        title="Privilege Creep",
        subtitle="Gradual entitlement accumulation toward org-admin",
        narrative=(
            "A data scientist requests a service-account token, then reads secret-manager "
            "keys, then escalates to organisation admin — each step individually defensible, "
            "the trajectory not. Peer divergence carries this one: no other analyst in the "
            "cohort holds anything close to these entitlements."
        ),
        username="elena.rostova",
        expected_state=TransitionState.CRITICAL_TRANSITION,
        expected_outcome=(
            "Peer divergence and privilege vectors dominate; the terminal escalation to "
            "organisation admin is itself sufficient for a critical verdict."
        ),
        teaches="The cohort is the control group that makes entitlement creep visible.",
        steps=[
            ScenarioStep(120, EventType.PRIVILEGE_ACTION, "gcp_iam_service_account_token", "assume_role", 3),
            ScenarioStep(
                96, EventType.PRIVILEGE_ACTION, "gcp_iam_service_account_token", "create_access_key", 3
            ),
            ScenarioStep(60, EventType.SECRET_ACCESS, "gcp_secret_manager_db_keys", "read", 4),
            ScenarioStep(36, EventType.SECRET_ACCESS, "gcp_secret_manager_db_keys", "read", 4, True),
            ScenarioStep(
                14,
                EventType.ROLE_MODIFICATION,
                "gcp_resourcemanager_organization_admin",
                "grant_permission",
                5,
                True,
            ),
            ScenarioStep(
                5, EventType.PRIVILEGE_ACTION, "gcp_resourcemanager_organization_admin", "sudo", 5, True
            ),
        ],
    ),
    "impossible_travel": Scenario(
        id="impossible_travel",
        title="Impossible Travel",
        subtitle="Concurrent sessions from two continents",
        narrative=(
            "An SRE authenticates from Dublin twenty minutes after a Singapore session — "
            "roughly 11,000 km apart, an implied speed of 33,000 km/h. Geo-velocity alone is "
            "conclusive; no behavioural history is needed to know one session is not them."
        ),
        username="liam.smith",
        expected_state=TransitionState.ESCALATING,
        expected_outcome="Geo-velocity vector saturates on the physically impossible pair.",
        teaches="Some signals are decisive on their own and need no accumulation.",
        steps=[
            ScenarioStep(
                3.4,
                EventType.AUTHENTICATION,
                "bastion_host_eu",
                "login",
                3,
                ip="103.21.44.9",
                country="SG",
                latitude=1.35,
                longitude=103.82,
            ),
            ScenarioStep(
                3.0,
                EventType.AUTHENTICATION,
                "bastion_host_eu",
                "login",
                3,
                ip="89.101.4.77",
                country="IE",
                latitude=53.35,
                longitude=-6.26,
                device="unknown-device",
            ),
            ScenarioStep(
                2.5,
                EventType.PRIVILEGE_ACTION,
                "kubernetes_cluster_prod",
                "sudo",
                4,
                ip="89.101.4.77",
                country="IE",
                latitude=53.35,
                longitude=-6.26,
                device="unknown-device",
            ),
            ScenarioStep(
                1.2,
                EventType.SECRET_ACCESS,
                "prod_ssh_keys_vault",
                "read",
                5,
                ip="89.101.4.77",
                country="IE",
                latitude=53.35,
                longitude=-6.26,
                device="unknown-device",
            ),
        ],
    ),
    "departing_employee": Scenario(
        id="departing_employee",
        title="The Departing Employee",
        subtitle="Bulk collection ahead of a resignation",
        narrative=(
            "An account executive who resigned last week downloads the full CRM pipeline, "
            "the pricing playbook and the customer contact list, then shares a folder "
            "externally. Volume anomaly and external sharing carry this one — and HR context "
            "makes the timing the most damning part of it."
        ),
        username="noah.garcia",
        expected_state=TransitionState.CRITICAL_TRANSITION,
        expected_outcome=(
            "Volume and resource vectors flag the staged collection, and the external "
            "share of 130k customer records closes it out as critical."
        ),
        teaches="Departure risk is a volume problem, and volume needs a per-identity baseline.",
        steps=[
            ScenarioStep(
                50,
                EventType.DATA_EXPORT,
                "salesforce_crm_pipeline",
                "export",
                3,
                records=42_000,
                bytes_transferred=180_000_000,
            ),
            ScenarioStep(
                46,
                EventType.FILE_ACCESS,
                "pricing_playbook_confidential",
                "download",
                4,
                bytes_transferred=24_000_000,
            ),
            ScenarioStep(
                30,
                EventType.DATA_EXPORT,
                "customer_contact_master_list",
                "export",
                4,
                records=88_000,
                bytes_transferred=210_000_000,
            ),
            ScenarioStep(
                20,
                EventType.FILE_ACCESS,
                "quarterly_budget_sheets",
                "download",
                3,
                bytes_transferred=8_000_000,
            ),
            ScenarioStep(
                4,
                EventType.NETWORK_EGRESS,
                "gdrive_external_share",
                "share_external",
                4,
                True,
                bytes_transferred=420_000_000,
                records=130_000,
            ),
        ],
    ),
}


class SimulatorService:
    """Runs scenarios against the live pipeline and reports the outcome honestly."""

    def list_scenarios(self) -> list[dict]:
        return [s.summary() for s in SCENARIOS.values()]

    async def run(self, db: AsyncSession, scenario_id: str) -> dict:
        scenario = SCENARIOS.get(scenario_id)
        if scenario is None:
            raise NotFoundError(f"Unknown scenario '{scenario_id}'. Available: {', '.join(SCENARIOS)}.")

        identity = (
            await db.execute(select(Identity).where(Identity.username == scenario.username))
        ).scalar_one_or_none()
        if identity is None:
            raise NotFoundError(
                f"Scenario target '{scenario.username}' is not present. Seed the estate first."
            )

        risk_before = identity.risk_score
        state_before = TransitionState(str(identity.transition_state))

        now = utcnow()
        payloads = [
            EventIngest(
                identity=identity.id,
                occurred_at=now - timedelta(hours=step.hours_ago),
                event_type=step.event_type,
                resource=step.resource,
                action=step.action,
                sensitivity_level=step.sensitivity,
                outcome=step.outcome,
                ip_address=step.ip,
                country=step.country,
                latitude=step.latitude,
                longitude=step.longitude,
                device_id=step.device,
                bytes_transferred=step.bytes_transferred,
                record_count=step.records,
                is_off_hours=step.off_hours,
                context_tags=step.tags,
                source=f"scenario:{scenario.id}",
            )
            for step in scenario.steps
        ]
        await ingest_service.ingest(db, payloads, recompute=False, source_override=f"scenario:{scenario.id}")

        result = await detection_service.score_identity(db, identity, persist=True, snapshot=True)
        await db.flush()

        alert_id = None
        from app.db.models import Alert  # local import avoids a cycle at module load

        alert = (
            await db.execute(
                select(Alert)
                .where(Alert.identity_id == identity.id)
                .order_by(Alert.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if alert:
            alert_id = alert.id

        matched = scenario.matches(result.transition_state)
        logger.info(
            "simulator.scenario_run",
            scenario=scenario.id,
            identity=identity.username,
            risk=result.cumulative_risk,
            state=result.transition_state.value,
            expected=scenario.expected_state.value,
            matched=matched,
        )

        return {
            "scenario": scenario.summary(),
            "identity_id": identity.id,
            "events_injected": len(payloads),
            "risk_before": risk_before,
            "risk_after": result.cumulative_risk,
            "state_before": state_before,
            "state_after": result.transition_state,
            "alert_id": alert_id,
            "damping_applied": result.damping_applied,
            "anti_tamper_triggered": result.anti_tamper_triggered,
            "matched_rules": result.matched_rule_ids,
            "outcome_matches_expectation": matched,
        }


# --------------------------------------------------------------- synthetic data
DEPARTMENT_ASSETS: dict[str, list[tuple[str, int]]] = {
    "Engineering": [
        ("github_repo_webapp", 1),
        ("jira_board_sprint", 1),
        ("figma_designs", 1),
        ("npm_registry_internal", 1),
        ("ci_pipeline_frontend", 2),
        ("staging_api_gateway", 2),
    ],
    "Infrastructure": [
        ("kubernetes_cluster_dev", 2),
        ("terraform_staging", 2),
        ("datadog_dashboards", 1),
        ("aws_ec2_dev", 2),
        ("bastion_host_eu", 3),
        ("kubernetes_cluster_prod", 4),
    ],
    "Core Platform": [
        ("github_repo_backend", 1),
        ("kafka_staging_cluster", 2),
        ("postgres_user_db_dev", 2),
        ("grpc_api_specs", 1),
        ("service_mesh_config", 3),
    ],
    "Finance": [
        ("netsuite_erp", 3),
        ("quarterly_budget_sheets", 3),
        ("payroll_internal_app", 4),
        ("stripe_reporting_api", 3),
    ],
    "Analytics": [
        ("snowflake_bi_marts", 2),
        ("tableau_dashboards", 1),
        ("dbt_analytics_models", 2),
        ("metabase_sql_runner", 2),
        ("customer_analytics_warehouse", 4),
    ],
    "People Ops": [
        ("workday_portal", 3),
        ("greenhouse_ats", 2),
        ("notion_handbook", 1),
        ("slack_admin_panel", 2),
    ],
    "Sales": [
        ("salesforce_crm_pipeline", 3),
        ("gong_call_recordings", 2),
        ("pricing_playbook_confidential", 4),
        ("customer_contact_master_list", 4),
    ],
    "Legal": [
        ("ironclad_contracts", 3),
        ("legal_matter_tracker", 3),
        ("docusign_envelopes", 2),
    ],
    "Security": [
        ("splunk_search_head", 3),
        ("crowdstrike_console", 3),
        ("vault_policy_admin", 4),
    ],
}

ACTIONS_BY_TYPE: dict[EventType, list[str]] = {
    EventType.FILE_ACCESS: ["read", "read", "read", "write", "download"],
    EventType.API_CALL: ["query", "query", "list", "read", "write"],
    EventType.AUTHENTICATION: ["login"],
    EventType.CONFIG_CHANGE: ["write", "update"],
}


def generate_normal_history(
    identity_id: str,
    department: str,
    start: datetime,
    end: datetime,
    *,
    daily_mean: int = 14,
    rng: random.Random | None = None,
) -> list[EventIngest]:
    """Produce plausible business-hours telemetry for baseline learning."""
    rng = rng or random.Random(hash(identity_id) & 0xFFFF)
    assets = DEPARTMENT_ASSETS.get(department, [("wiki_internal", 1), ("email_suite", 1)])
    events: list[EventIngest] = []

    day = start
    while day < end:
        if day.weekday() < 5:
            count = max(3, int(rng.gauss(daily_mean, daily_mean * 0.28)))
            # Each identity keeps a stable device and network, as real employees do.
            device = f"dev-{identity_id[-6:]}"
            ip = f"192.168.{abs(hash(identity_id)) % 250}.{abs(hash(identity_id)) % 200 + 10}"
            for _ in range(count):
                hour = int(min(18, max(8, rng.gauss(13, 2.4))))
                moment = day.replace(
                    hour=hour, minute=rng.randrange(60), second=rng.randrange(60), microsecond=0
                )
                resource, sensitivity = rng.choice(assets)
                event_type = (
                    EventType.AUTHENTICATION
                    if rng.random() < 0.06
                    else EventType.FILE_ACCESS
                    if "repo" in resource or "design" in resource or "sheet" in resource
                    else EventType.API_CALL
                )
                events.append(
                    EventIngest(
                        identity=identity_id,
                        occurred_at=moment,
                        event_type=event_type,
                        resource="sso_okta_gateway" if event_type is EventType.AUTHENTICATION else resource,
                        action=rng.choice(ACTIONS_BY_TYPE.get(event_type, ["read"])),
                        sensitivity_level=2 if event_type is EventType.AUTHENTICATION else sensitivity,
                        ip_address=ip,
                        country="US",
                        latitude=37.77,
                        longitude=-122.42,
                        device_id=device,
                        bytes_transferred=rng.randrange(1_000, 4_000_000),
                        record_count=rng.randrange(0, 400),
                        is_off_hours=False,
                        source="seed",
                    )
                )
        day += timedelta(days=1)
    return events


simulator_service = SimulatorService()
