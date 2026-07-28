import random
import uuid
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta
from app.models import (
    SecurityEvent, EventType, BaselineProfile, ContextRecord, ThreatAlert,
    TransitionState
)
from app.engine.baseline import BaselineEngine
from app.engine.context import ContextAwareEngine
from app.engine.sequence import SequenceCorrelationEngine
from app.engine.explainability import ExplainabilityEngine


class ThreatSimulator:
    """
    Simulates enterprise telemetry, behavioral baselines, legitimate organizational contexts,
    and 4 realistic threat transition scenarios for hackathon evaluation.
    """

    def __init__(
        self,
        baseline_engine: BaselineEngine,
        context_engine: ContextAwareEngine,
        sequence_engine: SequenceCorrelationEngine,
        explainability_engine: ExplainabilityEngine
    ):
        self.baseline_engine = baseline_engine
        self.context_engine = context_engine
        self.sequence_engine = sequence_engine
        self.explainability_engine = explainability_engine

        # State storage
        self.users: Dict[str, Dict[str, Any]] = {}
        self.events_db: Dict[str, List[SecurityEvent]] = {}  # user_id -> events
        self.baselines_db: Dict[str, BaselineProfile] = {}
        self.alerts_db: Dict[str, ThreatAlert] = {}

        # Initialize mock enterprise environment
        self.initialize_enterprise_data()

    def initialize_enterprise_data(self):
        """Builds a rich enterprise dataset of 12 users with established baselines and clean initial states."""
        self.users.clear()
        self.events_db.clear()
        self.baselines_db.clear()
        self.alerts_db.clear()

        user_definitions = [
            ("usr_alex", "alex.mercer", "Engineering", "Senior Frontend Engineer"),
            ("usr_sarah", "sarah.connor", "Infrastructure", "Lead DevOps Engineer"),
            ("usr_priya", "priya.patel", "Core Platform", "Cloud Backend Architect"),
            ("usr_marcus", "marcus.vance", "Finance", "Financial Controller"),
            ("usr_elena", "elena.rostova", "Analytics", "Staff Data Scientist"),
            ("usr_david", "david.kim", "People Ops", "HR Operations Director"),
            ("usr_jordan", "jordan.lee", "Engineering", "Frontend Developer"),
            ("usr_chloe", "chloe.dupont", "Engineering", "Software Engineer"),
            ("usr_liam", "liam.smith", "Infrastructure", "Site Reliability Engineer"),
            ("usr_noah", "noah.garcia", "Finance", "Senior Accountant"),
            ("usr_sophia", "sophia.chen", "Analytics", "BI Analyst"),
            ("usr_lucas", "lucas.muller", "Core Platform", "Distributed Systems Engineer"),
        ]

        now = datetime.utcnow()

        for uid, uname, dept, role in user_definitions:
            self.users[uid] = {
                "user_id": uid,
                "username": uname,
                "department": dept,
                "role": role,
            }
            # Generate 30 days of clean historical baseline events
            hist_events = self._generate_normal_history(uid, uname, dept, role, now - timedelta(days=35), now - timedelta(days=5))
            profile = self.baseline_engine.build_baseline_profile(uid, uname, dept, role, hist_events)
            self.baselines_db[uid] = profile

            # Generate recent 5 days of normal activity
            recent_events = self._generate_normal_history(uid, uname, dept, role, now - timedelta(days=5), now)
            self.events_db[uid] = recent_events

        # Register Legitimate Business Contexts
        context_priya = ContextRecord(
            id="ctx_priya_01",
            user_id="usr_priya",
            context_type="PROJECT_TRANSFER",
            description="Project Titan Data Lake Migration Lead Assignment",
            ticket_reference="CHG-2024-9182",
            valid_from=now - timedelta(days=10),
            valid_until=now + timedelta(days=30),
            damping_factor=0.25,  # 75% risk damping on Titan data lake operations
            approved_by="VP of Engineering (Mark Robinson)",
            target_resources=["prod_datalake_s3", "customer_analytics_warehouse", "snowflake_titan_lake"],
            active=True
        )
        self.context_engine.register_context(context_priya)

        context_sarah = ContextRecord(
            id="ctx_sarah_01",
            user_id="usr_sarah",
            context_type="ON_CALL_ROTATION",
            description="Tier-1 Production Emergency Primary On-Call",
            ticket_reference="INC-SCHEDULE-WK36",
            valid_from=now - timedelta(days=3),
            valid_until=now + timedelta(days=4),
            damping_factor=0.35,
            approved_by="DevOps Manager (Alan Turing)",
            target_resources=["kubernetes_cluster_prod", "bastion_host_eu"],
            active=True
        )
        self.context_engine.register_context(context_sarah)

        # Pre-seed Scenario 1 on Alex Mercer so initial load has a live, realistic low-and-slow case to investigate!
        self.run_scenario("slow_poisoner")

        # Also pre-seed Priya's legitimate project shift to show false-positive suppression
        self.run_scenario("project_switcher")

        # Recompute all
        self._recompute_all()

    def _generate_normal_history(self, uid: str, uname: str, dept: str, role: str, start: datetime, end: datetime) -> List[SecurityEvent]:
        events = []
        curr = start
        common_assets_by_dept = {
            "Engineering": ["github_repo_webapp", "jira_board_sprint", "figma_designs", "npm_registry_internal"],
            "Infrastructure": ["kubernetes_cluster_dev", "terraform_staging", "datadog_dashboards", "aws_ec2_dev"],
            "Core Platform": ["github_repo_backend", "kafka_staging_cluster", "postgres_user_db_dev", "grpc_api_specs"],
            "Finance": ["netsuite_erp", "quarterly_budget_sheets", "payroll_internal_app", "stripe_reporting_api"],
            "Analytics": ["snowflake_bi_marts", "tableau_dashboards", "dbt_analytics_models", "metabase_sql_runner"],
            "People Ops": ["workday_portal", "greenhouse_ats", "notion_handbook", "slack_admin_panel"]
        }
        assets = common_assets_by_dept.get(dept, ["wiki_internal", "email_suite"])

        # Create 12-18 events per weekday strictly during 09:00 - 17:30
        while curr < end:
            if curr.weekday() < 5:  # Monday to Friday
                num_events = random.randint(8, 14)
                for _ in range(num_events):
                    hour = random.randint(9, 17)
                    minute = random.randint(0, 59)
                    ev_time = curr.replace(hour=hour, minute=minute, second=random.randint(0, 59))
                    res = random.choice(assets)
                    events.append(SecurityEvent(
                        id=f"ev_{uuid.uuid4().hex[:8]}",
                        timestamp=ev_time,
                        user_id=uid,
                        username=uname,
                        department=dept,
                        role=role,
                        event_type=EventType.FILE_ACCESS if "repo" in res or "designs" in res else EventType.API_CALL,
                        resource=res,
                        sensitivity_level=1,
                        action="read" if random.random() < 0.8 else "write",
                        ip_address="192.168.1.105",
                        is_off_hours=False
                    ))
            curr += timedelta(days=1)
        return events

    def run_scenario(self, scenario_id: str) -> Dict[str, Any]:
        now = datetime.utcnow()

        if scenario_id == "slow_poisoner":
            # Target: Alex Mercer (Frontend Eng) -> starts accessing sensitive customer data gradually
            uid = "usr_alex"
            uname = "alex.mercer"
            dept = "Engineering"
            role = "Senior Frontend Engineer"

            transition_events = [
                # Day 1: Off-hours login
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(days=4, hours=3),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.AUTHENTICATION, resource="sso_okta_gateway",
                    sensitivity_level=2, action="login", is_off_hours=True
                ),
                # Day 2: Reads customer DB schema
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(days=3, hours=1),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.FILE_ACCESS, resource="internal_schema_docs_customer_pii",
                    sensitivity_level=3, action="read", is_off_hours=False
                ),
                # Day 3: Late night query on production customer DB
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(days=2, hours=2),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.API_CALL, resource="prod_customer_sql_replica",
                    sensitivity_level=4, action="query", is_off_hours=True
                ),
                # Day 4: Bulk query of payment tables
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(days=1, hours=2),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.API_CALL, resource="prod_payment_vault_metadata",
                    sensitivity_level=4, action="query_bulk", is_off_hours=True
                ),
                # Day 5: Bulk export Crown Jewel
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(hours=6),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.NETWORK_EGRESS, resource="crown_jewel_customer_pii_export.tar.gz",
                    sensitivity_level=5, action="export_all", is_off_hours=True
                )
            ]

            self.events_db[uid].extend(transition_events)
            self._recompute_user(uid)

            return {
                "scenario_id": scenario_id,
                "title": "The Slow Poisoner (Low-and-Slow Insider Exfiltration)",
                "target_user": uname,
                "injected_events": len(transition_events),
                "summary": "Alex Mercer gradually drifted from routine frontend UI tasks to off-hours querying of customer PII and bulk export. Sequence correlation captured the cumulative drift into Critical Transition."
            }

        elif scenario_id == "compromised_admin":
            uid = "usr_sarah"
            uname = "sarah.connor"
            dept = "Infrastructure"
            role = "Lead DevOps Engineer"

            transition_events = [
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(hours=6),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.AUTHENTICATION, resource="aws_management_console",
                    sensitivity_level=3, action="login", ip_address="185.220.101.5",
                    is_off_hours=True
                ),
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(hours=4),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.PRIVILEGE_ACTION, resource="iam_role_security_auditor",
                    sensitivity_level=4, action="assume_role", is_off_hours=True
                ),
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(hours=2),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.ROLE_MODIFICATION, resource="aws_iam_policy_admin_attach",
                    sensitivity_level=5, action="iam_modify", is_off_hours=True
                ),
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(minutes=45),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.API_CALL, resource="cloudtrail_audit_log_stream",
                    sensitivity_level=5, action="delete_audit_logs", is_off_hours=True
                )
            ]

            self.events_db[uid].extend(transition_events)
            self._recompute_user(uid)

            return {
                "scenario_id": scenario_id,
                "title": "The Compromised Admin (Credential Takeover & Lateral Escalation)",
                "target_user": uname,
                "injected_events": len(transition_events),
                "summary": "Sarah Connor's credentials were leveraged from an unusual external IP at 02:00 AM, rapidly executing IAM role assumption, privilege escalation, and CloudTrail audit tampering."
            }

        elif scenario_id == "project_switcher":
            uid = "usr_priya"
            uname = "priya.patel"
            dept = "Core Platform"
            role = "Cloud Backend Architect"

            transition_events = [
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(days=2, hours=3),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.FILE_ACCESS, resource="prod_datalake_s3",
                    sensitivity_level=4, action="read", is_off_hours=False,
                    context_tags=["ticket:CHG-2024-9182"]
                ),
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(days=1, hours=2),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.API_CALL, resource="snowflake_titan_lake",
                    sensitivity_level=4, action="query", is_off_hours=False,
                    context_tags=["ticket:CHG-2024-9182"]
                ),
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(hours=4),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.API_CALL, resource="customer_analytics_warehouse",
                    sensitivity_level=4, action="read", is_off_hours=False,
                    context_tags=["ticket:CHG-2024-9182"]
                )
            ]

            self.events_db[uid].extend(transition_events)
            self._recompute_user(uid)

            return {
                "scenario_id": scenario_id,
                "title": "The Legitimate Project Switcher (Context-Aware False Positive Suppression)",
                "target_user": uname,
                "injected_events": len(transition_events),
                "summary": "Priya Patel began accessing unfamiliar Tier-4 Data Lake tables. The Context-Aware Damping Engine matched her active Change Ticket (CHG-2024-9182), reducing raw risk by 75% and suppressing false positive alerts."
            }

        elif scenario_id == "privilege_creep":
            uid = "usr_elena"
            uname = "elena.rostova"
            dept = "Analytics"
            role = "Staff Data Scientist"

            transition_events = [
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(days=3),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.PRIVILEGE_ACTION, resource="gcp_iam_service_account_token",
                    sensitivity_level=3, action="assume_role", is_off_hours=False
                ),
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(days=1, hours=8),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.API_CALL, resource="gcp_secret_manager_db_keys",
                    sensitivity_level=4, action="read", is_off_hours=False
                ),
                SecurityEvent(
                    id=f"ev_{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(hours=5),
                    user_id=uid, username=uname, department=dept, role=role,
                    event_type=EventType.PRIVILEGE_ACTION, resource="gcp_resourcemanager_organization_admin",
                    sensitivity_level=5, action="sudo", is_off_hours=True
                )
            ]

            self.events_db[uid].extend(transition_events)
            self._recompute_user(uid)

            return {
                "scenario_id": scenario_id,
                "title": "Privilege Creep & Secret Access",
                "target_user": uname,
                "injected_events": len(transition_events),
                "summary": "Elena Rostova incrementally requested elevated cloud tokens, read production secret manager keys, and executed off-hours sudo escalations outside the data science baseline."
            }

        return {"error": f"Unknown scenario_id: {scenario_id}"}

    def inject_custom_event(
        self,
        user_id: str,
        event_type: EventType,
        resource: str,
        sensitivity_level: int,
        action: str,
        is_off_hours: bool,
        context_tags: List[str]
    ) -> Dict[str, Any]:
        user_meta = self.users.get(user_id)
        if not user_meta:
            return {"error": f"User {user_id} not found"}

        now = datetime.utcnow()
        ev = SecurityEvent(
            id=f"ev_{uuid.uuid4().hex[:8]}",
            timestamp=now,
            user_id=user_id,
            username=user_meta["username"],
            department=user_meta["department"],
            role=user_meta["role"],
            event_type=event_type,
            resource=resource,
            sensitivity_level=sensitivity_level,
            action=action,
            ip_address="192.168.1.189" if not is_off_hours else "198.51.100.42",
            is_off_hours=is_off_hours,
            context_tags=context_tags
        )

        self.events_db[user_id].append(ev)
        self._recompute_user(user_id)

        alert = self.alerts_db.get(user_id)
        return {
            "status": "success",
            "event_injected": ev.model_dump(mode="json"),
            "updated_alert": alert.model_dump(mode="json") if alert else None
        }

    def _recompute_all(self):
        for uid in self.users:
            self._recompute_user(uid)

    def _recompute_user(self, uid: str):
        user_meta = self.users[uid]
        uname = user_meta["username"]
        dept = user_meta["department"]
        role = user_meta["role"]

        events = self.events_db.get(uid, [])
        baseline = self.baselines_db.get(uid)
        if not baseline:
            baseline = self.baseline_engine.build_baseline_profile(uid, uname, dept, role, events)
            self.baselines_db[uid] = baseline

        correlation = self.sequence_engine.correlate_event_stream(events, baseline)
        contexts = self.context_engine.get_user_contexts(uid)

        risk = correlation["cumulative_risk"]
        raw_risk = correlation["raw_cumulative_risk"]
        state = correlation["transition_state"]
        timeline = correlation["timeline_points"]

        is_damped = any(p.get("is_damped") for p in timeline[-10:])
        damping_reasons = [p.get("damping_reason") for p in timeline[-10:] if p.get("damping_reason")]

        # Trigger alert if risk >= 28 or if context damped
        if risk >= 28.0 or is_damped:
            explanation = self.explainability_engine.generate_explanation(
                user_id=uid,
                username=uname,
                department=dept,
                role=role,
                baseline=baseline,
                correlation_result=correlation,
                recent_events=events[-25:],
                active_contexts=contexts
            )

            tactics = [m["technique"] for m in explanation.mitre_mapping]

            status = "DAMPED_BENIGN" if (is_damped and risk < 45.0) else ("OPEN" if risk >= 60.0 else "INVESTIGATING")

            self.alerts_db[uid] = ThreatAlert(
                id=f"alt_{uid}",
                user_id=uid,
                username=uname,
                department=dept,
                role=role,
                timestamp=datetime.utcnow(),
                title=f"Behavioral Drift: {uname} ({state.value})",
                risk_score=risk,
                raw_risk_score=raw_risk,
                context_damped=is_damped,
                damping_reason=damping_reasons[-1] if damping_reasons else None,
                transition_state=state,
                dominant_vectors=correlation["dominant_vectors"],
                status=status,
                explanation_summary=explanation.natural_language_brief.split("\n\n")[0],
                mitre_tactics=tactics,
                triage_notes=[]
            )
        else:
            if uid in self.alerts_db:
                del self.alerts_db[uid]

    def reset_to_clean_state(self):
        self.initialize_enterprise_data()
        return {"status": "success", "message": "Fleet reset to clean baseline state"}
