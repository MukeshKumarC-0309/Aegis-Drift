import pytest
from datetime import datetime, timedelta
from app.models import SecurityEvent, EventType, ContextRecord, TransitionState, BaselineProfile
from app.engine.baseline import BaselineEngine
from app.engine.context import ContextAwareEngine
from app.engine.sequence import SequenceCorrelationEngine
from app.engine.explainability import ExplainabilityEngine
from app.engine.simulator import ThreatSimulator
from app.engine.blast_radius import BlastRadiusEngine
from app.engine.copilot import ShiftCopilotEngine


def test_baseline_and_temporal_evaluation():
    baseline_eng = BaselineEngine()
    now = datetime.now()
    events = [
        SecurityEvent(
            id=f"ev_{i}",
            timestamp=now.replace(hour=10, minute=15),
            user_id="u1",
            username="test.user",
            department="Engineering",
            role="Developer",
            event_type=EventType.FILE_ACCESS,
            resource="repo_main",
            sensitivity_level=1,
            action="read"
        )
        for i in range(20)
    ]
    profile = baseline_eng.build_baseline_profile("u1", "test.user", "Engineering", "Developer", events)
    assert profile.user_id == "u1"
    assert "repo_main" in profile.common_resources

    # Test normal working hour event
    normal_ev = SecurityEvent(
        id="norm_1",
        timestamp=now.replace(hour=10, minute=30),
        user_id="u1",
        username="test.user",
        department="Engineering",
        role="Developer",
        event_type=EventType.FILE_ACCESS,
        resource="repo_main",
        sensitivity_level=1,
        action="read"
    )
    score_normal = baseline_eng.evaluate_event_anomaly(normal_ev, profile)
    assert score_normal["temporal"] < 40.0

    # Test off-hours unknown resource event
    abnormal_ev = SecurityEvent(
        id="abnorm_1",
        timestamp=now.replace(hour=3, minute=15),
        user_id="u1",
        username="test.user",
        department="Engineering",
        role="Developer",
        event_type=EventType.FILE_ACCESS,
        resource="financial_payroll_confidential",
        sensitivity_level=5,
        action="export_all",
        is_off_hours=True
    )
    score_abnormal = baseline_eng.evaluate_event_anomaly(abnormal_ev, profile)
    assert score_abnormal["temporal"] >= 75.0
    assert score_abnormal["resource"] >= 75.0
    assert score_abnormal["peer_divergence"] >= 65.0


def test_context_damping_and_scope_enforcement():
    ctx_eng = ContextAwareEngine()
    now = datetime.now()
    rec = ContextRecord(
        id="ctx_1",
        user_id="u1",
        context_type="PROJECT_TRANSFER",
        description="Data Platform Reassignment",
        valid_from=now - timedelta(days=2),
        valid_until=now + timedelta(days=5),
        damping_factor=0.30,
        approved_by="Security Lead",
        target_resources=["prod_analytics_cluster"],
        active=True
    )
    ctx_eng.register_context(rec)

    # Scoped event should be damped
    scoped_ev = SecurityEvent(
        id="ev_scoped",
        timestamp=now,
        user_id="u1",
        username="test.user",
        department="Engineering",
        role="Developer",
        event_type=EventType.FILE_ACCESS,
        resource="prod_analytics_cluster",
        sensitivity_level=4,
        action="query"
    )
    damped_score, is_damped, reason, _ = ctx_eng.evaluate_context(scoped_ev, 80.0)
    assert is_damped is True
    assert damped_score <= 25.0

    # Malicious action (delete audit logs) must NOT be damped even on scoped resource
    tamper_ev = SecurityEvent(
        id="ev_tamper",
        timestamp=now,
        user_id="u1",
        username="test.user",
        department="Engineering",
        role="Developer",
        event_type=EventType.API_CALL,
        resource="prod_analytics_cluster",
        sensitivity_level=5,
        action="delete_audit_logs"
    )
    damped_score_tamper, is_damped_tamper, _, _ = ctx_eng.evaluate_context(tamper_ev, 95.0)
    assert is_damped_tamper is False
    assert damped_score_tamper == 95.0


def test_sequence_correlation_and_transition():
    baseline_eng = BaselineEngine()
    ctx_eng = ContextAwareEngine()
    seq_eng = SequenceCorrelationEngine(baseline_eng, ctx_eng)
    now = datetime.now()

    profile = baseline_eng.build_baseline_profile("u1", "test.user", "Engineering", "Developer", [])

    events = [
        SecurityEvent(
            id=f"drift_{i}",
            timestamp=now - timedelta(hours=10 - i * 2),
            user_id="u1",
            username="test.user",
            department="Engineering",
            role="Developer",
            event_type=EventType.PRIVILEGE_ACTION,
            resource=f"prod_db_shard_{i}",
            sensitivity_level=4 + (1 if i > 2 else 0),
            action="sudo" if i > 1 else "query",
            is_off_hours=True
        )
        for i in range(5)
    ]

    res = seq_eng.correlate_event_stream(events, profile)
    assert res["cumulative_risk"] > 50.0
    assert res["transition_state"] in [TransitionState.ESCALATING, TransitionState.CRITICAL_TRANSITION]
    assert len(res["timeline_points"]) == 5


def test_threat_simulator_scenarios():
    baseline_eng = BaselineEngine()
    ctx_eng = ContextAwareEngine()
    seq_eng = SequenceCorrelationEngine(baseline_eng, ctx_eng)
    exp_eng = ExplainabilityEngine()
    sim = ThreatSimulator(baseline_eng, ctx_eng, seq_eng, exp_eng)

    assert len(sim.users) == 12

    out = sim.run_scenario("compromised_admin")
    assert out["scenario_id"] == "compromised_admin"

    alert = sim.alerts_db.get("usr_sarah")
    assert alert is not None
    assert alert.transition_state == TransitionState.CRITICAL_TRANSITION
    assert alert.risk_score >= 70.0


def test_blast_radius_and_copilot_engine():
    blast_eng = BlastRadiusEngine()
    copilot_eng = ShiftCopilotEngine()
    now = datetime.now()

    profile = BaselineProfile(
        user_id="u1",
        username="alex.mercer",
        department="Engineering",
        role="Senior Frontend Engineer",
        common_resources=["github_repo_webapp"]
    )

    recent_events = [
        SecurityEvent(
            id="ev_crown",
            timestamp=now,
            user_id="u1",
            username="alex.mercer",
            department="Engineering",
            role="Senior Frontend Engineer",
            event_type=EventType.NETWORK_EGRESS,
            resource="crown_jewel_customer_pii_export.tar.gz",
            sensitivity_level=5,
            action="export_all"
        )
    ]

    blast = blast_eng.compute_blast_radius("u1", "alex.mercer", "Engineering", "Senior Frontend Engineer", recent_events, profile, 85.0)
    assert blast["blast_radius_score"] > 60.0
    assert blast["pii_data_exposed"] is True
    assert len(blast["graph"]["nodes"]) >= 2

    # Test Copilot response
    inv_payload = {
        "composite_risk_score": 85.0,
        "transition_state": "CRITICAL_TRANSITION",
        "vector_scores": {"temporal": 40.0, "resource": 45.0},
        "baseline_vs_actual": {"novel_assets_accessed": ["crown_jewel_customer_pii_export.tar.gz"]}
    }
    answer = copilot_eng.answer_query("u1", "alex.mercer", "Engineering", "Senior Frontend Engineer", "What is the blast radius?", inv_payload, blast)
    assert "Blast Radius" in answer["answer"]
    assert len(answer["suggested_actions"]) > 0
