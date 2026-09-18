"""Detection engine behaviour.

These are the tests that matter most: they assert the *product claims* — that a
sequence is caught, that a benign control stays quiet, that approved context
suppresses, and that nothing can suppress evidence destruction.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.enums import EventType, TransitionState
from app.engine import (
    BaselineEngine,
    ContextEngine,
    ContextView,
    EventView,
    SequenceEngine,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 17, 10, 0, 0)


def make_engine() -> SequenceEngine:
    return SequenceEngine(BaselineEngine(), ContextEngine())


def routine_history(count: int = 240, end: datetime = NOW - timedelta(days=5)) -> list[EventView]:
    """Business-hours weekday activity on familiar resources.

    Timestamps are strictly increasing and always land before ``end``, so a test
    can append an anomalous chain and know it really is the tail of the stream.
    """
    events: list[EventView] = []
    moment = end
    produced = 0
    while produced < count:
        moment -= timedelta(days=1)
        if moment.weekday() >= 5:
            continue
        for slot in range(8):
            if produced >= count:
                break
            events.append(
                EventView(
                    id=f"hist-{produced}",
                    identity_id="idn_test",
                    occurred_at=moment.replace(hour=9 + slot, minute=15, second=0, microsecond=0),
                    event_type=EventType.API_CALL,
                    resource="github_repo_webapp",
                    action="read",
                    sensitivity_level=1,
                    ip_address="192.168.1.20",
                    country="US",
                    latitude=37.77,
                    longitude=-122.42,
                    device_id="dev-laptop",
                )
            )
            produced += 1
    return sorted(events, key=lambda e: e.occurred_at)


@pytest.fixture
def baseline():
    return BaselineEngine().build(
        "idn_test", "test.user", "Engineering", "Software Engineer", "eng_swe", routine_history()
    )


def exfiltration_chain() -> list[EventView]:
    """Five days of escalating drift ending in a crown-jewel export."""
    common = {
        "identity_id": "idn_test",
        "ip_address": "192.168.1.20",
        "country": "US",
        "latitude": 37.77,
        "longitude": -122.42,
        "device_id": "dev-laptop",
    }
    return [
        EventView(
            id="d1",
            occurred_at=NOW - timedelta(days=4),
            event_type=EventType.AUTHENTICATION,
            resource="sso_okta_gateway",
            action="login",
            sensitivity_level=2,
            is_off_hours=True,
            **common,
        ),
        EventView(
            id="d2",
            occurred_at=NOW - timedelta(days=3),
            event_type=EventType.FILE_ACCESS,
            resource="internal_schema_docs_customer_pii",
            action="read",
            sensitivity_level=3,
            is_off_hours=True,
            **common,
        ),
        EventView(
            id="d3",
            occurred_at=NOW - timedelta(days=2),
            event_type=EventType.API_CALL,
            resource="prod_customer_sql_replica",
            action="query_bulk",
            sensitivity_level=4,
            is_off_hours=True,
            record_count=48_000,
            **common,
        ),
        EventView(
            id="d4",
            occurred_at=NOW - timedelta(hours=6),
            event_type=EventType.NETWORK_EGRESS,
            resource="crown_jewel_customer_pii_export",
            action="export_all",
            sensitivity_level=5,
            is_off_hours=True,
            bytes_transferred=890_000_000,
            record_count=2_400_000,
            **common,
        ),
    ]


class TestSequenceCorrelation:
    def test_benign_history_stays_stable(self, baseline):
        """The control group must be quiet. A detector that alerts on normal
        behaviour is worse than no detector at all."""
        result = make_engine().correlate("idn_test", routine_history()[-80:], baseline)

        assert result.transition_state is TransitionState.STABLE
        assert result.cumulative_risk < 10
        assert result.event_count == 80

    def test_low_and_slow_chain_reaches_critical(self, baseline):
        events = routine_history()[-60:] + exfiltration_chain()
        result = make_engine().correlate("idn_test", events, baseline)

        assert result.transition_state is TransitionState.CRITICAL_TRANSITION
        assert result.cumulative_risk >= 75
        assert "resource" in result.dominant_vectors

    def test_no_single_event_would_trip_a_per_event_threshold_alone(self, baseline):
        """The premise of the platform: the early steps are individually unremarkable.
        Only their accumulation is damning."""
        engine = make_engine()
        chain = exfiltration_chain()

        # Score the first three steps in isolation, each as the only event.
        isolated = [engine.correlate("idn_test", [event], baseline).cumulative_risk for event in chain[:3]]
        together = engine.correlate("idn_test", chain[:3], baseline).cumulative_risk

        assert max(isolated) < together
        assert together > sum(isolated) / len(isolated)

    def test_risk_decays_when_drift_stops(self, baseline):
        """Old anomalies must fade, or every account eventually looks compromised."""
        engine = make_engine()
        chain = exfiltration_chain()

        recent = engine.correlate("idn_test", chain, baseline).cumulative_risk

        # The identical chain, but weeks in the past with quiet behaviour since.
        aged = [
            EventView(
                id=event.id,
                identity_id=event.identity_id,
                occurred_at=event.occurred_at - timedelta(days=40),
                event_type=event.event_type,
                resource=event.resource,
                action=event.action,
                sensitivity_level=event.sensitivity_level,
                is_off_hours=event.is_off_hours,
                bytes_transferred=event.bytes_transferred,
                record_count=event.record_count,
            )
            for event in chain
        ]
        quiet_since = routine_history(60, end=NOW)
        decayed = engine.correlate("idn_test", aged + quiet_since, baseline)

        assert decayed.cumulative_risk < recent
        assert decayed.peak_risk >= decayed.cumulative_risk

    def test_velocity_is_positive_while_drifting(self, baseline):
        result = make_engine().correlate("idn_test", routine_history()[-40:] + exfiltration_chain(), baseline)
        assert result.drift_velocity > 0


class TestContextDamping:
    def _context(self, **overrides) -> ContextView:
        defaults = {
            "id": "ctx_1",
            "identity_id": "idn_test",
            "context_type": "PROJECT_TRANSFER",
            "title": "Data migration",
            "description": "Approved migration work",
            "ticket_reference": "CHG-1",
            "valid_from": NOW - timedelta(days=10),
            "valid_until": NOW + timedelta(days=10),
            "damping_factor": 0.25,
            "target_resources": [
                "internal_schema_docs_customer_pii",
                "prod_customer_sql_replica",
                "crown_jewel_customer_pii_export",
                "sso_okta_gateway",
            ],
            "approved_by": "VP Engineering",
        }
        return ContextView(**{**defaults, **overrides})

    def test_scoped_context_suppresses_the_alert(self, baseline):
        events = routine_history()[-40:] + exfiltration_chain()
        engine = make_engine()

        undamped = engine.correlate("idn_test", events, baseline)
        damped = engine.correlate("idn_test", events, baseline, contexts=[self._context()])

        assert damped.damping_applied
        assert damped.cumulative_risk < undamped.cumulative_risk
        assert damped.transition_state is TransitionState.STABLE
        # The raw score is preserved so the analyst can still see what was suppressed.
        assert damped.raw_cumulative_risk == pytest.approx(undamped.raw_cumulative_risk, rel=0.01)

    def test_out_of_scope_resources_are_not_damped(self, baseline):
        context = self._context(target_resources=["some_unrelated_system"])
        result = make_engine().correlate(
            "idn_test", routine_history()[-40:] + exfiltration_chain(), baseline, contexts=[context]
        )
        assert not result.damping_applied

    def test_lapsed_context_does_not_damp(self, baseline):
        context = self._context(valid_from=NOW - timedelta(days=90), valid_until=NOW - timedelta(days=60))
        result = make_engine().correlate(
            "idn_test", routine_history()[-40:] + exfiltration_chain(), baseline, contexts=[context]
        )
        assert not result.damping_applied

    def test_blanket_context_damps_less_than_a_scoped_one(self, baseline):
        events = routine_history()[-40:] + exfiltration_chain()
        engine = make_engine()

        scoped = engine.correlate("idn_test", events, baseline, contexts=[self._context()])
        blanket = engine.correlate(
            "idn_test", events, baseline, contexts=[self._context(target_resources=[])]
        )
        assert blanket.cumulative_risk >= scoped.cumulative_risk


class TestAntiTamper:
    """The single most important security property in the system."""

    def _tamper_event(self, action: str) -> EventView:
        return EventView(
            id="tamper",
            identity_id="idn_test",
            occurred_at=NOW - timedelta(hours=1),
            event_type=EventType.API_CALL,
            resource="cloudtrail_audit_log_stream",
            action=action,
            sensitivity_level=5,
            is_off_hours=True,
        )

    @pytest.mark.parametrize(
        "action", ["delete_audit_logs", "disable_logging", "dump_credentials", "disable_mfa"]
    )
    def test_no_context_can_suppress_evidence_destruction(self, baseline, action):
        blanket = ContextView(
            id="ctx_oncall",
            identity_id="idn_test",
            context_type="ON_CALL_ROTATION",
            title="On-call",
            description="Primary on-call, broad production access",
            ticket_reference="INC-1",
            valid_from=NOW - timedelta(days=5),
            valid_until=NOW + timedelta(days=5),
            damping_factor=0.1,  # maximally permissive
            target_resources=[],  # blanket approval over everything
            approved_by="Manager",
        )

        result = make_engine().correlate(
            "idn_test",
            [*routine_history()[-30:], self._tamper_event(action)],
            baseline,
            contexts=[blanket],
        )

        assert result.anti_tamper_triggered
        scored = next(s for s in result.scored_events if s.event.id == "tamper")
        assert not scored.is_damped
        assert scored.damped_score == scored.raw_score
        assert result.cumulative_risk >= 50

    def test_tamper_event_is_maximally_scored_on_the_privilege_vector(self, baseline):
        vectors = BaselineEngine().score_event(self._tamper_event("delete_audit_logs"), baseline)
        assert vectors["privilege"] == 100.0
