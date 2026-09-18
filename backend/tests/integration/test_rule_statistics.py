"""Rule match accounting.

The Detections page reports per-rule match counts and precision, and surfaces
low-precision rules as tuning candidates. Those numbers are only useful if they
are accurate — and the scheduler re-scores the whole fleet every cycle, so the
counter must be idempotent under repeated scoring of the same events.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.db.models import DetectionRule, Identity
from app.services.detection import detection_service

pytestmark = pytest.mark.integration


@pytest.fixture
async def exfil_rule(db) -> DetectionRule:
    rule = DetectionRule(
        slug="test-crown-jewel-export",
        name="Crown-jewel export",
        description="Tier-5 bulk export.",
        category="exfiltration",
        conditions={
            "all": [
                {"field": "sensitivity_level", "op": "gte", "value": 5},
                {"field": "action", "op": "in", "value": ["export_all"]},
            ]
        },
        risk_boost=30.0,
        suppress_when_context=False,
        enabled=True,
    )
    db.add(rule)
    await db.commit()
    return rule


async def _ingest_matching_event(client: AsyncClient, headers: dict, identity: Identity) -> None:
    response = await client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={
            "events": [
                {
                    "identity": identity.username,
                    "occurred_at": (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
                    "event_type": "NETWORK_EGRESS",
                    "resource": "crown_jewel_customer_pii_export",
                    "action": "export_all",
                    "sensitivity_level": 5,
                    "record_count": 900_000,
                    "bytes_transferred": 700_000_000,
                    "is_off_hours": True,
                }
            ],
            "recompute": True,
        },
    )
    assert response.status_code == 202, response.text


class TestRuleMatchAccounting:
    async def test_a_matching_event_increments_the_counter(
        self, client: AsyncClient, admin_headers, identity, exfil_rule, db
    ):
        await _ingest_matching_event(client, admin_headers, identity)

        await db.refresh(exfil_rule)
        assert exfil_rule.match_count == 1
        assert exfil_rule.last_matched_at is not None

    async def test_rescoring_does_not_double_count(
        self, client: AsyncClient, admin_headers, identity, exfil_rule, db
    ):
        """The regression this guards: the scheduler re-scores every 45 seconds."""
        await _ingest_matching_event(client, admin_headers, identity)

        await db.refresh(exfil_rule)
        assert exfil_rule.match_count == 1

        # Re-score the same identity repeatedly over the same events.
        for _ in range(3):
            row = (await db.execute(select(Identity).where(Identity.id == identity.id))).scalar_one()
            await detection_service.score_identity(db, row)
            await db.commit()

        await db.refresh(exfil_rule)
        assert exfil_rule.match_count == 1, "re-scoring inflated the match count"

    async def test_a_second_distinct_event_does_increment(
        self, client: AsyncClient, admin_headers, identity, exfil_rule, db
    ):
        await _ingest_matching_event(client, admin_headers, identity)
        await _ingest_matching_event(client, admin_headers, identity)

        await db.refresh(exfil_rule)
        assert exfil_rule.match_count == 2

    async def test_stats_endpoint_reports_the_counts(
        self, client: AsyncClient, admin_headers, identity, exfil_rule
    ):
        await _ingest_matching_event(client, admin_headers, identity)

        stats = (await client.get("/api/v1/detections/stats", headers=admin_headers)).json()
        assert stats["total_matches"] >= 1

        row = next(r for r in stats["rules"] if r["slug"] == exfil_rule.slug)
        assert row["match_count"] == 1
        assert row["precision"] is None  # no analyst disposition yet

    async def test_false_positive_disposition_feeds_precision(
        self, client: AsyncClient, admin_headers, identity, exfil_rule
    ):
        """Closing the tuning loop: analyst dispositions become rule precision."""
        await _ingest_matching_event(client, admin_headers, identity)

        alerts = (await client.get("/api/v1/alerts", headers=admin_headers)).json()
        assert alerts["items"], "the matching event should have raised an alert"
        alert_id = alerts["items"][0]["id"]

        marked = await client.post(
            f"/api/v1/alerts/{alert_id}/false-positive",
            headers=admin_headers,
            params={"reason": "Approved migration, confirmed with the owner."},
        )
        assert marked.status_code == 200

        stats = (await client.get("/api/v1/detections/stats", headers=admin_headers)).json()
        row = next(r for r in stats["rules"] if r["slug"] == exfil_rule.slug)
        assert row["false_positives"] == 1
        assert row["precision"] == 0.0
        assert any(c["slug"] == exfil_rule.slug for c in stats["tuning_candidates"])

    async def test_a_non_matching_event_leaves_the_counter_alone(
        self, client: AsyncClient, admin_headers, identity, exfil_rule, db
    ):
        await client.post(
            "/api/v1/events/ingest",
            headers=admin_headers,
            json={
                "events": [
                    {
                        "identity": identity.username,
                        "event_type": "API_CALL",
                        "resource": "wiki_internal",
                        "action": "read",
                        "sensitivity_level": 1,
                    }
                ],
                "recompute": True,
            },
        )
        await db.refresh(exfil_rule)
        assert exfil_rule.match_count == 0


class TestCaseImpactSnapshot:
    """A case records the impact assessment the analyst acted on, not a live score."""

    async def test_case_captures_blast_radius_on_creation(
        self, client: AsyncClient, admin_headers, identity, exfil_rule
    ):
        await _ingest_matching_event(client, admin_headers, identity)

        alerts = (await client.get("/api/v1/alerts", headers=admin_headers)).json()
        alert = alerts["items"][0]

        created = await client.post(
            "/api/v1/cases",
            headers=admin_headers,
            json={
                "title": "Suspected exfiltration",
                "priority": "P1",
                "severity": "CRITICAL",
                "primary_identity_id": identity.id,
                "alert_ids": [alert["id"]],
            },
        )
        assert created.status_code == 201
        body = created.json()

        assert body["blast_radius_score"] > 0, "case did not capture a blast radius"
        assert body["estimated_records_at_risk"] > 0, "case did not capture records at risk"
        assert body["peak_risk_score"] > 0

    async def test_case_without_a_primary_identity_still_opens(self, client: AsyncClient, admin_headers):
        """The impact snapshot is advisory — its absence must never block a case."""
        created = await client.post(
            "/api/v1/cases",
            headers=admin_headers,
            json={"title": "Generic investigation", "priority": "P3", "severity": "LOW"},
        )
        assert created.status_code == 201
        assert created.json()["blast_radius_score"] == 0.0
