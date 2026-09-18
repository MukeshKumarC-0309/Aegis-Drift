"""API surface: authentication, RBAC, validation and the ingestion pipeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient

from app.db.models import Identity
from tests.conftest import TEST_PASSWORD

pytestmark = pytest.mark.integration


class TestHealth:
    async def test_liveness_needs_no_dependencies(self, client: AsyncClient):
        response = await client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    async def test_health_reports_database(self, client: AsyncClient):
        body = (await client.get("/health")).json()
        assert body["checks"]["database"] == "ok"
        assert body["status"] in {"healthy", "degraded"}

    async def test_metrics_are_exposed(self, client: AsyncClient):
        response = await client.get("/metrics")
        assert response.status_code == 200
        assert "aegisdrift_http_requests_total" in response.text


class TestAuthentication:
    async def test_login_returns_a_token_pair(self, client: AsyncClient, admin_user):
        response = await client.post(
            "/api/v1/auth/login", json={"email": admin_user.email, "password": TEST_PASSWORD}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["access_token"] and body["refresh_token"]
        assert body["token_type"] == "bearer"

    async def test_wrong_password_is_rejected(self, client: AsyncClient, admin_user):
        response = await client.post(
            "/api/v1/auth/login", json={"email": admin_user.email, "password": "wrong"}
        )
        assert response.status_code == 401

    async def test_unknown_email_gives_the_same_message_as_a_wrong_password(
        self, client: AsyncClient, admin_user
    ):
        """User enumeration defence: both paths must be indistinguishable."""
        unknown = await client.post(
            "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "whatever"}
        )
        wrong = await client.post("/api/v1/auth/login", json={"email": admin_user.email, "password": "wrong"})
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json()["error"]["message"] == wrong.json()["error"]["message"]

    async def test_protected_route_requires_a_token(self, client: AsyncClient):
        assert (await client.get("/api/v1/identities")).status_code == 401

    async def test_garbage_token_is_rejected(self, client: AsyncClient):
        response = await client.get("/api/v1/identities", headers={"Authorization": "Bearer nonsense"})
        assert response.status_code == 401

    async def test_refresh_issues_a_new_pair(self, client: AsyncClient, admin_user):
        login = await client.post(
            "/api/v1/auth/login", json={"email": admin_user.email, "password": TEST_PASSWORD}
        )
        response = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": login.json()["refresh_token"]}
        )
        assert response.status_code == 200
        assert response.json()["access_token"]

    async def test_access_token_cannot_be_used_to_refresh(self, client: AsyncClient, admin_headers):
        token = admin_headers["Authorization"].removeprefix("Bearer ")
        response = await client.post("/api/v1/auth/refresh", json={"refresh_token": token})
        assert response.status_code == 401

    async def test_me_returns_the_profile(self, client: AsyncClient, admin_headers):
        body = (await client.get("/api/v1/auth/me", headers=admin_headers)).json()
        assert body["email"] == "admin@example.com"
        assert body["role"] == "admin"


class TestRbac:
    async def test_viewer_cannot_create_an_identity(self, client: AsyncClient, viewer_headers):
        response = await client.post(
            "/api/v1/identities",
            headers=viewer_headers,
            json={
                "username": "new.user",
                "display_name": "New User",
                "email": "new@example.com",
                "department": "Engineering",
                "role_title": "Engineer",
            },
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "permission_denied"

    async def test_admin_can_create_an_identity(self, client: AsyncClient, admin_headers):
        response = await client.post(
            "/api/v1/identities",
            headers=admin_headers,
            json={
                "username": "new.user",
                "display_name": "New User",
                "email": "new@example.com",
                "department": "Engineering",
                "role_title": "Engineer",
            },
        )
        assert response.status_code == 201
        assert response.json()["peer_group_id"] == "engineering_engineer"

    async def test_viewer_cannot_retune_the_engine(self, client: AsyncClient, viewer_headers):
        response = await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=viewer_headers,
            json={"decay_halflife_hours": 24, "recompute": False},
        )
        assert response.status_code == 403

    async def test_viewer_can_read(self, client: AsyncClient, viewer_headers, identity):
        assert (await client.get("/api/v1/identities", headers=viewer_headers)).status_code == 200


class TestValidation:
    async def test_bad_payload_returns_structured_field_errors(self, client: AsyncClient, admin_headers):
        response = await client.post(
            "/api/v1/identities",
            headers=admin_headers,
            json={"username": "x"},  # too short, and missing required fields
        )
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "validation_error"
        assert len(error["details"]["fields"]) >= 1

    async def test_duplicate_username_conflicts(self, client: AsyncClient, admin_headers, identity):
        response = await client.post(
            "/api/v1/identities",
            headers=admin_headers,
            json={
                "username": identity.username,
                "display_name": "Clone",
                "email": "clone@example.com",
                "department": "Engineering",
                "role_title": "Engineer",
            },
        )
        assert response.status_code == 409

    async def test_missing_identity_returns_404(self, client: AsyncClient, admin_headers):
        response = await client.get("/api/v1/identities/does.not.exist", headers=admin_headers)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"

    async def test_out_of_order_thresholds_are_rejected(self, client: AsyncClient, admin_headers):
        response = await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={
                "threshold_early_drift": 90,
                "threshold_escalating": 50,
                "threshold_critical": 95,
                "recompute": False,
            },
        )
        assert response.status_code == 422
        assert "early_drift < escalating < critical" in response.json()["error"]["message"]

    async def test_unknown_vector_weight_is_rejected(self, client: AsyncClient, admin_headers):
        response = await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={"vector_weights": {"made_up_vector": 1.0}, "recompute": False},
        )
        assert response.status_code == 422


class TestIngestion:
    def _event(self, target: Identity, **overrides) -> dict:
        payload = {
            "identity": target.username,
            "event_type": "API_CALL",
            "resource": "prod_customer_sql_replica",
            "action": "query_bulk",
            "sensitivity_level": 4,
            "occurred_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        }
        payload.update(overrides)
        return payload

    async def test_batch_is_accepted_and_rescored(self, client: AsyncClient, admin_headers, identity):
        response = await client.post(
            "/api/v1/events/ingest",
            headers=admin_headers,
            json={"events": [self._event(identity) for _ in range(5)], "recompute": True},
        )
        assert response.status_code == 202
        body = response.json()
        assert body["accepted"] == 5
        assert body["rejected"] == 0
        assert identity.id in body["identities_rescored"]

    async def test_one_bad_record_does_not_reject_the_batch(
        self, client: AsyncClient, admin_headers, identity
    ):
        """Per-event error isolation: a partial batch is far more useful than a 400."""
        response = await client.post(
            "/api/v1/events/ingest",
            headers=admin_headers,
            json={
                "events": [
                    self._event(identity),
                    self._event(identity, **{"identity": "nobody.here"}),
                    self._event(identity),
                ],
                "recompute": False,
            },
        )
        assert response.status_code == 202
        body = response.json()
        assert body["accepted"] == 2
        assert body["rejected"] == 1
        assert body["errors"][0]["error"] == "Unknown identity"
        assert body["errors"][0]["index"] == 1

    async def test_future_timestamps_are_rejected(self, client: AsyncClient, admin_headers, identity):
        response = await client.post(
            "/api/v1/events/ingest",
            headers=admin_headers,
            json={
                "events": [
                    self._event(identity, occurred_at=(datetime.now(UTC) + timedelta(days=2)).isoformat())
                ],
                "recompute": False,
            },
        )
        assert response.json()["rejected"] == 1
        assert "future" in response.json()["errors"][0]["error"].lower()

    async def test_ingest_requires_authentication(self, client: AsyncClient, identity):
        response = await client.post("/api/v1/events/ingest", json={"events": [self._event(identity)]})
        assert response.status_code == 401

    async def test_sensitivity_is_bounded(self, client: AsyncClient, admin_headers, identity):
        response = await client.post(
            "/api/v1/events/ingest",
            headers=admin_headers,
            json={"events": [self._event(identity, sensitivity_level=99)]},
        )
        assert response.status_code == 422


class TestPagination:
    async def test_meta_is_consistent(self, client: AsyncClient, admin_headers, db):
        from app.engine.peer import cohort_key

        for i in range(7):
            db.add(
                Identity(
                    username=f"bulk.{i}",
                    display_name=f"Bulk {i}",
                    email=f"bulk{i}@example.com",
                    department="Engineering",
                    role_title="Engineer",
                    peer_group_id=cohort_key("Engineering", "Engineer"),
                )
            )
        await db.commit()

        response = await client.get(
            "/api/v1/identities", headers=admin_headers, params={"page": 1, "page_size": 3}
        )
        body = response.json()
        assert len(body["items"]) == 3
        assert body["meta"]["total"] == 7
        assert body["meta"]["total_pages"] == 3
        assert body["meta"]["has_next"] is True
        assert body["meta"]["has_previous"] is False

        last = await client.get(
            "/api/v1/identities", headers=admin_headers, params={"page": 3, "page_size": 3}
        )
        assert last.json()["meta"]["has_next"] is False
        assert len(last.json()["items"]) == 1

    async def test_page_size_is_capped(self, client: AsyncClient, admin_headers):
        response = await client.get("/api/v1/identities", headers=admin_headers, params={"page_size": 5000})
        assert response.status_code == 422


class TestApiKeys:
    async def test_key_is_returned_once_then_only_its_prefix(self, client: AsyncClient, admin_headers):
        created = await client.post("/api/v1/auth/api-keys", headers=admin_headers, json={"name": "ingest"})
        assert created.status_code == 201
        raw = created.json()["key"]
        assert raw.startswith("ad_live_")

        listed = await client.get("/api/v1/auth/api-keys", headers=admin_headers)
        assert "key" not in listed.json()[0]
        assert listed.json()[0]["prefix"] in raw

    async def test_key_authenticates_ingest(self, client: AsyncClient, admin_headers, identity):
        created = await client.post("/api/v1/auth/api-keys", headers=admin_headers, json={"name": "pipeline"})
        raw = created.json()["key"]

        response = await client.post(
            "/api/v1/events/ingest",
            headers={"X-API-Key": raw},
            json={
                "events": [
                    {
                        "identity": identity.username,
                        "event_type": "API_CALL",
                        "resource": "wiki_internal",
                        "action": "read",
                    }
                ],
                "recompute": False,
            },
        )
        assert response.status_code == 202

    async def test_revoked_key_stops_working(self, client: AsyncClient, admin_headers, identity):
        created = await client.post("/api/v1/auth/api-keys", headers=admin_headers, json={"name": "temp"})
        raw, key_id = created.json()["key"], created.json()["id"]
        await client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=admin_headers)

        response = await client.post(
            "/api/v1/events/ingest",
            headers={"X-API-Key": raw},
            json={
                "events": [
                    {
                        "identity": identity.username,
                        "event_type": "API_CALL",
                        "resource": "x",
                        "action": "read",
                    }
                ]
            },
        )
        assert response.status_code == 401


class TestObservability:
    async def test_every_response_carries_a_request_id(self, client: AsyncClient):
        response = await client.get("/health/live")
        assert response.headers["X-Request-ID"]
        assert float(response.headers["X-Response-Time-Ms"]) >= 0

    async def test_supplied_request_id_is_echoed(self, client: AsyncClient):
        response = await client.get("/health/live", headers={"X-Request-ID": "trace-me-123"})
        assert response.headers["X-Request-ID"] == "trace-me-123"

    async def test_security_headers_are_applied(self, client: AsyncClient):
        headers = (await client.get("/health/live")).headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"

    async def test_state_changes_are_audited(self, client: AsyncClient, admin_headers):
        await client.post(
            "/api/v1/identities",
            headers=admin_headers,
            json={
                "username": "audited.user",
                "display_name": "Audited",
                "email": "a@example.com",
                "department": "Engineering",
                "role_title": "Engineer",
            },
        )
        audit = await client.get("/api/v1/analytics/audit", headers=admin_headers)
        actions = [entry["action"] for entry in audit.json()["items"]]
        assert "identity.created" in actions

    async def test_audit_never_stores_credentials(self, client: AsyncClient, admin_headers):
        """Regression guard: the audit log must not become a password leak."""
        await client.post(
            "/api/v1/auth/users",
            headers=admin_headers,
            json={
                "email": "new.op@example.com",
                "full_name": "New Operator",
                "password": "Sup3rSecret!Value",
                "role": "analyst",
            },
        )
        audit = await client.get("/api/v1/analytics/audit", headers=admin_headers)
        assert "Sup3rSecret!Value" not in audit.text
