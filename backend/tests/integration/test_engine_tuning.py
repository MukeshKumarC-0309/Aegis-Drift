"""Engine tuning must be atomic.

The bug these guard: the handler used to mutate the live shared engine config and
only then validate it. A rejected request returned 422 while leaving the running
detector configured with the very values it had just refused — quietly raising the
alerting threshold while telling the operator nothing had changed. For a detection
system, going silent on a *rejected* change is close to the worst failure mode
available.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.services.detection import detection_service

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def restore_engine_config():
    """Tuning mutates process-wide state; put it back so tests stay independent."""
    from dataclasses import replace

    original = detection_service.config
    snapshot = replace(original, vector_weights=dict(original.vector_weights))
    yield
    detection_service.apply_config(snapshot)


def _live() -> dict:
    cfg = detection_service.config
    return {
        "early_drift": cfg.threshold_early_drift,
        "escalating": cfg.threshold_escalating,
        "critical": cfg.threshold_critical,
        "halflife": cfg.decay_halflife_hours,
        "weights": dict(cfg.vector_weights),
    }


class TestRejectedChangesDoNotLeak:
    async def test_out_of_order_thresholds_leave_the_engine_untouched(
        self, client: AsyncClient, admin_headers
    ):
        before = _live()

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
        assert _live() == before, "a rejected tuning request mutated the live engine"

    async def test_unknown_vector_leaves_the_engine_untouched(self, client: AsyncClient, admin_headers):
        before = _live()

        response = await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={"vector_weights": {"not_a_vector": 1.0}, "recompute": False},
        )

        assert response.status_code == 422
        assert _live() == before

    async def test_negative_weight_leaves_the_engine_untouched(self, client: AsyncClient, admin_headers):
        before = _live()

        response = await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={"vector_weights": {"temporal": -1.0}, "recompute": False},
        )

        assert response.status_code == 422
        assert _live() == before

    async def test_a_partially_valid_payload_is_rejected_wholesale(self, client: AsyncClient, admin_headers):
        """The half-life here is fine; the thresholds are not. Neither may apply."""
        before = _live()

        response = await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={
                "decay_halflife_hours": 12,
                "threshold_early_drift": 80,
                "threshold_escalating": 40,
                "recompute": False,
            },
        )

        assert response.status_code == 422
        assert _live()["halflife"] == before["halflife"], "a valid field leaked from a rejected payload"


class TestAcceptedChangesApply:
    async def test_valid_thresholds_are_committed(self, client: AsyncClient, admin_headers):
        response = await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={
                "threshold_early_drift": 30,
                "threshold_escalating": 55,
                "threshold_critical": 80,
                "recompute": False,
            },
        )

        assert response.status_code == 200
        assert _live()["early_drift"] == 30
        assert _live()["critical"] == 80

    async def test_the_sequence_engine_sees_the_new_config(self, client: AsyncClient, admin_headers):
        """Regression: the engine holds its own reference to the config object."""
        await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={"decay_halflife_hours": 6, "recompute": False},
        )
        assert detection_service.sequence_engine.config.decay_halflife_hours == 6

    async def test_weights_are_merged_not_replaced(self, client: AsyncClient, admin_headers):
        before = _live()["weights"]

        response = await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={"vector_weights": {"temporal": 0.3}, "recompute": False},
        )

        assert response.status_code == 200
        weights = response.json()["vector_weights"]
        assert weights["temporal"] == 0.3
        assert set(weights) == set(before), "editing one weight dropped the others"

    async def test_get_reflects_the_committed_state(self, client: AsyncClient, admin_headers):
        await client.put(
            "/api/v1/analytics/hyperparameters",
            headers=admin_headers,
            json={"normal_threshold": 35, "recompute": False},
        )
        current = (await client.get("/api/v1/analytics/hyperparameters", headers=admin_headers)).json()
        assert current["normal_threshold"] == 35
