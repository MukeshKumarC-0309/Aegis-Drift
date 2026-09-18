"""Access control on the Prometheus endpoint."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.config import settings

pytestmark = pytest.mark.integration


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    yield


class TestMetricsAccess:
    async def test_open_outside_production(self, client: AsyncClient):
        response = await client.get("/metrics")
        assert response.status_code == 200
        assert "aegisdrift_http_requests_total" in response.text

    async def test_production_without_a_token_does_not_serve_metrics(
        self, client: AsyncClient, production, monkeypatch
    ):
        """Fails closed: no token configured means the endpoint is not available."""
        monkeypatch.setattr(settings, "METRICS_TOKEN", None)
        response = await client.get("/metrics")
        assert response.status_code == 404
        assert "aegisdrift_" not in response.text

    async def test_production_rejects_a_wrong_token(self, client: AsyncClient, production, monkeypatch):
        monkeypatch.setattr(settings, "METRICS_TOKEN", "the-real-token")
        response = await client.get("/metrics", headers={"Authorization": "Bearer wrong"})
        assert response.status_code == 404

    async def test_production_rejects_a_missing_header(self, client: AsyncClient, production, monkeypatch):
        monkeypatch.setattr(settings, "METRICS_TOKEN", "the-real-token")
        assert (await client.get("/metrics")).status_code == 404

    async def test_production_accepts_the_correct_token(self, client: AsyncClient, production, monkeypatch):
        monkeypatch.setattr(settings, "METRICS_TOKEN", "the-real-token")
        response = await client.get("/metrics", headers={"Authorization": "Bearer the-real-token"})
        assert response.status_code == 200
        assert "aegisdrift_http_requests_total" in response.text

    async def test_rejection_is_404_not_401(self, client: AsyncClient, production, monkeypatch):
        """404 rather than 401, so the endpoint's existence is not advertised."""
        monkeypatch.setattr(settings, "METRICS_TOKEN", "the-real-token")
        assert (await client.get("/metrics")).status_code == 404
