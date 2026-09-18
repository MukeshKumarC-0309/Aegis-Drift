"""Prometheus instrumentation."""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from app.core.config import settings

REQUEST_COUNT = Counter(
    "silentshift_http_requests_total",
    "HTTP requests processed.",
    ["method", "path", "status"],
)

REQUEST_LATENCY = Histogram(
    "silentshift_http_request_duration_seconds",
    "HTTP request latency.",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

EVENTS_INGESTED = Counter("silentshift_events_ingested_total", "Telemetry events accepted.", ["source"])

ALERTS_RAISED = Counter("silentshift_alerts_raised_total", "Alerts raised.", ["severity"])

ACTIONS_EXECUTED = Counter(
    "silentshift_response_actions_total", "Response actions executed.", ["action", "automated"]
)

SCORING_DURATION = Histogram(
    "silentshift_identity_scoring_seconds",
    "Time to score one identity through the full pipeline.",
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
)

IDENTITIES_BY_STATE = Gauge(
    "silentshift_identities_by_state", "Monitored identities per transition state.", ["state"]
)

FLEET_RISK = Gauge("silentshift_fleet_mean_risk", "Mean risk score across the fleet.")

WEBSOCKET_CLIENTS = Gauge("silentshift_websocket_clients", "Connected live-feed clients.")


def observe_request(method: str, path: str, status: int, duration: float) -> None:
    if not settings.METRICS_ENABLED:
        return
    REQUEST_COUNT.labels(method=method, path=path, status=str(status)).inc()
    REQUEST_LATENCY.labels(method=method, path=path).observe(duration)


def render_metrics() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
