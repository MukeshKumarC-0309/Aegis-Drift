"""Liveness, readiness and dependency health."""

from __future__ import annotations

import time
from datetime import datetime

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.api.deps import DbSession
from app.core.config import settings
from app.core.metrics import render_metrics

router = APIRouter()

_STARTED_AT = time.monotonic()


@router.get("/health", tags=["Health"], summary="Overall health")
async def health(db: DbSession, response: Response) -> dict:
    checks: dict[str, str] = {}

    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {type(exc).__name__}"

    if settings.REDIS_URL:
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(settings.REDIS_URL)
            await client.ping()
            await client.aclose()
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"error: {type(exc).__name__}"
    else:
        checks["redis"] = "not configured"

    degraded = [k for k, v in checks.items() if v.startswith("error")]
    overall = "healthy" if not degraded else ("unhealthy" if "database" in degraded else "degraded")
    if overall == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": overall,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "uptime_seconds": round(time.monotonic() - _STARTED_AT, 1),
        "checks": checks,
        "timestamp": datetime.utcnow(),
    }


@router.get("/health/live", tags=["Health"], summary="Liveness probe")
async def liveness() -> dict:
    """Process is up. Deliberately touches no dependency — a database blip must not
    cause Kubernetes to restart an otherwise healthy pod."""
    return {"status": "alive"}


@router.get("/health/ready", tags=["Health"], summary="Readiness probe")
async def readiness(db: DbSession, response: Response) -> dict:
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as exc:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not ready", "reason": type(exc).__name__}


@router.get("/metrics", tags=["Health"], summary="Prometheus metrics", include_in_schema=False)
async def metrics() -> Response:
    if not settings.METRICS_ENABLED:
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    payload, content_type = render_metrics()
    return Response(content=payload, media_type=content_type)
