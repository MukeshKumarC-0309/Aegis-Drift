"""HTTP middleware: correlation IDs, access logging, security headers, rate limits."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.logging import get_logger, request_id_ctx
from app.core.metrics import observe_request

logger = get_logger("http")

#: Paths excluded from access logging and rate limiting.
QUIET_PATHS = {"/health", "/health/live", "/health/ready", "/metrics", "/favicon.ico"}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a correlation ID, times the request and emits one structured log line."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        token = request_id_ctx.set(request_id)
        request.state.request_id = request_id
        started = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            duration = time.perf_counter() - started
            logger.exception(
                "request.failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round(duration * 1000, 2),
            )
            request_id_ctx.reset(token)
            raise

        duration = time.perf_counter() - started
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = f"{duration * 1000:.2f}"

        route = request.scope.get("route")
        template = getattr(route, "path", request.url.path)
        observe_request(request.method, template, response.status_code, duration)

        if request.url.path not in QUIET_PATHS:
            logger.info(
                "request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=round(duration * 1000, 2),
                client=request.client.host if request.client else None,
            )
        request_id_ctx.reset(token)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies baseline hardening headers to every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if settings.is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window limiter keyed on client IP plus API key prefix.

    In-process by design: it protects a single replica from a runaway client. A
    multi-replica deployment should additionally rate limit at the ingress.
    """

    def __init__(self, app, requests: int, window_seconds: int, ingest_requests: int) -> None:
        super().__init__(app)
        self.requests = requests
        self.window = window_seconds
        self.ingest_requests = ingest_requests
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not settings.RATE_LIMIT_ENABLED or request.url.path in QUIET_PATHS:
            return await call_next(request)

        limit = self.ingest_requests if "/events" in request.url.path else self.requests
        key = self._key(request)
        now = time.monotonic()
        window = self._hits[key]

        while window and now - window[0] > self.window:
            window.popleft()

        if len(window) >= limit:
            retry_after = max(1, int(self.window - (now - window[0])))
            logger.warning("ratelimit.blocked", key=key, path=request.url.path, limit=limit)
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "rate_limited",
                        "message": f"Rate limit of {limit} requests per {self.window}s exceeded.",
                    }
                },
                headers={"Retry-After": str(retry_after), "X-RateLimit-Limit": str(limit)},
            )

        window.append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - len(window)))

        # Opportunistic eviction so idle keys do not accumulate forever.
        if len(self._hits) > 4096:
            for stale in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window * 4]:
                self._hits.pop(stale, None)
        return response

    @staticmethod
    def _key(request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For", "")
        ip = (
            forwarded.split(",")[0].strip()
            if forwarded
            else (request.client.host if request.client else "unknown")
        )
        api_key = request.headers.get("X-API-Key", "")
        return f"{ip}:{api_key[:14]}" if api_key else ip
