"""Aegis Drift application factory and ASGI entrypoint."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.v1.endpoints import health
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import AegisDriftError
from app.core.logging import configure_logging, get_logger
from app.core.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.session import dispose_engine, init_models, session_scope
from app.services.events import event_bus
from app.workers.scheduler import scheduler

configure_logging()
logger = get_logger(__name__)

API_DESCRIPTION = """
**Aegis Drift** is an Identity Threat Detection & Response (ITDR) platform. It detects
low-and-slow account compromise and insider risk that per-event rules structurally
cannot see.

### How it works

1. **Baselines** — each identity's own circadian rhythm, resource surface, privilege
   habits, network origins and data volume are learned from history.
2. **Eight-vector scoring** — every event is scored independently on temporal,
   resource, privilege, peer-divergence, geo-velocity, volume, device and threat-intel
   dimensions.
3. **Sequence correlation** — a leaky risk accumulator with exponential decay turns a
   *trajectory* of small deviations into a state transition. Unbroken anomaly streaks
   compound; isolated noise decays away.
4. **Context-aware damping** — approved change tickets, on-call rotations and role
   transfers suppress the false positives that cause alert fatigue. Evidence-destroying
   actions can never be suppressed, by any approval.
5. **Explainable verdicts** — every score is traceable to specific events, with the
   arguments *against* the verdict stated explicitly.

### Authentication

Most endpoints require `Authorization: Bearer <access token>` from `POST /api/v1/auth/login`.
Telemetry ingest additionally accepts an `X-API-Key` header for machine clients.

Roles, in ascending order: `viewer` → `analyst` → `responder` → `admin`.
"""

TAGS_METADATA = [
    {"name": "Authentication", "description": "Sign-in, tokens, operators and API keys."},
    {"name": "Identities", "description": "The monitored estate and per-identity investigation."},
    {"name": "Alerts", "description": "The triage queue and alert disposition."},
    {"name": "Cases", "description": "Investigations, timelines and SLA tracking."},
    {"name": "Telemetry", "description": "Event ingestion and the raw event stream."},
    {"name": "Context Registry", "description": "Approved business justifications that damp risk."},
    {"name": "Detection Rules", "description": "Declarative rule authoring, testing and tuning."},
    {"name": "Response", "description": "Containment actions and SOAR playbooks."},
    {"name": "Analytics", "description": "Dashboards, executive metrics and engine tuning."},
    {"name": "Catalogue", "description": "Protected assets and threat-intel indicators."},
    {"name": "Simulator", "description": "Reproducible attack scenarios and estate reset."},
    {"name": "Forensic Export", "description": "Dossiers and evidence exports for incident records."},
    {"name": "Live Stream", "description": "WebSocket feed of scoring and response events."},
    {"name": "Health", "description": "Probes and Prometheus metrics."},
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "app.starting",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        database="sqlite" if settings.is_sqlite else "postgresql",
    )

    await init_models()
    await event_bus.start()

    seeded = False
    if settings.AUTO_SEED:
        from app.db.seed import seed_all

        async with session_scope() as db:
            created = await seed_all(db)
        if any(created.values()):
            seeded = True
            logger.info("app.seeded", **created)

    await scheduler.start()
    logger.info("app.ready", docs=settings.docs_url or "disabled")
    _print_welcome(seeded)

    yield

    await scheduler.stop()
    await event_bus.stop()
    await dispose_engine()
    logger.info("app.stopped")


def _print_welcome(seeded: bool) -> None:
    """Print where to go and how to sign in.

    Written straight to stdout rather than through the logger: this is addressed to
    a person watching a terminal, not to a log aggregator, and it should stay
    readable when LOG_FORMAT is json.
    """
    if settings.is_production:
        return

    port = settings.PORT
    url = f"http://localhost:{port}"
    lines = [
        "",
        "  ┌─────────────────────────────────────────────────────────────┐",
        "  │  Aegis Drift is running                                     │",
        "  └─────────────────────────────────────────────────────────────┘",
        "",
        f"    Console    {url}",
        f"    API docs   {url}/docs",
        "",
        "    Sign in with any of:",
        "      admin@aegisdrift.com      ChangeMe_Aeg1sDrift!   (full access)",
        "      analyst@aegisdrift.com    AnalystDemo_2026!       (triage, cases)",
        "      viewer@aegisdrift.com     ViewerDemo_2026!        (read only)",
        "",
    ]
    if seeded:
        lines += [
            "    A demonstration estate has been created: 24 identities with",
            "    learned behavioural baselines. Open Threat Simulator and press",
            "    'Run all scenarios' to watch the detection engine work.",
            "",
        ]
    print("\n".join(lines), flush=True)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        description=API_DESCRIPTION,
        version=settings.VERSION,
        openapi_tags=TAGS_METADATA,
        docs_url=settings.docs_url,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
        contact={"name": "Aegis Drift Engineering", "url": "https://github.com/"},
        license_info={"name": "Apache 2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"},
    )

    # Middleware executes bottom-up: context (outermost) → security → rate limit → gzip.
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    if settings.RATE_LIMIT_ENABLED:
        app.add_middleware(
            RateLimitMiddleware,
            requests=settings.RATE_LIMIT_REQUESTS,
            window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
            ingest_requests=settings.RATE_LIMIT_INGEST_REQUESTS,
        )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Response-Time-Ms", "X-RateLimit-Remaining"],
    )
    if settings.TRUSTED_HOSTS != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(health.router)
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    _register_exception_handlers(app)
    _mount_frontend(app)
    return app


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AegisDriftError)
    async def _domain_error(_: Request, exc: AegisDriftError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "The request payload failed validation.",
                    "details": {
                        "fields": [
                            {
                                "location": " → ".join(str(p) for p in err["loc"]),
                                "message": err["msg"],
                                "type": err["type"],
                            }
                            for err in exc.errors()
                        ]
                    },
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse | FileResponse:
        if exc.status_code == 404 and not request.url.path.startswith(("/api", "/health", "/metrics")):
            spa = _frontend_dir() / "index.html"
            if spa.exists():
                # Client-side routing: hand unknown paths to the SPA.
                return FileResponse(spa)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": f"http_{exc.status_code}",
                    "message": exc.detail if isinstance(exc.detail, str) else "Request failed.",
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_exception", path=request.url.path, error=str(exc))
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": (
                        str(exc)
                        if settings.DEBUG
                        else "An unexpected error occurred. The incident has been logged."
                    ),
                    "details": {"request_id": getattr(request.state, "request_id", None)},
                }
            },
        )


def _frontend_dir() -> Path:
    base = Path(__file__).resolve().parent.parent
    return (base / settings.FRONTEND_DIST_DIR).resolve()


def _mount_frontend(app: FastAPI) -> None:
    """Serve the built SPA when present. In development the Vite dev server owns this."""
    if not settings.SERVE_FRONTEND:
        return
    dist = _frontend_dir()
    if not (dist / "index.html").exists():
        logger.info("frontend.not_built", expected=str(dist))

        @app.get("/", include_in_schema=False)
        async def _api_only() -> dict:
            return {
                "service": settings.PROJECT_NAME,
                "version": settings.VERSION,
                "message": "API is running. The console has not been built.",
                "build_hint": "cd frontend && npm install && npm run build",
                "docs": settings.docs_url,
            }

        return

    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/", include_in_schema=False)
    async def _spa_root() -> FileResponse:
        return FileResponse(dist / "index.html")

    for filename in ("favicon.svg", "favicon.ico", "robots.txt", "manifest.webmanifest"):
        path = dist / filename
        if path.exists():
            app.add_api_route(
                f"/{filename}",
                _static_file_route(path),
                methods=["GET"],
                include_in_schema=False,
            )

    logger.info("frontend.mounted", dist=str(dist))


def _static_file_route(path: Path):
    async def _serve() -> FileResponse:
        return FileResponse(path)

    return _serve


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=os.getenv("RELOAD", "").lower() in {"1", "true", "yes"},
        log_config=None,
    )
