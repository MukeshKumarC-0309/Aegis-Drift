"""Version 1 API surface."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    alerts,
    analytics,
    auth,
    cases,
    catalog,
    contexts,
    detections,
    events,
    export,
    identities,
    response,
    simulator,
    stream,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(identities.router, prefix="/identities", tags=["Identities"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(cases.router, prefix="/cases", tags=["Cases"])
api_router.include_router(events.router, prefix="/events", tags=["Telemetry"])
api_router.include_router(contexts.router, prefix="/contexts", tags=["Context Registry"])
api_router.include_router(detections.router, prefix="/detections", tags=["Detection Rules"])
api_router.include_router(response.router, prefix="/response", tags=["Response"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
api_router.include_router(catalog.router, prefix="/catalog", tags=["Catalogue"])
api_router.include_router(simulator.router, prefix="/simulator", tags=["Simulator"])
api_router.include_router(export.router, prefix="/export", tags=["Forensic Export"])
api_router.include_router(stream.router, prefix="/stream", tags=["Live Stream"])
