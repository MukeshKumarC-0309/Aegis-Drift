"""Threat scenario simulator and estate reset."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import delete, select

from app.api.deps import CurrentUser, DbSession, RequireAdmin, RequireAnalyst
from app.db.models import (
    ActionRecord,
    Alert,
    Baseline,
    Case,
    CaseEntry,
    ContextRecord,
    Identity,
    RiskSnapshot,
    SecurityEvent,
    Watchlist,
)
from app.schemas.analytics import ScenarioRunResult, ScenarioSummary
from app.schemas.common import Message
from app.services import audit
from app.services.events import event_bus
from app.services.simulator import simulator_service

router = APIRouter()


@router.get(
    "/scenarios",
    response_model=list[ScenarioSummary],
    summary="Available threat scenarios",
    description=(
        "Each scenario declares the outcome it expects. Running one reports whether the "
        "engine actually produced that outcome, so the simulator doubles as a live "
        "regression harness rather than a scripted demo."
    ),
)
async def list_scenarios(_: CurrentUser) -> list[dict]:
    return simulator_service.list_scenarios()


@router.post(
    "/scenarios/{scenario_id}/run",
    response_model=ScenarioRunResult,
    summary="Run a threat scenario",
)
async def run_scenario(scenario_id: str, user: RequireAnalyst, db: DbSession) -> dict:
    result = await simulator_service.run(db, scenario_id)
    await audit.record(
        db,
        action="simulator.scenario_run",
        target_type="scenario",
        target_id=scenario_id,
        actor=user,
        payload={
            "risk_after": result["risk_after"],
            "state_after": str(result["state_after"]),
            "matched_expectation": result["outcome_matches_expectation"],
        },
    )
    await event_bus.publish(
        "scenario.completed",
        {
            "scenario_id": scenario_id,
            "identity_id": result["identity_id"],
            "risk_after": result["risk_after"],
            "state_after": str(result["state_after"]),
        },
    )
    return result


@router.post(
    "/reset",
    response_model=Message,
    summary="Reset the estate to its seeded baseline",
    description=(
        "Deletes all simulated and injected telemetry, alerts, cases and response history, "
        "then re-learns every baseline from freshly generated history. Destructive and "
        "restricted to administrators."
    ),
)
async def reset_estate(user: RequireAdmin, db: DbSession) -> Message:
    from app.db.seed import seed_all

    for model in (
        CaseEntry,
        ActionRecord,
        Alert,
        Case,
        RiskSnapshot,
        SecurityEvent,
        ContextRecord,
        Baseline,
        Watchlist,
        Identity,
    ):
        await db.execute(delete(model))
    await db.flush()

    created = await seed_all(db, force=True)
    await audit.record(db, action="simulator.estate_reset", target_type="estate", actor=user, payload=created)
    await event_bus.publish("estate.reset", created)
    return Message(
        message="Estate reset to its seeded baseline.",
        detail=f"Recreated {created.get('identities', 0)} identities and "
        f"{created.get('events', 0)} historical events.",
    )


@router.post(
    "/rescore-all",
    response_model=Message,
    summary="Re-score every identity",
)
async def rescore_all(user: RequireAnalyst, db: DbSession) -> Message:
    results = await detection_rescore(db)
    await audit.record(
        db,
        action="simulator.fleet_rescored",
        target_type="estate",
        actor=user,
        payload={"identities": len(results)},
    )
    return Message(message=f"Re-scored {len(results)} identities.")


async def detection_rescore(db):
    from app.services.detection import detection_service

    return await detection_service.score_all(db, snapshot=True)


@router.get("/estate", summary="Row counts across the estate")
async def estate_summary(db: DbSession, _: CurrentUser) -> dict:
    from sqlalchemy import func

    counts = {}
    for label, model in (
        ("identities", Identity),
        ("events", SecurityEvent),
        ("alerts", Alert),
        ("cases", Case),
        ("contexts", ContextRecord),
        ("actions", ActionRecord),
        ("snapshots", RiskSnapshot),
    ):
        counts[label] = int((await db.execute(select(func.count()).select_from(model))).scalar_one())
    return counts
