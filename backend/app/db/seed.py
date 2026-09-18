"""Idempotent database seeding.

Builds the demonstration estate: operators, identities, assets, a learned baseline
per identity from generated history, detection rules, playbooks, contexts and
threat intel. Safe to run repeatedly — existing rows are left untouched.
"""

from __future__ import annotations

import random
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.enums import IntegrationStatus
from app.core.logging import get_logger
from app.core.security import Role, hash_password
from app.db.base import utcnow
from app.db.models import (
    Asset,
    ContextRecord,
    DetectionRule,
    Identity,
    Integration,
    Playbook,
    ThreatIndicator,
    User,
    Watchlist,
)
from app.db.seed_data import (
    ASSETS,
    BUILTIN_RULES,
    CONTEXTS,
    IDENTITIES,
    INDICATORS,
    INTEGRATIONS,
    PLAYBOOKS,
    SERVICE_ACCOUNTS,
)
from app.engine.peer import cohort_key
from app.services.detection import detection_service
from app.services.ingest import ingest_service
from app.services.simulator import generate_normal_history

logger = get_logger(__name__)

#: Days of synthetic history generated per identity for baseline learning.
HISTORY_DAYS = 40

#: Reproducible estate across restarts.
SEED = 20260917


async def seed_all(db: AsyncSession, *, force: bool = False) -> dict[str, int]:
    """Populate the database. Returns a count of rows created per entity."""
    created: dict[str, int] = {}

    created["users"] = await _seed_users(db)
    created["assets"] = await _seed_assets(db)
    created["rules"] = await _seed_rules(db)
    created["playbooks"] = await _seed_playbooks(db)
    created["indicators"] = await _seed_indicators(db)
    created["integrations"] = await _seed_integrations(db)
    await db.flush()

    existing_identities = int((await db.execute(select(func.count()).select_from(Identity))).scalar_one())
    if existing_identities and not force:
        logger.info("seed.identities_present", count=existing_identities)
        created["identities"] = 0
        return created

    created["identities"] = await _seed_identities(db)
    await db.flush()
    created["contexts"] = await _seed_contexts(db)
    created["watchlists"] = await _seed_watchlists(db)
    await db.flush()

    created["events"] = await _seed_history(db)
    await _learn_baselines(db)

    logger.info("seed.complete", **created)
    return created


# --------------------------------------------------------------------- entities
async def _seed_users(db: AsyncSession) -> int:
    accounts = [
        (
            settings.FIRST_SUPERUSER_EMAIL,
            "Platform Administrator",
            Role.ADMIN,
            settings.FIRST_SUPERUSER_PASSWORD,
        )
    ]

    # Demo logins exist to show the RBAC tiers. They are skipped in production
    # unless explicitly enabled, because the responder role can quarantine
    # accounts and their default passwords are published in the README.
    if settings.seed_demo_accounts:
        accounts += [
            ("analyst@silentshift.io", "Sam Okonkwo", Role.ANALYST, settings.DEMO_ANALYST_PASSWORD),
            (
                "responder@silentshift.io",
                "Riley Nakamura",
                Role.RESPONDER,
                settings.DEMO_RESPONDER_PASSWORD,
            ),
            ("viewer@silentshift.io", "Casey Brennan", Role.VIEWER, settings.DEMO_VIEWER_PASSWORD),
        ]
    else:
        logger.info("seed.demo_accounts_skipped", reason="production or explicitly disabled")
    count = 0
    for email, name, role, password in accounts:
        exists = (await db.execute(select(User.id).where(User.email == email))).scalar_one_or_none()
        if exists:
            continue
        db.add(
            User(
                email=email,
                full_name=name,
                hashed_password=hash_password(password),
                role=role,
                is_active=True,
                preferences={"theme": "dark", "density": "comfortable"},
            )
        )
        count += 1
    return count


async def _seed_assets(db: AsyncSession) -> int:
    existing = {k for (k,) in (await db.execute(select(Asset.key))).all()}
    count = 0
    for key, name, category, tier, env, owner, pii, pci, phi, crown, records, scopes in ASSETS:
        if key in existing:
            continue
        db.add(
            Asset(
                key=key,
                display_name=name,
                category=category,
                sensitivity_level=tier,
                environment=env,
                owner_team=owner,
                contains_pii=pii,
                contains_cardholder_data=pci,
                contains_phi=phi,
                is_crown_jewel=crown,
                record_estimate=records,
                compliance_scopes=list(scopes),
            )
        )
        count += 1
    return count


async def _seed_rules(db: AsyncSession) -> int:
    existing = {s for (s,) in (await db.execute(select(DetectionRule.slug))).all()}
    count = 0
    for spec in BUILTIN_RULES:
        if spec["slug"] in existing:
            continue
        db.add(DetectionRule(is_builtin=True, enabled=True, **spec))
        count += 1
    return count


async def _seed_playbooks(db: AsyncSession) -> int:
    existing = {s for (s,) in (await db.execute(select(Playbook.slug))).all()}
    count = 0
    for spec in PLAYBOOKS:
        if spec["slug"] in existing:
            continue
        db.add(Playbook(enabled=True, **spec))
        count += 1
    return count


async def _seed_indicators(db: AsyncSession) -> int:
    existing = {v for (v,) in (await db.execute(select(ThreatIndicator.value))).all()}
    now = utcnow()
    count = 0
    for kind, value, confidence, severity, feed, description in INDICATORS:
        if value in existing:
            continue
        db.add(
            ThreatIndicator(
                indicator_type=kind,
                value=value,
                confidence=confidence,
                severity=severity,
                source_feed=feed,
                description=description,
                first_seen=now - timedelta(days=30),
                last_seen=now - timedelta(hours=6),
                expires_at=now + timedelta(days=90),
            )
        )
        count += 1
    return count


async def _seed_integrations(db: AsyncSession) -> int:
    existing = {n for (n,) in (await db.execute(select(Integration.name))).all()}
    now = utcnow()
    count = 0
    for name, kind, vendor, status, protocol, interval, entities, ingested in INTEGRATIONS:
        if name in existing:
            continue
        db.add(
            Integration(
                name=name,
                kind=kind,
                vendor=vendor,
                status=status,
                protocol=protocol,
                sync_interval=interval,
                entities_synced=entities,
                events_ingested_24h=ingested,
                last_heartbeat_at=now - timedelta(seconds=random.Random(name).randrange(5, 900)),
                error_message=(
                    "API rate limit reached; falling back to a 10-minute polling interval."
                    if status is IntegrationStatus.DEGRADED
                    else None
                ),
            )
        )
        count += 1
    return count


async def _seed_identities(db: AsyncSession) -> int:
    now = utcnow()
    rng = random.Random(SEED)
    for username, display, dept, role, location, privileged, manager in IDENTITIES:
        db.add(
            Identity(
                username=username,
                display_name=display,
                email=f"{username}@silentshift.io",
                department=dept,
                role_title=role,
                manager=manager,
                location=location,
                employment_type="SERVICE" if username in SERVICE_ACCOUNTS else "FULL_TIME",
                peer_group_id=cohort_key(dept, role),
                is_privileged=privileged,
                is_service_account=username in SERVICE_ACCOUNTS,
                joined_at=now - timedelta(days=rng.randrange(120, 2200)),
            )
        )
    return len(IDENTITIES)


async def _seed_contexts(db: AsyncSession) -> int:
    lookup = {i.username: i for i in (await db.execute(select(Identity))).scalars().all()}
    now = utcnow()
    count = 0
    for username, kind, title, description, ticket, back, forward, factor, approver, resources in CONTEXTS:
        identity = lookup.get(username)
        if identity is None:
            continue
        db.add(
            ContextRecord(
                identity_id=identity.id,
                context_type=kind,
                title=title,
                description=description,
                ticket_reference=ticket,
                source_system="servicenow",
                valid_from=now - timedelta(days=back),
                valid_until=now + timedelta(days=forward),
                damping_factor=factor,
                target_resources=list(resources),
                approved_by=approver,
            )
        )
        count += 1
    return count


async def _seed_watchlists(db: AsyncSession) -> int:
    exists = (
        await db.execute(select(Watchlist.id).where(Watchlist.name == "Notice period"))
    ).scalar_one_or_none()
    if exists:
        return 0
    departing = (
        await db.execute(select(Identity).where(Identity.username == "noah.garcia"))
    ).scalar_one_or_none()
    members = [departing.id] if departing else []
    if departing:
        departing.on_watchlist = True
    db.add(
        Watchlist(
            name="Notice period",
            description="Identities serving notice. Scored more aggressively until their "
            "last day, when offboarding removes them automatically.",
            reason="HR-flagged resignation",
            risk_multiplier=1.3,
            member_ids=members,
            expires_at=utcnow() + timedelta(days=30),
        )
    )
    return 1


# ---------------------------------------------------------------------- history
async def _seed_history(db: AsyncSession) -> int:
    """Generate and ingest business-hours telemetry so baselines have something to learn."""
    identities = (await db.execute(select(Identity))).scalars().all()
    now = utcnow()
    start = now - timedelta(days=HISTORY_DAYS)
    total = 0

    for identity in identities:
        rng = random.Random(f"{SEED}:{identity.username}")
        daily = 6 if identity.is_service_account else rng.randrange(9, 18)
        payloads = generate_normal_history(
            identity.id, identity.department, start, now, daily_mean=daily, rng=rng
        )
        # Ingest without re-scoring: baselines do not exist yet, so scoring here
        # would burn cycles producing results we are about to invalidate.
        result = await ingest_service.ingest(db, payloads, recompute=False, source_override="seed")
        total += result.accepted
    await db.flush()
    return total


async def _learn_baselines(db: AsyncSession) -> None:
    identities = (await db.execute(select(Identity))).scalars().all()
    for identity in identities:
        await detection_service.rebuild_baseline(db, identity)
    await db.flush()

    # First real scoring pass, now that every identity has a baseline.
    await detection_service.refresh_peer_cache(db, force=True)
    for identity in identities:
        await detection_service.score_identity(db, identity, persist=True, snapshot=True)
    logger.info("seed.baselines_learned", identities=len(identities))
