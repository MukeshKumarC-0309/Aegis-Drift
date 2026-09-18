"""Forensic export: the signed dossier an analyst attaches to an incident record."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from fastapi import APIRouter, Response
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.core.config import settings
from app.core.exceptions import NotFoundError
from app.db.models import Identity, SecurityEvent
from app.services import audit
from app.services.investigation import investigation_service

router = APIRouter()


@router.get(
    "/identities/{identity_id}/dossier.md",
    summary="Forensic dossier (Markdown)",
    response_class=Response,
    responses={200: {"content": {"text/markdown": {}}}},
)
async def markdown_dossier(identity_id: str, db: DbSession, user: CurrentUser) -> Response:
    bundle = await investigation_service.build(db, identity_id)
    identity = bundle["identity"]

    events = (
        (
            await db.execute(
                select(SecurityEvent)
                .where(SecurityEvent.identity_id == identity["id"])
                .order_by(SecurityEvent.occurred_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )

    chain = _evidence_chain(events)
    body = _render_dossier(bundle, chain, user.email)

    await audit.record(
        db,
        action="export.dossier",
        target_type="identity",
        target_id=identity["id"],
        actor=user,
        payload={"format": "markdown", "events_in_chain": len(chain)},
    )
    filename = f"aegisdrift-dossier-{identity['username']}-{datetime.utcnow():%Y%m%d%H%M}.md"
    return Response(
        content=body,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/identities/{identity_id}/dossier.json",
    summary="Forensic dossier (JSON)",
)
async def json_dossier(identity_id: str, db: DbSession, user: CurrentUser) -> dict:
    bundle = await investigation_service.build(db, identity_id)
    events = (
        (
            await db.execute(
                select(SecurityEvent)
                .where(SecurityEvent.identity_id == bundle["identity"]["id"])
                .order_by(SecurityEvent.occurred_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )

    await audit.record(
        db,
        action="export.dossier",
        target_type="identity",
        target_id=bundle["identity"]["id"],
        actor=user,
        payload={"format": "json"},
    )
    return {
        "case_reference": f"AD-DOSSIER-{bundle['identity']['username'].upper()}-"
        f"{datetime.utcnow():%Y%m%d%H%M}",
        "classification": "CONFIDENTIAL — INTERNAL SECURITY USE",
        "generated_at": datetime.utcnow(),
        "generated_by": user.email,
        "platform_version": settings.VERSION,
        "investigation": bundle,
        "evidence_chain": _evidence_chain(events),
        "integrity_note": (
            "Each evidence digest is SHA-256 over the canonical field set of the source "
            "record. Digests verify the export against the datastore; they are not a "
            "cryptographic signature over the document as a whole."
        ),
    }


@router.get("/identities/{identity_id}/events.csv", summary="Event export (CSV)")
async def events_csv(identity_id: str, db: DbSession, user: CurrentUser) -> Response:
    identity = (
        await db.execute(
            select(Identity).where((Identity.id == identity_id) | (Identity.username == identity_id))
        )
    ).scalar_one_or_none()
    if identity is None:
        raise NotFoundError(f"No identity matches '{identity_id}'.")

    rows = (
        (
            await db.execute(
                select(SecurityEvent)
                .where(SecurityEvent.identity_id == identity.id)
                .order_by(SecurityEvent.occurred_at.desc())
                .limit(5000)
            )
        )
        .scalars()
        .all()
    )

    header = (
        "occurred_at,event_type,resource,action,outcome,sensitivity,ip_address,country,"
        "device_id,bytes,records,off_hours,anomaly_score,damped_score,is_damped,matched_rules"
    )
    lines = [header]
    for r in rows:
        lines.append(
            ",".join(
                _csv_cell(v)
                for v in (
                    r.occurred_at.isoformat(),
                    r.event_type,
                    r.resource,
                    r.action,
                    r.outcome,
                    r.sensitivity_level,
                    r.ip_address,
                    r.country,
                    r.device_id or "",
                    r.bytes_transferred,
                    r.record_count,
                    r.is_off_hours,
                    round(r.anomaly_score, 2),
                    round(r.damped_score, 2),
                    r.is_damped,
                    "|".join(r.matched_rules or []),
                )
            )
        )

    await audit.record(
        db,
        action="export.events_csv",
        target_type="identity",
        target_id=identity.id,
        actor=user,
        payload={"rows": len(rows)},
    )
    filename = f"aegisdrift-events-{identity.username}-{datetime.utcnow():%Y%m%d}.csv"
    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ------------------------------------------------------------------- rendering
def _csv_cell(value) -> str:
    text = str(value)
    if any(c in text for c in ',"\n'):
        return '"' + text.replace('"', '""') + '"'
    return text


def _evidence_chain(events) -> list[dict]:
    """Digest each event over a canonical field set so the export is verifiable."""
    chain = []
    for event in events:
        canonical = json.dumps(
            {
                "id": event.id,
                "occurred_at": event.occurred_at.isoformat(),
                "identity_id": event.identity_id,
                "resource": event.resource,
                "action": event.action,
                "sensitivity_level": event.sensitivity_level,
                "ip_address": event.ip_address,
                "bytes_transferred": event.bytes_transferred,
                "record_count": event.record_count,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        chain.append(
            {
                "event_id": event.id,
                "occurred_at": event.occurred_at.isoformat(),
                "resource": event.resource,
                "action": event.action,
                "sensitivity_level": event.sensitivity_level,
                "anomaly_score": round(event.anomaly_score, 2),
                "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            }
        )
    return chain


def _render_dossier(bundle: dict, chain: list[dict], author: str) -> str:
    identity = bundle["identity"]
    explanation = bundle["explanation"]
    blast = bundle["blast_radius"]
    now = datetime.utcnow()

    def section(rows: list[str]) -> str:
        return "\n".join(rows)

    findings = (
        section(
            [f"- **{f['severity']}** — {f['title']}\n  {f['detail']}" for f in explanation["key_findings"]]
        )
        or "- No material findings in the current window."
    )

    attribution = (
        section(
            [
                f"| {a['label']} | {a['score']:.1f} | {a['share']:.1f}% |"
                for a in explanation["attribution"]
                if a["score"] > 0
            ]
        )
        or "| — | — | — |"
    )

    techniques = (
        section(
            [
                f"- **{t['id']} {t['name']}** ({t['tactic']}, {t['confidence']}% confidence) — "
                f"{t['description']}"
                for t in explanation["mitre_techniques"]
            ]
        )
        or "- No ATT&CK techniques evidenced."
    )

    compliance = (
        section(
            [
                f"- **{c['framework']}** ({c['severity']}) — {c['obligation']}"
                for c in blast["compliance_impacts"]
            ]
        )
        or "- No regulatory thresholds crossed."
    )

    actions = (
        section(
            [
                f"{i}. **{a['label']}** _({a['urgency']})_ — {a['rationale']}"
                for i, a in enumerate(explanation["recommended_actions"], 1)
            ]
        )
        or "1. No action required."
    )

    counter = section([f"- {c}" for c in explanation["counter_evidence"]]) or "- None recorded."

    evidence = section(
        [
            f"| `{c['occurred_at'][:19].replace('T', ' ')}` | {c['resource']} | {c['action']} | "
            f"T{c['sensitivity_level']} | {c['anomaly_score']:.1f} | `{c['sha256'][:16]}…` |"
            for c in chain
        ]
    )

    contexts = (
        section(
            [
                f"- **{c['context_type']}** `{c['ticket_reference'] or c['id']}` — {c['title']}; "
                f"approved by {c['approved_by']}; damping ×{c['damping_factor']:.2f}; "
                f"{'currently covering' if c['currently_covering'] else 'window lapsed'}"
                for c in bundle["contexts"]
            ]
        )
        or "- No business context records exist for this identity."
    )

    return f"""# Aegis Drift Forensic Dossier

| | |
|---|---|
| **Case reference** | `AD-DOSSIER-{identity["username"].upper()}-{now:%Y%m%d%H%M}` |
| **Classification** | CONFIDENTIAL — Internal security use |
| **Generated** | {now:%Y-%m-%d %H:%M:%S} UTC |
| **Generated by** | {author} |
| **Platform** | Aegis Drift v{settings.VERSION} |

---

## 1. Subject

| Field | Value |
|---|---|
| Identity | `{identity["username"]}` (`{identity["id"]}`) |
| Name | {identity["display_name"]} |
| Role | {identity["role_title"]}, {identity["department"]} |
| Manager | {identity["manager"] or "—"} |
| Location | {identity["location"]} |
| Privileged | {"yes" if identity["is_privileged"] else "no"} |
| Quarantined | {"yes" if identity["is_quarantined"] else "no"} |

## 2. Verdict

| Metric | Value |
|---|---|
| Composite risk | **{bundle["risk_score"]:.1f} / 100** |
| Unmitigated raw risk | {bundle["raw_risk_score"]:.1f} / 100 |
| Peak risk in window | {bundle["peak_risk"]:.1f} / 100 |
| Transition state | **{bundle["transition_state"]}** |
| Drift velocity | {bundle["drift_velocity"]:+.1f} points/day |
| Verdict | **{explanation["verdict"]}** |
| Engine confidence | {explanation["confidence"]:.0f}% |
| Events analysed | {bundle["event_count"]} |

## 3. Analyst brief

{explanation["narrative"]}

## 4. Findings

{findings}

## 5. Vector attribution

| Vector | Score | Share of verdict |
|---|---:|---:|
{attribution}

## 6. Blast radius

| Metric | Value |
|---|---|
| Blast radius score | **{blast["blast_radius_score"]:.1f} / 100** ({blast["impact_level"]}) |
| Assets reached | {blast["assets_touched"]} ({blast["crown_jewels_touched"]} crown jewels) |
| Records at risk | ~{blast["records_at_risk"]:,} |
| Modelled exposure | {blast["estimated_exposure_display"]} |
| PII exposed | {"yes" if blast["pii_exposed"] else "no"} |
| Cardholder data exposed | {"yes" if blast["cardholder_data_exposed"] else "no"} |

## 7. Regulatory exposure

{compliance}

## 8. MITRE ATT&CK alignment

{techniques}

## 9. Business context examined

{contexts}

## 10. Considerations against this verdict

{counter}

## 11. Recommended response

{actions}

## 12. Evidence chain

| Timestamp (UTC) | Resource | Action | Tier | Score | SHA-256 |
|---|---|---|---|---:|---|
{evidence}

---

*Digests are SHA-256 over each record's canonical field set. They verify this export
against the datastore; they are not a cryptographic signature over the document.
Exposure figures are per-record planning estimates, not legal determinations.*
"""
