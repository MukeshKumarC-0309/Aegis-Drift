"""Blast-radius modelling: what an identity could reach, and what that would cost.

Produces a graph the console renders topologically, plus a regulatory exposure
assessment derived from the classification of the assets actually touched.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.engine.types import EventView


@dataclass(slots=True)
class AssetView:
    """Classification metadata for one protected resource."""

    key: str
    display_name: str
    category: str = "application"
    sensitivity_level: int = 2
    environment: str = "production"
    owner_team: str = "Unassigned"
    contains_pii: bool = False
    contains_phi: bool = False
    contains_cardholder_data: bool = False
    is_crown_jewel: bool = False
    record_estimate: int = 0
    compliance_scopes: list[str] = field(default_factory=list)


#: Per-record breach cost by data class, from published industry incident studies.
#: These are planning estimates surfaced to the analyst, not precise liabilities.
COST_PER_RECORD = {
    "phi": 408.0,
    "cardholder": 262.0,
    "pii": 165.0,
    "generic": 48.0,
}

FRAMEWORK_RULES: tuple[tuple[str, str, str], ...] = (
    ("GDPR Art. 32/33", "pii", "72-hour supervisory authority notification obligation"),
    ("PCI DSS v4.0 Req. 10", "cardholder", "Cardholder data environment access requires forensic review"),
    ("HIPAA §164.308", "phi", "Protected health information breach assessment required"),
    ("SOC 2 CC6.1", "crown_jewel", "Logical access control exception requires auditor disclosure"),
    ("ISO 27001 A.9", "privileged", "Access control non-conformity — corrective action required"),
)


class BlastRadiusEngine:
    """Computes reachable assets, downstream impact and compliance exposure."""

    def compute(
        self,
        identity_id: str,
        username: str,
        department: str,
        role_title: str,
        events: list[EventView],
        assets: dict[str, AssetView],
        composite_risk: float,
        *,
        is_privileged: bool = False,
    ) -> dict:
        touched = self._touched_assets(events, assets)

        crown_jewels = [a for a in touched.values() if a.is_crown_jewel]
        pii_assets = [a for a in touched.values() if a.contains_pii]
        pci_assets = [a for a in touched.values() if a.contains_cardholder_data]
        phi_assets = [a for a in touched.values() if a.contains_phi]

        records_at_risk = sum(a.record_estimate for a in touched.values())
        exposure = self._financial_exposure(touched)

        score = self._score(touched, composite_risk, is_privileged)
        nodes, edges = self._graph(identity_id, username, role_title, department, events, touched)

        return {
            "identity_id": identity_id,
            "username": username,
            "blast_radius_score": round(score, 1),
            "impact_level": self._impact_level(score),
            "assets_touched": len(touched),
            "crown_jewels_touched": len(crown_jewels),
            "crown_jewel_names": [a.display_name for a in crown_jewels],
            "pii_exposed": bool(pii_assets),
            "cardholder_data_exposed": bool(pci_assets),
            "phi_exposed": bool(phi_assets),
            "records_at_risk": records_at_risk,
            "estimated_exposure_usd": exposure,
            "estimated_exposure_display": _money(exposure),
            "lateral_reach": self._lateral_reach(touched, is_privileged),
            "compliance_impacts": self._compliance(touched, is_privileged),
            "graph": {"nodes": nodes, "edges": edges},
            "asset_breakdown": [
                {
                    "key": a.key,
                    "name": a.display_name,
                    "category": a.category,
                    "sensitivity": a.sensitivity_level,
                    "environment": a.environment,
                    "owner_team": a.owner_team,
                    "crown_jewel": a.is_crown_jewel,
                    "pii": a.contains_pii,
                    "cardholder": a.contains_cardholder_data,
                    "records": a.record_estimate,
                }
                for a in sorted(touched.values(), key=lambda x: -x.sensitivity_level)
            ],
        }

    # ------------------------------------------------------------------ pieces
    @staticmethod
    def _touched_assets(events: list[EventView], assets: dict[str, AssetView]) -> dict[str, AssetView]:
        """Resolve each distinct resource to a catalogued asset, inferring unknowns."""
        touched: dict[str, AssetView] = {}
        for event in events:
            if event.resource in touched:
                continue
            known = assets.get(event.resource)
            touched[event.resource] = known or _infer_asset(event)
        return touched

    @staticmethod
    def _financial_exposure(touched: dict[str, AssetView]) -> float:
        total = 0.0
        for asset in touched.values():
            if not asset.record_estimate:
                continue
            if asset.contains_phi:
                rate = COST_PER_RECORD["phi"]
            elif asset.contains_cardholder_data:
                rate = COST_PER_RECORD["cardholder"]
            elif asset.contains_pii:
                rate = COST_PER_RECORD["pii"]
            else:
                rate = COST_PER_RECORD["generic"]
            total += asset.record_estimate * rate
        return round(total, 2)

    @staticmethod
    def _score(touched: dict[str, AssetView], composite_risk: float, is_privileged: bool) -> float:
        """Blend asset criticality with how likely the identity is to actually act."""
        if not touched:
            return 0.0
        criticality = 0.0
        for asset in touched.values():
            weight = {1: 2.0, 2: 5.0, 3: 11.0, 4: 20.0, 5: 32.0}.get(asset.sensitivity_level, 5.0)
            if asset.is_crown_jewel:
                weight *= 1.4
            if asset.environment == "production":
                weight *= 1.2
            criticality += weight
        criticality = min(100.0, criticality)

        # Reachability alone is not risk — weight it by the identity's current score.
        likelihood = min(1.0, composite_risk / 100.0)
        score = criticality * (0.45 + 0.55 * likelihood)
        if is_privileged:
            score = min(100.0, score * 1.15)
        return min(100.0, score)

    @staticmethod
    def _impact_level(score: float) -> str:
        if score >= 80:
            return "CATASTROPHIC"
        if score >= 60:
            return "SEVERE"
        if score >= 38:
            return "MODERATE"
        if score >= 18:
            return "LIMITED"
        return "MINIMAL"

    @staticmethod
    def _lateral_reach(touched: dict[str, AssetView], is_privileged: bool) -> dict:
        """Estimate onward movement from the credential and IAM assets reached."""
        credential_assets = [
            a
            for a in touched.values()
            if a.category in {"secret_store", "iam", "identity"} or "key" in a.key.lower()
        ]
        environments = sorted({a.environment for a in touched.values()})
        teams = sorted({a.owner_team for a in touched.values() if a.owner_team != "Unassigned"})
        multiplier = 4 if is_privileged else 2
        return {
            "credential_assets_reached": len(credential_assets),
            "environments": environments,
            "downstream_teams": teams,
            "estimated_additional_systems": len(credential_assets) * multiplier,
            "can_escalate_to_admin": any(a.category == "iam" for a in touched.values()),
        }

    @staticmethod
    def _compliance(touched: dict[str, AssetView], is_privileged: bool) -> list[dict]:
        flags = {
            "pii": any(a.contains_pii for a in touched.values()),
            "cardholder": any(a.contains_cardholder_data for a in touched.values()),
            "phi": any(a.contains_phi for a in touched.values()),
            "crown_jewel": any(a.is_crown_jewel for a in touched.values()),
            "privileged": is_privileged or any(a.category == "iam" for a in touched.values()),
        }
        impacts = []
        for framework, flag, obligation in FRAMEWORK_RULES:
            if not flags.get(flag):
                continue
            scoped = [a.display_name for a in touched.values() if _has_flag(a, flag)][:5]
            impacts.append(
                {
                    "framework": framework,
                    "triggered_by": flag,
                    "obligation": obligation,
                    "severity": "CRITICAL" if flag in {"cardholder", "phi"} else "HIGH",
                    "in_scope_assets": scoped,
                }
            )
        # Surface explicit scopes declared on the assets themselves.
        declared = sorted({s for a in touched.values() for s in a.compliance_scopes})
        for scope in declared:
            if not any(scope.lower() in i["framework"].lower() for i in impacts):
                impacts.append(
                    {
                        "framework": scope,
                        "triggered_by": "asset_declaration",
                        "obligation": "Asset is explicitly declared in scope for this framework",
                        "severity": "MEDIUM",
                        "in_scope_assets": [
                            a.display_name for a in touched.values() if scope in a.compliance_scopes
                        ][:5],
                    }
                )
        return impacts

    @staticmethod
    def _graph(
        identity_id: str,
        username: str,
        role_title: str,
        department: str,
        events: list[EventView],
        touched: dict[str, AssetView],
    ) -> tuple[list[dict], list[dict]]:
        """Force-directed graph: identity at the centre, assets grouped by category."""
        nodes: list[dict] = [
            {
                "id": identity_id,
                "label": username,
                "type": "identity",
                "sublabel": f"{role_title} · {department}",
                "sensitivity": 0,
                "size": 26,
            }
        ]
        edges: list[dict] = []

        # Aggregate interactions per resource so edge weight means something.
        interactions: dict[str, dict] = {}
        for event in events:
            entry = interactions.setdefault(
                event.resource, {"count": 0, "actions": set(), "max_score": 0.0, "bytes": 0}
            )
            entry["count"] += 1
            entry["actions"].add(event.action)
            entry["bytes"] += event.bytes_transferred

        category_nodes: set[str] = set()
        for key, asset in touched.items():
            stats = interactions.get(key, {"count": 1, "actions": set(), "bytes": 0})
            category_id = f"cat::{asset.category}"
            if category_id not in category_nodes:
                category_nodes.add(category_id)
                nodes.append(
                    {
                        "id": category_id,
                        "label": asset.category.replace("_", " ").title(),
                        "type": "category",
                        "sublabel": asset.environment,
                        "sensitivity": 0,
                        "size": 14,
                    }
                )
                edges.append({"source": identity_id, "target": category_id, "weight": 1, "kind": "groups"})

            nodes.append(
                {
                    "id": key,
                    "label": asset.display_name,
                    "type": "crown_jewel" if asset.is_crown_jewel else "asset",
                    "sublabel": f"Tier {asset.sensitivity_level} · {asset.owner_team}",
                    "sensitivity": asset.sensitivity_level,
                    "records": asset.record_estimate,
                    "size": 8 + asset.sensitivity_level * 3,
                }
            )
            edges.append(
                {
                    "source": category_id,
                    "target": key,
                    "weight": stats["count"],
                    "kind": "accesses",
                    "actions": sorted(stats["actions"]),
                    "bytes": stats["bytes"],
                }
            )
        return nodes, edges


def _has_flag(asset: AssetView, flag: str) -> bool:
    return {
        "pii": asset.contains_pii,
        "cardholder": asset.contains_cardholder_data,
        "phi": asset.contains_phi,
        "crown_jewel": asset.is_crown_jewel,
        "privileged": asset.category == "iam",
    }.get(flag, False)


def _infer_asset(event: EventView) -> AssetView:
    """Best-effort classification for a resource missing from the asset catalogue."""
    key = event.resource
    lowered = key.lower()
    pii = any(k in lowered for k in ("customer", "pii", "user_db", "profile", "email"))
    pci = any(k in lowered for k in ("payment", "card", "billing", "stripe"))
    phi = any(k in lowered for k in ("health", "medical", "patient", "phi"))

    if any(k in lowered for k in ("iam", "role", "policy", "permission")):
        category = "iam"
    elif any(k in lowered for k in ("secret", "vault", "key", "credential")):
        category = "secret_store"
    elif any(k in lowered for k in ("sql", "postgres", "database", "db", "warehouse", "snowflake")):
        category = "database"
    elif any(k in lowered for k in ("s3", "bucket", "datalake", "storage")):
        category = "object_store"
    elif any(k in lowered for k in ("repo", "github", "gitlab")):
        category = "source_code"
    elif any(k in lowered for k in ("okta", "sso", "entra", "auth")):
        category = "identity"
    else:
        category = "application"

    return AssetView(
        key=key,
        display_name=key.replace("_", " ").title(),
        category=category,
        sensitivity_level=event.sensitivity_level,
        contains_pii=pii,
        contains_cardholder_data=pci,
        contains_phi=phi,
        is_crown_jewel=event.sensitivity_level >= 5,
        record_estimate=event.record_count,
    )


def _money(value: float) -> str:
    if value >= 1_000_000:
        return f"${value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"${value / 1_000:.0f}K"
    return f"${value:,.0f}"
