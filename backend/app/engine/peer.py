"""Peer-cohort statistics — the control group every identity is measured against.

An identity doing something unusual *for them* is interesting; doing something no
one in their role has ever done is far more so. These cohort aggregates are what
let the engine tell those two cases apart.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from statistics import fmean, pstdev

from app.engine.types import BaselineView, PeerStats

#: A cohort needs at least this many members before its statistics mean anything.
MIN_COHORT_SIZE = 3

#: Resources held in common by at least this share of the cohort are "expected".
SHARED_RESOURCE_THRESHOLD = 0.4


@dataclass(slots=True)
class CohortMember:
    identity_id: str
    username: str
    department: str
    role_title: str
    risk_score: float
    daily_events: float
    max_sensitivity: int
    resources: list[str]


def cohort_key(department: str, role_title: str) -> str:
    """Stable cohort identifier. Role seniority is stripped so a 'Senior Frontend
    Engineer' and a 'Frontend Engineer' land in the same behavioural cohort."""
    role = role_title.lower()
    for prefix in ("senior ", "staff ", "principal ", "lead ", "junior ", "associate ", "chief "):
        role = role.removeprefix(prefix)
    slug = f"{department}_{role}".lower()
    return "".join(c if c.isalnum() or c == "_" else "_" for c in slug).strip("_")


class PeerEngine:
    """Builds and serves cohort statistics."""

    def build_cohorts(self, members: list[CohortMember]) -> dict[str, PeerStats]:
        """Group members by cohort key and compute aggregate statistics."""
        grouped: dict[str, list[CohortMember]] = defaultdict(list)
        for member in members:
            grouped[cohort_key(member.department, member.role_title)].append(member)

        cohorts: dict[str, PeerStats] = {}
        for key, group in grouped.items():
            cohorts[key] = self._aggregate(key, group)

        # Members in a cohort too small to be meaningful fall back to a
        # department-wide cohort, which is coarser but statistically sounder.
        by_department: dict[str, list[CohortMember]] = defaultdict(list)
        for member in members:
            by_department[member.department.lower()].append(member)
        for key, group in grouped.items():
            if len(group) >= MIN_COHORT_SIZE:
                continue
            dept_group = by_department.get(group[0].department.lower(), group)
            if len(dept_group) >= MIN_COHORT_SIZE:
                fallback = self._aggregate(f"dept::{group[0].department.lower()}", dept_group)
                fallback.key = key  # keep the caller's lookup key
                cohorts[key] = fallback
        return cohorts

    @staticmethod
    def _aggregate(key: str, group: list[CohortMember]) -> PeerStats:
        risks = [m.risk_score for m in group]
        counts = Counter(r for m in group for r in set(m.resources))
        threshold = max(1, int(len(group) * SHARED_RESOURCE_THRESHOLD))
        shared = sorted(r for r, n in counts.items() if n >= threshold)

        return PeerStats(
            key=key,
            member_count=len(group),
            shared_resources=shared,
            mean_risk=round(fmean(risks), 2) if risks else 5.0,
            stddev_risk=round(pstdev(risks), 2) if len(risks) > 1 else 3.0,
            mean_daily_events=round(fmean([m.daily_events for m in group]), 2),
            mean_max_sensitivity=round(fmean([float(m.max_sensitivity) for m in group]), 2),
        )

    @staticmethod
    def outliers(members: list[CohortMember], cohorts: dict[str, PeerStats], z_threshold: float = 2.0):
        """Identities whose risk sits ``z_threshold`` sigma above their own cohort."""
        found = []
        for member in members:
            stats = cohorts.get(cohort_key(member.department, member.role_title))
            if not stats or stats.member_count < MIN_COHORT_SIZE:
                continue
            sigma = max(stats.stddev_risk, 1.0)
            z = (member.risk_score - stats.mean_risk) / sigma
            if z >= z_threshold:
                found.append(
                    {
                        "identity_id": member.identity_id,
                        "username": member.username,
                        "cohort": stats.key,
                        "risk_score": member.risk_score,
                        "cohort_mean": stats.mean_risk,
                        "z_score": round(z, 2),
                    }
                )
        return sorted(found, key=lambda o: -o["z_score"])

    @staticmethod
    def from_baselines(baselines: list[BaselineView], risks: dict[str, float]) -> list[CohortMember]:
        """Adapt stored baselines into cohort members."""
        return [
            CohortMember(
                identity_id=b.identity_id,
                username=b.username,
                department=b.department,
                role_title=b.role_title,
                risk_score=risks.get(b.identity_id, 5.0),
                daily_events=b.avg_daily_events,
                max_sensitivity=b.typical_max_sensitivity,
                resources=b.common_resources,
            )
            for b in baselines
        ]
