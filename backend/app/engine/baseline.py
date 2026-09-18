"""Behavioural baseline construction and single-event anomaly scoring.

Every event is scored independently on eight orthogonal vectors, each normalised
to ``[0, 100]``. The sequence correlator (``app/engine/sequence.py``) is what turns
this per-event signal into a drifting cumulative risk.
"""

from __future__ import annotations

import math
from collections import Counter
from statistics import pstdev

from app.core.enums import (
    ANTI_TAMPER_ACTIONS,
    PRIVILEGED_ACTIONS,
    RiskVector,
)
from app.engine.types import BaselineView, EventView, IndicatorView, PeerStats

#: Laplace smoothing constant for the circadian histograms.
ALPHA = 0.5

#: Resources that are inherently sensitive regardless of who touches them.
HIGH_VALUE_KEYWORDS = (
    "crown_jewel",
    "payment",
    "cardholder",
    "customer_pii",
    "secret",
    "credential",
    "private_key",
    "root",
    "vault",
    "payroll",
    "salary",
)

#: Rough cross-department separation — engineering has no business in payroll, etc.
DEPARTMENT_FORBIDDEN: dict[str, tuple[str, ...]] = {
    "engineering": ("payroll", "salary", "financial_ledger", "exec_briefings", "cardholder", "workday"),
    "core platform": ("payroll", "salary", "exec_briefings", "greenhouse"),
    "infrastructure": ("payroll", "salary", "greenhouse", "exec_briefings"),
    "finance": ("github", "kubernetes", "ssh_key", "terraform", "source_repo"),
    "people ops": ("prod_database", "api_gateway", "aws_root", "kubernetes", "github"),
    "analytics": ("aws_root", "iam_policy", "prod_ssh", "payroll"),
    "legal": ("kubernetes", "prod_database", "terraform", "github"),
    "sales": ("kubernetes", "prod_database", "terraform", "github", "payroll"),
}

EARTH_RADIUS_KM = 6371.0
#: Above this implied speed a login pair is physically impossible.
IMPOSSIBLE_TRAVEL_KMH = 900.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two coordinates, in kilometres."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def shannon_entropy(counts: dict[str, int] | Counter) -> tuple[float, float]:
    """Return ``(entropy_bits, normalised_entropy)`` for a frequency map."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0, 0.0
    entropy = 0.0
    for c in counts.values():
        if c <= 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    unique = len([c for c in counts.values() if c > 0])
    normalised = entropy / math.log2(unique) if unique > 1 else 0.0
    return entropy, normalised


class BaselineEngine:
    """Builds baselines from history and scores individual events against them."""

    # ------------------------------------------------------------------ build
    def build(
        self,
        identity_id: str,
        username: str,
        department: str,
        role_title: str,
        peer_group_id: str,
        events: list[EventView],
    ) -> BaselineView:
        """Derive a ``BaselineView`` from an identity's historical event stream."""
        if not events:
            return BaselineView(
                identity_id=identity_id,
                username=username,
                department=department,
                role_title=role_title,
                peer_group_id=peer_group_id,
                hourly_distribution=dict.fromkeys(range(24), 1 / 24),
                dow_distribution=dict.fromkeys(range(7), 1 / 7),
            )

        total = len(events)

        hour_counts = Counter(e.occurred_at.hour for e in events)
        hourly = {h: (hour_counts.get(h, 0) + ALPHA) / (total + 24 * ALPHA) for h in range(24)}

        dow_counts = Counter(e.occurred_at.weekday() for e in events)
        dow = {d: (dow_counts.get(d, 0) + ALPHA) / (total + 7 * ALPHA) for d in range(7)}

        resource_counts = Counter(e.resource for e in events)
        _, norm_entropy = shannon_entropy(resource_counts)

        action_counts = Counter(e.action_key for e in events)

        # Daily volume statistics drive the volume vector.
        per_day: Counter[str] = Counter()
        bytes_per_day: Counter[str] = Counter()
        for e in events:
            day = e.occurred_at.date().isoformat()
            per_day[day] += 1
            bytes_per_day[day] += e.bytes_transferred
        daily_counts = list(per_day.values()) or [0]
        daily_bytes = list(bytes_per_day.values()) or [0]

        off_hours = sum(
            1 for e in events if e.is_off_hours or e.occurred_at.hour < 7 or e.occurred_at.hour > 20
        )

        timestamps = [e.occurred_at for e in events]
        span_days = max((max(timestamps) - min(timestamps)).days, 1)

        return BaselineView(
            identity_id=identity_id,
            username=username,
            department=department,
            role_title=role_title,
            peer_group_id=peer_group_id,
            hourly_distribution=hourly,
            dow_distribution=dow,
            common_resources=[r for r, _ in resource_counts.most_common(25)],
            resource_frequencies=dict(resource_counts.most_common(40)),
            known_ip_prefixes=sorted({_ip_prefix(e.ip_address) for e in events}),
            known_countries=sorted({e.country for e in events if e.country}),
            known_devices=sorted({e.device_id for e in events if e.device_id}),
            action_frequencies=dict(action_counts),
            resource_entropy=round(norm_entropy, 4),
            avg_daily_events=round(sum(daily_counts) / len(daily_counts), 2),
            stddev_daily_events=round(pstdev(daily_counts) if len(daily_counts) > 1 else 4.0, 2),
            avg_daily_bytes=round(sum(daily_bytes) / len(daily_bytes), 2),
            stddev_daily_bytes=round(pstdev(daily_bytes) if len(daily_bytes) > 1 else 1.0, 2),
            typical_max_sensitivity=_percentile_sensitivity(events),
            off_hours_ratio=round(off_hours / total, 4),
            sample_event_count=total,
            maturity=round(min(1.0, (total / 400) * 0.6 + (span_days / 30) * 0.4), 3),
        )

    # ------------------------------------------------------------------ score
    def score_event(
        self,
        event: EventView,
        baseline: BaselineView,
        *,
        peer: PeerStats | None = None,
        previous_event: EventView | None = None,
        rolling_day_count: int = 0,
        rolling_day_bytes: int = 0,
        indicators: dict[str, IndicatorView] | None = None,
    ) -> dict[str, float]:
        """Score one event on all eight vectors. Returns ``{vector: 0..100}``."""
        return {
            RiskVector.TEMPORAL.value: self._temporal(event, baseline),
            RiskVector.RESOURCE.value: self._resource(event, baseline),
            RiskVector.PRIVILEGE.value: self._privilege(event, baseline),
            RiskVector.PEER_DIVERGENCE.value: self._peer_divergence(event, baseline, peer),
            RiskVector.GEOVELOCITY.value: self._geovelocity(event, baseline, previous_event),
            RiskVector.VOLUME.value: self._volume(event, baseline, rolling_day_count, rolling_day_bytes),
            RiskVector.DEVICE.value: self._device(event, baseline),
            RiskVector.INTEL.value: self._intel(event, indicators or {}),
        }

    # ----------------------------------------------------------- vector: time
    def _temporal(self, event: EventView, baseline: BaselineView) -> float:
        """Rarity of this hour/weekday under the identity's circadian histogram."""
        hour_p = baseline.hourly_distribution.get(event.occurred_at.hour, 1 / 24)
        dow_p = baseline.dow_distribution.get(event.occurred_at.weekday(), 1 / 7)

        # A uniform distribution gives p = 1/24; scaling by 12 puts "half as likely
        # as uniform" at zero anomaly and vanishingly rare hours near 1.0.
        score = max(0.0, 1.0 - hour_p * 12.0)

        if event.is_off_hours:
            score = max(score, 0.72)
        if event.occurred_at.weekday() >= 5 and dow_p < 0.08:
            score = max(score, 0.68)
        # A first-ever off-hours event for a strictly 9-5 identity is maximally odd.
        if baseline.off_hours_ratio < 0.01 and event.is_off_hours:
            score = max(score, 0.85)
        return round(min(100.0, score * 100.0), 2)

    # ------------------------------------------------------- vector: resource
    def _resource(self, event: EventView, baseline: BaselineView) -> float:
        """Novelty of the resource plus any jump above the usual sensitivity tier."""
        resource = event.resource.lower()
        known = event.resource in baseline.resource_frequencies
        familiarity = baseline.resource_frequencies.get(event.resource, 0)

        if known and familiarity >= 5:
            novelty = 8.0
        elif known:
            novelty = 28.0
        else:
            novelty = 68.0

        sens_delta = event.sensitivity_level - baseline.typical_max_sensitivity
        sensitivity = min(100.0, 38.0 + sens_delta * 22.0) if sens_delta > 0 else 10.0

        score = novelty * 0.42 + sensitivity * 0.58
        if any(k in resource for k in HIGH_VALUE_KEYWORDS) and not known:
            score = min(100.0, score + 18.0)
        return round(min(100.0, score), 2)

    # ------------------------------------------------------ vector: privilege
    def _privilege(self, event: EventView, baseline: BaselineView) -> float:
        """Weight of the action itself, discounted if the identity does it routinely."""
        action = event.action_key
        if action in ANTI_TAMPER_ACTIONS:
            return 100.0

        if action in PRIVILEGED_ACTIONS:
            base = 88.0
        elif action in {"write", "delete", "export", "query_bulk", "download", "share_external"}:
            base = 52.0
        elif action in {"read", "query", "list", "view", "login"}:
            base = 12.0
        else:
            base = 26.0

        # Routine use of a privileged action for this identity is far less alarming.
        seen = baseline.action_frequencies.get(action, 0)
        if seen >= 10:
            base *= 0.45
        elif seen >= 3:
            base *= 0.7

        if event.outcome.upper() in {"DENIED", "FAILURE"} and base >= 50:
            base = min(100.0, base + 10.0)  # probing for permissions they lack
        return round(min(100.0, base), 2)

    # ----------------------------------------------------------- vector: peer
    def _peer_divergence(self, event: EventView, baseline: BaselineView, peer: PeerStats | None) -> float:
        """How far outside the cohort's normal surface this action falls."""
        dept = baseline.department.lower()
        resource = event.resource.lower()
        score = 14.0

        for forbidden in DEPARTMENT_FORBIDDEN.get(dept, ()):
            if forbidden in resource:
                score += 62.0
                break

        if peer and peer.shared_resources:
            if event.resource not in peer.shared_resources:
                score += 22.0
            if event.sensitivity_level > peer.mean_max_sensitivity + 1:
                score += 24.0
        elif event.resource not in baseline.common_resources:
            score += 16.0

        if event.action_key in PRIVILEGED_ACTIONS and "engineer" not in baseline.role_title.lower():
            score += 18.0
        return round(min(100.0, score), 2)

    # ---------------------------------------------------- vector: geovelocity
    def _geovelocity(self, event: EventView, baseline: BaselineView, previous: EventView | None) -> float:
        """Unfamiliar network origin, plus impossible-travel between consecutive events."""
        score = 0.0

        if event.country and baseline.known_countries and event.country not in baseline.known_countries:
            score = max(score, 62.0)
        if baseline.known_ip_prefixes and _ip_prefix(event.ip_address) not in baseline.known_ip_prefixes:
            score = max(score, 45.0)

        if previous and None not in (event.latitude, event.longitude, previous.latitude, previous.longitude):
            hours = max((event.occurred_at - previous.occurred_at).total_seconds() / 3600.0, 1 / 60)
            distance = haversine_km(
                previous.latitude,  # type: ignore[arg-type]
                previous.longitude,  # type: ignore[arg-type]
                event.latitude,  # type: ignore[arg-type]
                event.longitude,  # type: ignore[arg-type]
            )
            if distance > 100:
                speed = distance / hours
                if speed > IMPOSSIBLE_TRAVEL_KMH:
                    # Scale from 80 at exactly the threshold up to 100 well beyond it.
                    excess = min(1.0, (speed - IMPOSSIBLE_TRAVEL_KMH) / (4 * IMPOSSIBLE_TRAVEL_KMH))
                    score = max(score, 80.0 + excess * 20.0)
                elif speed > IMPOSSIBLE_TRAVEL_KMH * 0.55:
                    score = max(score, 55.0)
        return round(min(100.0, score), 2)

    # --------------------------------------------------------- vector: volume
    def _volume(
        self,
        event: EventView,
        baseline: BaselineView,
        rolling_day_count: int,
        rolling_day_bytes: int,
    ) -> float:
        """Z-scored deviation in today's event count and egress volume."""
        score = 0.0

        if baseline.avg_daily_events > 0:
            sigma = max(baseline.stddev_daily_events, 2.0)
            z = (rolling_day_count - baseline.avg_daily_events) / sigma
            if z > 2:
                score = max(score, min(85.0, 30.0 + (z - 2) * 18.0))

        if rolling_day_bytes > 0 and baseline.avg_daily_bytes >= 0:
            sigma_b = max(baseline.stddev_daily_bytes, 1.0)
            zb = (rolling_day_bytes - baseline.avg_daily_bytes) / sigma_b
            if zb > 2:
                score = max(score, min(95.0, 40.0 + (zb - 2) * 15.0))

        # A single very large transfer is suspicious regardless of the daily rollup.
        if event.bytes_transferred > 500_000_000:
            score = max(score, 88.0)
        elif event.bytes_transferred > 50_000_000:
            score = max(score, 62.0)
        if event.record_count > 100_000:
            score = max(score, 90.0)
        elif event.record_count > 10_000:
            score = max(score, 66.0)
        return round(min(100.0, score), 2)

    # --------------------------------------------------------- vector: device
    def _device(self, event: EventView, baseline: BaselineView) -> float:
        if not event.device_id:
            return 0.0
        if not baseline.known_devices:
            return 12.0
        if event.device_id in baseline.known_devices:
            return 0.0
        return 58.0

    # ---------------------------------------------------------- vector: intel
    def _intel(self, event: EventView, indicators: dict[str, IndicatorView]) -> float:
        """Match the event's network artefacts against the threat-intel feed."""
        best = 0.0
        for candidate in (event.ip_address, event.asn, event.user_agent):
            if not candidate:
                continue
            hit = indicators.get(candidate)
            if hit:
                best = max(best, float(min(100, hit.confidence)))
        return round(best, 2)


def _ip_prefix(ip: str) -> str:
    """First three octets of an IPv4 address (a rough /24 network identity)."""
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def _percentile_sensitivity(events: list[EventView]) -> int:
    """95th-percentile sensitivity rather than the max, so one outlier in the
    training window does not permanently raise the identity's ceiling."""
    levels = sorted(e.sensitivity_level for e in events)
    if not levels:
        return 2
    idx = min(len(levels) - 1, int(len(levels) * 0.95))
    return levels[idx]


def classify_hour_profile(hourly: dict[int, float]) -> str:
    """Human label for a circadian histogram, used in analyst-facing copy."""
    if not hourly:
        return "unknown"
    peak = max(hourly, key=lambda h: hourly[h])
    if 6 <= peak <= 11:
        return "early-shift (06:00-11:00 peak)"
    if 12 <= peak <= 17:
        return "standard business hours (12:00-17:00 peak)"
    if 18 <= peak <= 22:
        return "late-shift (18:00-22:00 peak)"
    return "overnight / irregular"
