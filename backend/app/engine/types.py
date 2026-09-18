"""Plain dataclasses the engine works with.

The engine deliberately does not import SQLAlchemy models: it operates on these
frozen value objects so it stays synchronous, pure and trivially unit-testable.
Adapters in ``app/services`` convert ORM rows to and from these types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.enums import EventType, RiskVector, TransitionState


@dataclass(slots=True)
class EventView:
    """A single security event, normalised for scoring."""

    id: str
    identity_id: str
    occurred_at: datetime
    event_type: EventType
    resource: str
    action: str
    sensitivity_level: int = 1
    outcome: str = "SUCCESS"
    ip_address: str = "10.0.0.1"
    country: str = "US"
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    device_id: str | None = None
    user_agent: str | None = None
    bytes_transferred: int = 0
    record_count: int = 0
    is_off_hours: bool = False
    context_tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def action_key(self) -> str:
        return self.action.lower().strip()


@dataclass(slots=True)
class BaselineView:
    """The learned behavioural norm for one identity."""

    identity_id: str
    username: str
    department: str
    role_title: str
    peer_group_id: str
    hourly_distribution: dict[int, float] = field(default_factory=dict)
    dow_distribution: dict[int, float] = field(default_factory=dict)
    common_resources: list[str] = field(default_factory=list)
    resource_frequencies: dict[str, int] = field(default_factory=dict)
    known_ip_prefixes: list[str] = field(default_factory=list)
    known_countries: list[str] = field(default_factory=list)
    known_devices: list[str] = field(default_factory=list)
    action_frequencies: dict[str, int] = field(default_factory=dict)
    resource_entropy: float = 0.5
    avg_daily_events: float = 20.0
    stddev_daily_events: float = 6.0
    avg_daily_bytes: float = 0.0
    stddev_daily_bytes: float = 1.0
    typical_max_sensitivity: int = 2
    off_hours_ratio: float = 0.02
    sample_event_count: int = 0
    maturity: float = 0.0

    @property
    def is_mature(self) -> bool:
        """Below ~200 samples the distributions are too sparse to trust fully."""
        return self.sample_event_count >= 200


@dataclass(slots=True)
class ContextView:
    """An approved business justification that can damp risk."""

    id: str
    identity_id: str
    context_type: str
    title: str
    description: str
    ticket_reference: str | None
    valid_from: datetime
    valid_until: datetime
    damping_factor: float
    target_resources: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    approved_by: str = "unknown"
    is_active: bool = True

    def covers(self, moment: datetime) -> bool:
        return self.is_active and self.valid_from <= moment <= self.valid_until


@dataclass(slots=True)
class PeerStats:
    """Aggregate behaviour of an identity's cohort."""

    key: str
    member_count: int = 1
    shared_resources: list[str] = field(default_factory=list)
    mean_risk: float = 5.0
    stddev_risk: float = 3.0
    mean_daily_events: float = 20.0
    mean_max_sensitivity: float = 2.0


@dataclass(slots=True)
class RuleView:
    """A detection rule as the engine sees it."""

    id: str
    slug: str
    name: str
    severity: str
    conditions: dict[str, Any]
    risk_boost: float = 10.0
    mitre_techniques: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    suppress_when_context: bool = True
    enabled: bool = True


@dataclass(slots=True)
class IndicatorView:
    indicator_type: str
    value: str
    confidence: int
    severity: str
    source_feed: str
    description: str | None = None


@dataclass(slots=True)
class ScoredEvent:
    """Result of scoring one event against a baseline."""

    event: EventView
    vector_scores: dict[str, float]
    raw_score: float
    damped_score: float
    is_damped: bool
    damping_reason: str | None
    matched_rules: list[str]
    anti_tamper: bool
    cumulative_risk: float = 0.0
    raw_cumulative_risk: float = 0.0
    state: TransitionState = TransitionState.STABLE

    def top_vectors(self, n: int = 3) -> list[str]:
        return [k for k, _ in sorted(self.vector_scores.items(), key=lambda kv: -kv[1])[:n]]


@dataclass(slots=True)
class CorrelationResult:
    """Output of running a full event stream through the sequence correlator."""

    identity_id: str
    cumulative_risk: float
    raw_cumulative_risk: float
    transition_state: TransitionState
    drift_velocity: float
    dominant_vectors: list[str]
    vector_scores: dict[str, float]
    scored_events: list[ScoredEvent]
    matched_rule_ids: list[str]
    anti_tamper_triggered: bool
    damping_applied: bool
    damping_reasons: list[str]
    peak_risk: float
    event_count: int

    @property
    def timeline(self) -> list[dict[str, Any]]:
        """Chart-ready projection of the scored stream."""
        return [
            {
                "event_id": s.event.id,
                "timestamp": s.event.occurred_at.isoformat(),
                "resource": s.event.resource,
                "action": s.event.action,
                "event_type": s.event.event_type.value,
                "sensitivity": s.event.sensitivity_level,
                "event_score": round(s.damped_score, 1),
                "raw_event_score": round(s.raw_score, 1),
                "cumulative_risk": round(s.cumulative_risk, 1),
                "raw_cumulative_risk": round(s.raw_cumulative_risk, 1),
                "is_damped": s.is_damped,
                "damping_reason": s.damping_reason,
                "anti_tamper": s.anti_tamper,
                "matched_rules": s.matched_rules,
                "state": s.state.value,
                "vectors": {k: round(v, 1) for k, v in s.vector_scores.items()},
            }
            for s in self.scored_events
        ]


DEFAULT_VECTOR_WEIGHTS: dict[str, float] = {
    RiskVector.TEMPORAL.value: 0.14,
    RiskVector.RESOURCE.value: 0.22,
    RiskVector.PRIVILEGE.value: 0.20,
    RiskVector.PEER_DIVERGENCE.value: 0.13,
    RiskVector.GEOVELOCITY.value: 0.12,
    RiskVector.VOLUME.value: 0.11,
    RiskVector.DEVICE.value: 0.05,
    RiskVector.INTEL.value: 0.03,
}
