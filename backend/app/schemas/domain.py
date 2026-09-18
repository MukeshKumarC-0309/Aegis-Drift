"""Schemas for the monitored-estate domain: identities, events, alerts, contexts."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field, field_validator

from app.core.enums import (
    AlertStatus,
    CasePriority,
    CaseStatus,
    ContextType,
    EventType,
    IndicatorType,
    ResponseAction,
    Severity,
    TransitionState,
)
from app.schemas.common import ORMModel

Sensitivity = Annotated[int, Field(ge=1, le=5)]


# ---------------------------------------------------------------------- identity
class IdentityRead(ORMModel):
    id: str
    username: str
    display_name: str
    email: str
    department: str
    role_title: str
    manager: str | None
    location: str
    employment_type: str
    peer_group_id: str
    is_privileged: bool
    is_service_account: bool
    is_active: bool
    is_quarantined: bool
    on_watchlist: bool
    risk_score: float
    raw_risk_score: float
    transition_state: TransitionState
    drift_velocity: float
    dominant_vector: str
    vector_scores: dict[str, float]
    event_count: int
    last_event_at: datetime | None
    last_scored_at: datetime | None


class IdentityCreate(BaseModel):
    username: Annotated[str, Field(min_length=2, max_length=120)]
    display_name: str
    email: str
    department: str
    role_title: str
    manager: str | None = None
    location: str = "Unknown"
    employment_type: str = "FULL_TIME"
    is_privileged: bool = False
    is_service_account: bool = False


class IdentityUpdate(BaseModel):
    display_name: str | None = None
    department: str | None = None
    role_title: str | None = None
    manager: str | None = None
    location: str | None = None
    is_privileged: bool | None = None
    is_active: bool | None = None
    on_watchlist: bool | None = None


class BaselineRead(ORMModel):
    id: str
    identity_id: str
    hourly_distribution: dict
    dow_distribution: dict
    common_resources: list
    known_countries: list
    known_devices: list
    resource_entropy: float
    avg_daily_events: float
    stddev_daily_events: float
    typical_max_sensitivity: int
    off_hours_ratio: float
    sample_event_count: int
    maturity: float
    version: int
    window_start: datetime | None
    window_end: datetime | None
    updated_at: datetime


# ------------------------------------------------------------------------ event
class EventIngest(BaseModel):
    """One telemetry event submitted to the ingest API."""

    identity: str = Field(description="Identity id or username.")
    occurred_at: datetime | None = None
    event_type: EventType
    resource: Annotated[str, Field(min_length=1, max_length=255)]
    action: Annotated[str, Field(min_length=1, max_length=64)]
    sensitivity_level: Sensitivity = 1
    outcome: str = "SUCCESS"
    ip_address: str = "10.0.0.1"
    country: str = "US"
    city: str | None = None
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    asn: str | None = None
    device_id: str | None = None
    user_agent: str | None = None
    bytes_transferred: Annotated[int, Field(ge=0)] = 0
    record_count: Annotated[int, Field(ge=0)] = 0
    is_off_hours: bool | None = None
    context_tags: list[str] = Field(default_factory=list)
    source: str = "api"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("country")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()[:4]


class EventBatchIngest(BaseModel):
    events: Annotated[list[EventIngest], Field(min_length=1, max_length=1000)]
    recompute: bool = Field(default=True, description="Re-score affected identities synchronously.")


class EventRead(ORMModel):
    id: str
    identity_id: str
    occurred_at: datetime
    ingested_at: datetime
    event_type: EventType
    resource: str
    action: str
    outcome: str
    sensitivity_level: int
    ip_address: str
    country: str
    city: str | None
    asn: str | None
    device_id: str | None
    bytes_transferred: int
    record_count: int
    is_off_hours: bool
    anomaly_score: float
    damped_score: float
    vector_scores: dict[str, float]
    is_damped: bool
    damping_reason: str | None
    matched_rules: list
    context_tags: list
    source: str


class IngestResult(BaseModel):
    accepted: int
    rejected: int
    identities_rescored: list[str]
    alerts_raised: list[str]
    errors: list[dict] = Field(default_factory=list)
    duration_ms: int


# ------------------------------------------------------------------------ alert
class AlertRead(ORMModel):
    id: str
    identity_id: str
    case_id: str | None
    title: str
    summary: str
    severity: Severity
    status: AlertStatus
    confidence: float
    risk_score: float
    raw_risk_score: float
    transition_state: TransitionState
    drift_velocity: float
    context_damped: bool
    damping_reason: str | None
    anti_tamper_override: bool
    dominant_vectors: list
    vector_scores: dict
    mitre_techniques: list
    matched_rule_ids: list
    assigned_to_id: str | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    resolution_note: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    created_at: datetime


class AlertWithIdentity(AlertRead):
    username: str | None = None
    department: str | None = None
    role_title: str | None = None


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    assigned_to_id: str | None = None
    resolution_note: str | None = None
    severity: Severity | None = None


# ---------------------------------------------------------------------- context
class ContextCreate(BaseModel):
    identity_id: str
    context_type: ContextType = ContextType.APPROVED_CHANGE_TICKET
    title: Annotated[str, Field(min_length=3, max_length=200)]
    description: str = ""
    ticket_reference: str | None = None
    source_system: str = "manual"
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    valid_days: Annotated[int, Field(ge=1, le=365)] = 14
    damping_factor: Annotated[float, Field(ge=0.1, le=0.95)] = 0.35
    target_resources: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    approved_by: Annotated[str, Field(min_length=2, max_length=160)]


class ContextUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    valid_until: datetime | None = None
    damping_factor: Annotated[float, Field(ge=0.1, le=0.95)] | None = None
    target_resources: list[str] | None = None
    is_active: bool | None = None


class ContextRead(ORMModel):
    id: str
    identity_id: str
    context_type: ContextType
    title: str
    description: str
    ticket_reference: str | None
    source_system: str
    valid_from: datetime
    valid_until: datetime
    damping_factor: float
    target_resources: list
    allowed_actions: list
    approved_by: str
    is_active: bool
    applied_count: int
    created_at: datetime


# ------------------------------------------------------------------------- case
class CaseCreate(BaseModel):
    title: Annotated[str, Field(min_length=3, max_length=255)]
    description: str = ""
    priority: CasePriority = CasePriority.P3
    severity: Severity = Severity.MEDIUM
    primary_identity_id: str | None = None
    assignee_id: str | None = None
    alert_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: CaseStatus | None = None
    priority: CasePriority | None = None
    severity: Severity | None = None
    assignee_id: str | None = None
    tags: list[str] | None = None
    closure_reason: str | None = None


class CaseEntryCreate(BaseModel):
    body: Annotated[str, Field(min_length=1, max_length=8000)]
    entry_type: str = "COMMENT"


class CaseEntryRead(ORMModel):
    id: str
    case_id: str
    entry_type: str
    author_id: str | None
    author_label: str
    body: str
    entry_metadata: dict
    created_at: datetime


class CaseRead(ORMModel):
    id: str
    reference: str
    title: str
    description: str
    status: CaseStatus
    priority: CasePriority
    severity: Severity
    primary_identity_id: str | None
    assignee_id: str | None
    tags: list
    mitre_techniques: list
    peak_risk_score: float
    blast_radius_score: float
    estimated_records_at_risk: int
    sla_due_at: datetime | None
    acknowledged_at: datetime | None
    contained_at: datetime | None
    closed_at: datetime | None
    closure_reason: str | None
    created_at: datetime
    updated_at: datetime


class CaseDetail(CaseRead):
    entries: list[CaseEntryRead] = Field(default_factory=list)
    alerts: list[AlertRead] = Field(default_factory=list)


# ------------------------------------------------------------------------- rule
class RuleCreate(BaseModel):
    slug: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9\-_]{2,95}$")]
    name: Annotated[str, Field(min_length=3, max_length=200)]
    description: str = ""
    category: str = "behavioural"
    severity: Severity = Severity.MEDIUM
    conditions: dict[str, Any]
    risk_boost: Annotated[float, Field(ge=0, le=40)] = 10.0
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    suppress_when_context: bool = True
    enabled: bool = True


class RuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: Severity | None = None
    conditions: dict[str, Any] | None = None
    risk_boost: Annotated[float, Field(ge=0, le=40)] | None = None
    enabled: bool | None = None
    suppress_when_context: bool | None = None


class RuleRead(ORMModel):
    id: str
    slug: str
    name: str
    description: str
    category: str
    severity: Severity
    enabled: bool
    is_builtin: bool
    conditions: dict
    risk_boost: float
    mitre_techniques: list
    recommended_actions: list
    suppress_when_context: bool
    match_count: int
    true_positive_count: int
    false_positive_count: int
    last_matched_at: datetime | None


class RuleTestRequest(BaseModel):
    conditions: dict[str, Any]
    sample: dict[str, Any] = Field(
        default_factory=dict, description="Fact overrides for the simulated event."
    )


class RuleTestResult(BaseModel):
    valid: bool
    matched: bool
    error: str | None = None
    facts: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------- response
class ActionRequest(BaseModel):
    action: ResponseAction
    notes: str | None = None
    alert_id: str | None = None
    case_id: str | None = None
    ticket_reference: str | None = None


class ActionRead(ORMModel):
    id: str
    identity_id: str
    alert_id: str | None
    case_id: str | None
    action: ResponseAction
    outcome: str
    performed_by_label: str
    is_automated: bool
    notes: str | None
    result: dict
    duration_ms: int
    created_at: datetime


class PlaybookRead(ORMModel):
    id: str
    slug: str
    name: str
    description: str
    category: str
    steps: list
    trigger_conditions: dict
    auto_execute: bool
    requires_approval: bool
    enabled: bool
    estimated_minutes: int
    run_count: int
    last_run_at: datetime | None


class PlaybookRunRequest(BaseModel):
    identity_id: str
    case_id: str | None = None
    dry_run: bool = True
    notes: str | None = None


# ----------------------------------------------------------------------- assets
class AssetRead(ORMModel):
    id: str
    key: str
    display_name: str
    category: str
    owner_team: str
    sensitivity_level: int
    environment: str
    contains_pii: bool
    contains_phi: bool
    contains_cardholder_data: bool
    is_crown_jewel: bool
    record_estimate: int
    compliance_scopes: list
    tags: list


class IndicatorCreate(BaseModel):
    indicator_type: IndicatorType
    value: Annotated[str, Field(min_length=1, max_length=255)]
    confidence: Annotated[int, Field(ge=0, le=100)] = 70
    severity: Severity = Severity.MEDIUM
    source_feed: str = "manual"
    description: str | None = None
    expires_in_days: Annotated[int, Field(ge=1, le=3650)] | None = None


class IndicatorRead(ORMModel):
    id: str
    indicator_type: IndicatorType
    value: str
    confidence: int
    severity: str
    source_feed: str
    description: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    expires_at: datetime | None
    hit_count: int
    is_active: bool


class IntegrationRead(ORMModel):
    id: str
    name: str
    kind: str
    vendor: str
    status: str
    protocol: str
    sync_interval: str
    last_heartbeat_at: datetime | None
    entities_synced: int
    events_ingested_24h: int
    error_message: str | None


class WatchlistRead(ORMModel):
    id: str
    name: str
    description: str
    reason: str
    risk_multiplier: float
    member_ids: list
    expires_at: datetime | None
    is_active: bool
    created_at: datetime


class WatchlistCreate(BaseModel):
    name: Annotated[str, Field(min_length=2, max_length=120)]
    description: str = ""
    reason: str = "Manual addition"
    risk_multiplier: Annotated[float, Field(ge=1.0, le=3.0)] = 1.25
    member_ids: list[str] = Field(default_factory=list)
    expires_in_days: Annotated[int, Field(ge=1, le=365)] | None = None


class AuditLogRead(ORMModel):
    id: str
    created_at: datetime
    actor_email: str
    action: str
    target_type: str
    target_id: str | None
    outcome: str
    ip_address: str | None
    request_id: str | None
    payload: dict
