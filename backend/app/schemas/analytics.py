"""Schemas for dashboards, investigation payloads and the copilot."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field

from app.core.enums import TransitionState


class KpiSet(BaseModel):
    monitored_identities: int
    active_threat_transitions: int
    critical_identities: int
    open_alerts: int
    open_cases: int
    suppressed_false_positives: int
    fleet_health_score: float
    mean_risk_score: float
    events_last_24h: int
    anti_tamper_events: int


class TrendPoint(BaseModel):
    timestamp: datetime
    value: float
    label: str | None = None


class DistributionSlice(BaseModel):
    key: str
    label: str
    count: int
    percentage: float


class OverviewResponse(BaseModel):
    kpis: KpiSet
    transition_distribution: list[DistributionSlice]
    severity_distribution: list[DistributionSlice]
    department_risk: list[dict[str, Any]]
    vector_heatmap: dict[str, float]
    risk_trend: list[TrendPoint]
    event_volume_trend: list[TrendPoint]
    top_alerts: list[dict[str, Any]]
    top_risky_identities: list[dict[str, Any]]
    recent_actions: list[dict[str, Any]]
    peer_outliers: list[dict[str, Any]]
    generated_at: datetime


class TimelinePoint(BaseModel):
    event_id: str
    timestamp: str
    resource: str
    action: str
    event_type: str
    sensitivity: int
    event_score: float
    raw_event_score: float
    cumulative_risk: float
    raw_cumulative_risk: float
    is_damped: bool
    damping_reason: str | None
    anti_tamper: bool
    matched_rules: list[str]
    state: str
    vectors: dict[str, float]


class InvestigationResponse(BaseModel):
    """Everything the Investigator Workbench needs, in one round trip."""

    identity: dict[str, Any]
    risk_score: float
    raw_risk_score: float
    transition_state: TransitionState
    drift_velocity: float
    peak_risk: float
    vector_scores: dict[str, float]
    dominant_vectors: list[str]
    explanation: dict[str, Any]
    blast_radius: dict[str, Any]
    timeline: list[TimelinePoint]
    baseline: dict[str, Any] | None
    contexts: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    matched_rules: list[dict[str, Any]]
    event_count: int
    generated_at: datetime


class CopilotRequest(BaseModel):
    identity_id: str
    question: Annotated[str, Field(min_length=2, max_length=500)]
    conversation_id: str | None = None


class CopilotResponse(BaseModel):
    intent: str
    answer: str
    confidence: float
    citations: list[dict[str, Any]]
    follow_ups: list[str]
    data: dict[str, Any]
    identity_id: str
    conversation_id: str | None
    answered_at: datetime


class HyperparameterSet(BaseModel):
    decay_halflife_hours: Annotated[float, Field(ge=1, le=720)]
    normal_threshold: Annotated[float, Field(ge=5, le=80)]
    threshold_early_drift: Annotated[float, Field(ge=5, le=95)]
    threshold_escalating: Annotated[float, Field(ge=10, le=98)]
    threshold_critical: Annotated[float, Field(ge=20, le=100)]
    vector_weights: dict[str, float]
    synergy_elevated_at: Annotated[float, Field(ge=10, le=95)]


class HyperparameterUpdate(BaseModel):
    decay_halflife_hours: Annotated[float, Field(ge=1, le=720)] | None = None
    normal_threshold: Annotated[float, Field(ge=5, le=80)] | None = None
    threshold_early_drift: Annotated[float, Field(ge=5, le=95)] | None = None
    threshold_escalating: Annotated[float, Field(ge=10, le=98)] | None = None
    threshold_critical: Annotated[float, Field(ge=20, le=100)] | None = None
    vector_weights: dict[str, float] | None = None
    synergy_elevated_at: Annotated[float, Field(ge=10, le=95)] | None = None
    recompute: bool = True


class ScenarioSummary(BaseModel):
    id: str
    title: str
    subtitle: str
    narrative: str
    target_username: str
    expected_outcome: str
    expected_state: TransitionState
    expect_exact: bool
    teaches: str
    event_count: int
    duration_days: int


class ScenarioRunResult(BaseModel):
    scenario: ScenarioSummary
    identity_id: str
    events_injected: int
    risk_before: float
    risk_after: float
    state_before: TransitionState
    state_after: TransitionState
    alert_id: str | None
    damping_applied: bool
    anti_tamper_triggered: bool
    matched_rules: list[str]
    outcome_matches_expectation: bool


class MitreCoverage(BaseModel):
    tactic: str
    total: int
    observed: int
    techniques: list[dict[str, Any]]


class ComplianceReport(BaseModel):
    framework: str
    control_reference: str
    status: str
    coverage_percentage: float
    evidence: list[str]
    gaps: list[str]
    last_assessed: datetime


class EnterpriseMetrics(BaseModel):
    mttd_hours: float
    mttd_industry_baseline_hours: float
    mttd_reduction_percentage: float
    mttr_hours: float
    alerts_per_analyst_day: float
    false_positive_rate: float
    noise_suppression_percentage: float
    analyst_hours_saved_monthly: float
    detection_coverage_percentage: float
    records_protected: int
    exposure_under_management_usd: float
    exposure_under_management_display: str
    compliance: list[ComplianceReport]
    methodology_note: str
