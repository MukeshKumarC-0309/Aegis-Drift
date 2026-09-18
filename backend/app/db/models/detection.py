"""Detection-side tables: alerts, context exemptions, rules and risk snapshots."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AlertStatus, ContextType, Severity, TransitionState
from app.db.base import Base, IDMixin, TimestampMixin
from app.db.types import JSONType, StrEnumType


class Alert(Base, IDMixin, TimestampMixin):
    """A raised behavioural finding for one identity."""

    __tablename__ = "alerts"
    __id_prefix__ = "alr"
    __table_args__ = (
        Index("ix_alerts_status_risk", "status", "risk_score"),
        Index("ix_alerts_identity_created", "identity_id", "created_at"),
    )

    identity_id: Mapped[str] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    case_id: Mapped[str | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), index=True, nullable=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        StrEnumType(Severity, 16), default=Severity.MEDIUM, nullable=False, index=True
    )
    status: Mapped[AlertStatus] = mapped_column(
        StrEnumType(AlertStatus, 32), default=AlertStatus.OPEN, nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, default=70.0, nullable=False)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    raw_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    transition_state: Mapped[TransitionState] = mapped_column(
        StrEnumType(TransitionState, 32), default=TransitionState.EARLY_DRIFT, nullable=False
    )
    drift_velocity: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    context_damped: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    damping_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    anti_tamper_override: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    dominant_vectors: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    vector_scores: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    triggering_event_ids: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    matched_rule_ids: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    assigned_to_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    case: Mapped[Case | None] = relationship(back_populates="alerts")


class ContextRecord(Base, IDMixin, TimestampMixin):
    """An approved business justification that damps risk inside its window."""

    __tablename__ = "context_records"
    __id_prefix__ = "ctx"
    __table_args__ = (Index("ix_context_identity_window", "identity_id", "valid_from", "valid_until"),)

    identity_id: Mapped[str] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    context_type: Mapped[ContextType] = mapped_column(
        StrEnumType(ContextType, 48), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    ticket_reference: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    source_system: Mapped[str] = mapped_column(String(64), default="manual", nullable=False)

    valid_from: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    damping_factor: Mapped[float] = mapped_column(Float, default=0.35, nullable=False)
    target_resources: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    allowed_actions: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    approved_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    applied_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class DetectionRule(Base, IDMixin, TimestampMixin):
    """A declarative rule evaluated against every scored event."""

    __tablename__ = "detection_rules"
    __id_prefix__ = "rul"

    slug: Mapped[str] = mapped_column(String(96), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="behavioural", nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(
        StrEnumType(Severity, 16), default=Severity.MEDIUM, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ``conditions`` is a small JSON DSL — see app/engine/rules.py for the grammar.
    conditions: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    risk_boost: Mapped[float] = mapped_column(Float, default=10.0, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    recommended_actions: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    suppress_when_context: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    true_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RiskSnapshot(Base, IDMixin):
    """Periodic point-in-time risk reading, used for trend charts and backtesting."""

    __tablename__ = "risk_snapshots"
    __id_prefix__ = "snp"
    __table_args__ = (Index("ix_snapshots_identity_ts", "identity_id", "captured_at"),)

    identity_id: Mapped[str] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    captured_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    raw_risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    transition_state: Mapped[TransitionState] = mapped_column(
        StrEnumType(TransitionState, 32), nullable=False
    )
    vector_scores: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Watchlist(Base, IDMixin, TimestampMixin):
    """A named set of identities under heightened scrutiny."""

    __tablename__ = "watchlists"
    __id_prefix__ = "wat"

    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reason: Mapped[str] = mapped_column(String(200), default="Manual addition", nullable=False)
    risk_multiplier: Mapped[float] = mapped_column(Float, default=1.25, nullable=False)
    member_ids: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


from app.db.models.response import Case  # noqa: E402  (resolves the Alert.case relationship)
