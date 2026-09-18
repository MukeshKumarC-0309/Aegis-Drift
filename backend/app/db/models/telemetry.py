"""Raw telemetry: security events, assets and threat-intel indicators."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import EventType, IndicatorType
from app.db.base import Base, IDMixin, TimestampMixin
from app.db.types import JSONType, StrEnumType


class SecurityEvent(Base, IDMixin):
    """One observed action by an identity. The highest-volume table in the system."""

    __tablename__ = "security_events"
    __id_prefix__ = "evt"
    __table_args__ = (
        Index("ix_events_identity_ts", "identity_id", "occurred_at"),
        Index("ix_events_resource_ts", "resource", "occurred_at"),
        Index("ix_events_score", "anomaly_score"),
    )

    identity_id: Mapped[str] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    event_type: Mapped[EventType] = mapped_column(StrEnumType(EventType, 32), nullable=False, index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(24), default="SUCCESS", nullable=False)
    sensitivity_level: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    ip_address: Mapped[str] = mapped_column(String(64), default="10.0.0.1", nullable=False)
    country: Mapped[str] = mapped_column(String(4), default="US", nullable=False)
    city: Mapped[str | None] = mapped_column(String(80), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    asn: Mapped[str | None] = mapped_column(String(48), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    bytes_transferred: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_off_hours: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Scoring results, written back after the detection pipeline runs.
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    damped_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    vector_scores: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    is_damped: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    damping_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_rules: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    context_tags: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="simulator", nullable=False)
    event_metadata: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)


class Asset(Base, IDMixin, TimestampMixin):
    """A protected resource: database, bucket, repo, SaaS app or secret store."""

    __tablename__ = "assets"
    __id_prefix__ = "ast"

    key: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="application", nullable=False, index=True)
    owner_team: Mapped[str] = mapped_column(String(96), default="Unassigned", nullable=False)
    sensitivity_level: Mapped[int] = mapped_column(Integer, default=2, nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(24), default="production", nullable=False)
    contains_pii: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    contains_phi: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    contains_cardholder_data: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_crown_jewel: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    record_estimate: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    compliance_scopes: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)


class ThreatIndicator(Base, IDMixin, TimestampMixin):
    """An IoC from a feed; matches boost the intel risk vector."""

    __tablename__ = "threat_indicators"
    __id_prefix__ = "ioc"
    __table_args__ = (Index("ix_indicators_type_value", "indicator_type", "value", unique=True),)

    indicator_type: Mapped[IndicatorType] = mapped_column(StrEnumType(IndicatorType, 24), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=70, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    source_feed: Mapped[str] = mapped_column(String(96), default="internal", nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
