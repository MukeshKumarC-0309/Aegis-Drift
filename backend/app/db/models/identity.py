"""Monitored workforce identities, their behavioural baselines and peer cohorts."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import TransitionState
from app.db.base import Base, IDMixin, TimestampMixin
from app.db.types import JSONType, StrEnumType


class Identity(Base, IDMixin, TimestampMixin):
    """A workforce account under behavioural surveillance."""

    __tablename__ = "identities"
    __id_prefix__ = "idn"
    __table_args__ = (
        Index("ix_identities_dept_risk", "department", "risk_score"),
        Index("ix_identities_state", "transition_state"),
    )

    username: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    department: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    role_title: Mapped[str] = mapped_column(String(120), nullable=False)
    manager: Mapped[str | None] = mapped_column(String(160), nullable=True)
    location: Mapped[str] = mapped_column(String(80), default="Unknown", nullable=False)
    employment_type: Mapped[str] = mapped_column(String(40), default="FULL_TIME", nullable=False)
    peer_group_id: Mapped[str] = mapped_column(String(96), index=True, nullable=False)
    joined_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    is_privileged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_service_account: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    on_watchlist: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Denormalised scoring cache, refreshed by the risk recomputation worker.
    risk_score: Mapped[float] = mapped_column(Float, default=5.0, nullable=False, index=True)
    raw_risk_score: Mapped[float] = mapped_column(Float, default=5.0, nullable=False)
    transition_state: Mapped[TransitionState] = mapped_column(
        StrEnumType(TransitionState, 32), default=TransitionState.STABLE, nullable=False
    )
    drift_velocity: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    dominant_vector: Mapped[str] = mapped_column(String(32), default="nominal", nullable=False)
    vector_scores: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    last_scored_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    baseline: Mapped[Baseline | None] = relationship(
        back_populates="identity", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )


class Baseline(Base, IDMixin, TimestampMixin):
    """Learned "normal" for one identity — the reference every event is scored against."""

    __tablename__ = "baselines"
    __id_prefix__ = "bsl"

    identity_id: Mapped[str] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), unique=True, index=True
    )
    hourly_distribution: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    dow_distribution: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    common_resources: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    resource_frequencies: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    known_ip_prefixes: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    known_countries: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    known_devices: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    action_frequencies: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    resource_entropy: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    avg_daily_events: Mapped[float] = mapped_column(Float, default=20.0, nullable=False)
    stddev_daily_events: Mapped[float] = mapped_column(Float, default=6.0, nullable=False)
    avg_daily_bytes: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    stddev_daily_bytes: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    typical_max_sensitivity: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    off_hours_ratio: Mapped[float] = mapped_column(Float, default=0.02, nullable=False)

    sample_event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    window_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    maturity: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    identity: Mapped[Identity] = relationship(back_populates="baseline")


class PeerGroup(Base, IDMixin, TimestampMixin):
    """Cohort statistics used by the peer-divergence vector."""

    __tablename__ = "peer_groups"
    __id_prefix__ = "peer"

    key: Mapped[str] = mapped_column(String(96), unique=True, index=True, nullable=False)
    department: Mapped[str] = mapped_column(String(80), nullable=False)
    role_title: Mapped[str] = mapped_column(String(120), nullable=False)
    member_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    centroid: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    shared_resources: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    mean_risk: Mapped[float] = mapped_column(Float, default=5.0, nullable=False)
    stddev_risk: Mapped[float] = mapped_column(Float, default=3.0, nullable=False)
    mean_daily_events: Mapped[float] = mapped_column(Float, default=20.0, nullable=False)
    mean_max_sensitivity: Mapped[float] = mapped_column(Float, default=2.0, nullable=False)
