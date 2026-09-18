"""Response-side tables: cases, their timelines, playbooks and executed actions."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import ActionOutcome, CasePriority, CaseStatus, ResponseAction, Severity
from app.db.base import Base, IDMixin, TimestampMixin
from app.db.types import JSONType, StrEnumType


class Case(Base, IDMixin, TimestampMixin):
    """An investigation grouping one or more alerts, owned by an analyst."""

    __tablename__ = "cases"
    __id_prefix__ = "case"
    __table_args__ = (Index("ix_cases_status_priority", "status", "priority"),)

    reference: Mapped[str] = mapped_column(String(48), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[CaseStatus] = mapped_column(
        StrEnumType(CaseStatus, 32), default=CaseStatus.NEW, nullable=False, index=True
    )
    priority: Mapped[CasePriority] = mapped_column(
        StrEnumType(CasePriority, 8), default=CasePriority.P3, nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        StrEnumType(Severity, 16), default=Severity.MEDIUM, nullable=False
    )

    primary_identity_id: Mapped[str | None] = mapped_column(
        ForeignKey("identities.id", ondelete="SET NULL"), index=True, nullable=True
    )
    assignee_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    opened_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    tags: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    peak_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    blast_radius_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    estimated_records_at_risk: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    closure_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    alerts: Mapped[list[Alert]] = relationship(back_populates="case", lazy="selectin")
    entries: Mapped[list[CaseEntry]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="CaseEntry.created_at",
    )


class CaseEntry(Base, IDMixin, TimestampMixin):
    """A single line in a case timeline: comment, status change or automated note."""

    __tablename__ = "case_entries"
    __id_prefix__ = "ent"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    entry_type: Mapped[str] = mapped_column(String(32), default="COMMENT", nullable=False)
    author_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    author_label: Mapped[str] = mapped_column(String(160), default="system", nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    entry_metadata: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    case: Mapped[Case] = relationship(back_populates="entries")


class Playbook(Base, IDMixin, TimestampMixin):
    """An ordered set of response steps, optionally auto-triggered by conditions."""

    __tablename__ = "playbooks"
    __id_prefix__ = "pbk"

    slug: Mapped[str] = mapped_column(String(96), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="containment", nullable=False)
    steps: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    trigger_conditions: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    auto_execute: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    estimated_minutes: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    run_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ActionRecord(Base, IDMixin, TimestampMixin):
    """Audit trail of a containment/response action applied to an identity."""

    __tablename__ = "action_records"
    __id_prefix__ = "act"
    __table_args__ = (Index("ix_actions_identity_created", "identity_id", "created_at"),)

    identity_id: Mapped[str] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    playbook_id: Mapped[str | None] = mapped_column(
        ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True
    )

    action: Mapped[ResponseAction] = mapped_column(
        StrEnumType(ResponseAction, 48), nullable=False, index=True
    )
    outcome: Mapped[ActionOutcome] = mapped_column(
        StrEnumType(ActionOutcome, 24), default=ActionOutcome.PENDING, nullable=False
    )
    performed_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    performed_by_label: Mapped[str] = mapped_column(String(160), default="system", nullable=False)
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


from app.db.models.detection import Alert  # noqa: E402  (resolves Case.alerts)
