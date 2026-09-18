"""Platform-side tables: operators, credentials, auditing and integrations."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import IntegrationKind, IntegrationStatus
from app.core.security import Role
from app.db.base import Base, IDMixin, TimestampMixin
from app.db.types import JSONType, StrEnumType


class User(Base, IDMixin, TimestampMixin):
    """A SOC operator who signs into the console."""

    __tablename__ = "users"
    __id_prefix__ = "usr"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(StrEnumType(Role, 32), default=Role.ANALYST, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    preferences: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    api_keys: Mapped[list[ApiKey]] = relationship(
        back_populates="owner", cascade="all, delete-orphan", lazy="selectin"
    )


class ApiKey(Base, IDMixin, TimestampMixin):
    """Machine credential for the telemetry ingest endpoints."""

    __tablename__ = "api_keys"
    __id_prefix__ = "key"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    prefix: Mapped[str] = mapped_column(String(24), nullable=False)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    scopes: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    call_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    owner: Mapped[User] = relationship(back_populates="api_keys")


class AuditLog(Base, IDMixin):
    """Append-only record of every state-changing operation."""

    __tablename__ = "audit_logs"
    __id_prefix__ = "aud"
    __table_args__ = (Index("ix_audit_logs_actor_ts", "actor_email", "created_at"),)

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    actor_email: Mapped[str] = mapped_column(String(255), default="system", nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(48), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(24), default="SUCCESS", nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)


class Integration(Base, IDMixin, TimestampMixin):
    """A connected upstream system (IdP, SIEM, ITSM ...)."""

    __tablename__ = "integrations"
    __id_prefix__ = "int"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[IntegrationKind] = mapped_column(
        StrEnumType(IntegrationKind, 24), nullable=False, index=True
    )
    vendor: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[IntegrationStatus] = mapped_column(
        StrEnumType(IntegrationStatus, 24), default=IntegrationStatus.DISCONNECTED, nullable=False
    )
    protocol: Mapped[str] = mapped_column(String(80), default="REST", nullable=False)
    sync_interval: Mapped[str] = mapped_column(String(48), default="15m", nullable=False)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    entities_synced: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    events_ingested_24h: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    config: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
