"""Importing this package registers every SQLAlchemy mapper."""

from app.db.models.detection import (
    Alert,
    ContextRecord,
    DetectionRule,
    RiskSnapshot,
    Watchlist,
)
from app.db.models.identity import Baseline, Identity, PeerGroup
from app.db.models.platform import ApiKey, AuditLog, Integration, User
from app.db.models.response import ActionRecord, Case, CaseEntry, Playbook
from app.db.models.telemetry import Asset, SecurityEvent, ThreatIndicator

__all__ = [
    "ActionRecord",
    "Alert",
    "ApiKey",
    "Asset",
    "AuditLog",
    "Baseline",
    "Case",
    "CaseEntry",
    "ContextRecord",
    "DetectionRule",
    "Identity",
    "Integration",
    "PeerGroup",
    "Playbook",
    "RiskSnapshot",
    "SecurityEvent",
    "ThreatIndicator",
    "User",
    "Watchlist",
]
