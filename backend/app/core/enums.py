"""Domain vocabulary shared by ORM models, Pydantic schemas and the detection engine."""

from __future__ import annotations

from enum import StrEnum


class EventType(StrEnum):
    AUTHENTICATION = "AUTHENTICATION"
    FILE_ACCESS = "FILE_ACCESS"
    PRIVILEGE_ACTION = "PRIVILEGE_ACTION"
    API_CALL = "API_CALL"
    NETWORK_EGRESS = "NETWORK_EGRESS"
    ROLE_MODIFICATION = "ROLE_MODIFICATION"
    DATA_EXPORT = "DATA_EXPORT"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    SECRET_ACCESS = "SECRET_ACCESS"
    MFA_EVENT = "MFA_EVENT"


class TransitionState(StrEnum):
    STABLE = "STABLE"
    EARLY_DRIFT = "EARLY_DRIFT"
    ESCALATING = "ESCALATING"
    CRITICAL_TRANSITION = "CRITICAL_TRANSITION"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    SUPPRESSED = "SUPPRESSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CONFIRMED_INCIDENT = "CONFIRMED_INCIDENT"
    CLOSED = "CLOSED"


class CaseStatus(StrEnum):
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    PENDING_INPUT = "PENDING_INPUT"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CasePriority(StrEnum):
    P4 = "P4"
    P3 = "P3"
    P2 = "P2"
    P1 = "P1"


class ContextType(StrEnum):
    PROJECT_TRANSFER = "PROJECT_TRANSFER"
    ON_CALL_ROTATION = "ON_CALL_ROTATION"
    APPROVED_CHANGE_TICKET = "APPROVED_CHANGE_TICKET"
    TRAVEL_EXEMPTION = "TRAVEL_EXEMPTION"
    MAINTENANCE_WINDOW = "MAINTENANCE_WINDOW"
    ROLE_CHANGE = "ROLE_CHANGE"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"


class RiskVector(StrEnum):
    """The behavioural dimensions scored for every event."""

    TEMPORAL = "temporal"
    RESOURCE = "resource"
    PRIVILEGE = "privilege"
    PEER_DIVERGENCE = "peer_divergence"
    GEOVELOCITY = "geovelocity"
    VOLUME = "volume"
    DEVICE = "device"
    INTEL = "intel"


class ActionOutcome(StrEnum):
    PENDING = "PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ResponseAction(StrEnum):
    STEP_UP_MFA = "STEP_UP_MFA"
    QUARANTINE_SESSION = "QUARANTINE_SESSION"
    REVOKE_TOKENS = "REVOKE_TOKENS"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    SUSPEND_API_KEYS = "SUSPEND_API_KEYS"
    NOTIFY_MANAGER = "NOTIFY_MANAGER"
    OPEN_TICKET = "OPEN_TICKET"
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    RE_BASELINE = "RE_BASELINE"
    ADD_CONTEXT_EXEMPTION = "ADD_CONTEXT_EXEMPTION"
    ESCALATE = "ESCALATE"


class IndicatorType(StrEnum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    ASN = "ASN"
    USER_AGENT = "USER_AGENT"
    FILE_HASH = "FILE_HASH"
    TOR_EXIT = "TOR_EXIT"


class IntegrationKind(StrEnum):
    IDP = "IDP"
    ITSM = "ITSM"
    SIEM = "SIEM"
    EDR = "EDR"
    CASB = "CASB"
    HRIS = "HRIS"
    CHATOPS = "CHATOPS"


class IntegrationStatus(StrEnum):
    CONNECTED = "CONNECTED"
    STREAMING = "STREAMING"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"


SENSITIVITY_LABELS: dict[int, str] = {
    1: "Public",
    2: "Internal",
    3: "Confidential",
    4: "Restricted",
    5: "Crown Jewel",
}

#: Actions that can never be damped by an approved business context.
ANTI_TAMPER_ACTIONS: frozenset[str] = frozenset(
    {
        "delete_audit_logs",
        "dump_credentials",
        "disable_logging",
        "disable_mfa",
        "exfiltrate",
        "create_backdoor_user",
        "rotate_root_key",
    }
)

#: High-signal privileged actions used by the privilege vector.
PRIVILEGED_ACTIONS: frozenset[str] = frozenset(
    {
        "sudo",
        "assume_role",
        "iam_modify",
        "export_all",
        "grant_permission",
        "attach_policy",
        "create_access_key",
        *ANTI_TAMPER_ACTIONS,
    }
)
